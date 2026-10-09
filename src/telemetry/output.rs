//! The process-wide output path (G7 B04/B06): every line Hopae writes to
//! stderr, tracing lines and event JSON lines alike, goes through one
//! dedicated output thread fed by a bounded channel.
//!
//! Producers never wait. A line that does not fit the channel is dropped and
//! counted (`hopae_log_lines_dropped_total` for tracing lines,
//! `hopae_events_log_dropped_total` for event lines), so a stderr nobody
//! drains can stall the output thread but nothing else: not the store writer,
//! not the blocking pool, not a request. Each line is handed over whole, so
//! lines never interleave.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tracing_subscriber::fmt::MakeWriter;

use crate::store::StoreHooks;
use crate::telemetry::counters;

/// Lines the global channel holds.
const GLOBAL_CAPACITY: usize = 4096;

struct Item {
    bytes: Vec<u8>,
    /// Test hook: abort once this line is written (`after_log_line`).
    crash_after: Option<Arc<StoreHooks>>,
}

pub struct Output {
    tx: SyncSender<Item>,
    pending: Arc<AtomicUsize>,
}

impl Output {
    /// An output thread writing to `writer`, behind a channel of `capacity` lines.
    pub fn spawn(mut writer: Box<dyn Write + Send>, capacity: usize) -> Arc<Output> {
        let (tx, rx) = mpsc::sync_channel::<Item>(capacity.max(1));
        let pending = Arc::new(AtomicUsize::new(0));
        let counted = pending.clone();
        let _ = std::thread::Builder::new()
            .name("hopae-output".into())
            .spawn(move || {
                while let Ok(item) = rx.recv() {
                    // A failing writer loses the line; it never ends the thread.
                    let _ = writer.write_all(&item.bytes).and_then(|()| writer.flush());
                    counted.fetch_sub(1, Ordering::SeqCst);
                    if let Some(h) = item.crash_after {
                        h.crash_point("after_log_line");
                    }
                }
            });
        Arc::new(Output { tx, pending })
    }

    /// The stderr output of this process.
    pub fn global() -> &'static Arc<Output> {
        static G: OnceLock<Arc<Output>> = OnceLock::new();
        G.get_or_init(|| Output::spawn(Box::new(std::io::stderr()), GLOBAL_CAPACITY))
    }

    /// Queue one whole line; `false` when the channel is full (nothing was
    /// queued). Never blocks.
    pub fn try_line(&self, bytes: Vec<u8>, crash_after: Option<Arc<StoreHooks>>) -> bool {
        self.pending.fetch_add(1, Ordering::SeqCst);
        match self.tx.try_send(Item { bytes, crash_after }) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.pending.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
    }

    /// Wait (bounded) until everything queued so far has been written.
    pub fn flush(&self, timeout: Duration) {
        let end = Instant::now() + timeout;
        while self.pending.load(Ordering::SeqCst) > 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A `tracing` writer over this output.
    pub fn make_writer(self: &Arc<Self>) -> OutputMakeWriter {
        OutputMakeWriter(self.clone())
    }
}

/// `MakeWriter` for the tracing subscriber: each event is collected and
/// queued as one line when its writer is dropped.
#[derive(Clone)]
pub struct OutputMakeWriter(Arc<Output>);

pub struct LineWriter {
    out: Arc<Output>,
    buf: Vec<u8>,
}

impl<'a> MakeWriter<'a> for OutputMakeWriter {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> LineWriter {
        LineWriter {
            out: self.0.clone(),
            buf: Vec::with_capacity(256),
        }
    }
}

impl Write for LineWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        if !self.out.try_line(std::mem::take(&mut self.buf), None) {
            counters::inc(counters::LOG_LINES_DROPPED_TOTAL, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{OsRng, TestClock, Timestamp};
    use crate::event::deliveries::DeliveryWorker;
    use crate::event::sinks::LogSink;
    use crate::event::types::{EventBuilder, EventKind, Outcome};
    use crate::store::Store;
    use crate::store::types::EventRetention;
    use std::sync::Mutex;

    /// Output that parks every write until released (an undrained stderr).
    #[derive(Clone)]
    struct Parked(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Parked {
        fn new() -> Parked {
            Parked(Arc::new((Mutex::new(false), std::sync::Condvar::new())))
        }
        fn release(&self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }

    impl Write for Parked {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let mut open = self.0.0.lock().unwrap();
            while !*open {
                open = self.0.1.wait(open).unwrap();
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn store(sinks: &[&str]) -> (tempfile::TempDir, Store, Arc<TestClock>) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock::new(Timestamp(1_800_000_000_000)));
        let s = Store::open(
            &dir.path().join("t.db"),
            clock.clone(),
            sinks.iter().map(|s| s.to_string()).collect(),
            None,
        )
        .unwrap();
        (dir, s, clock)
    }

    /// Lines are handed over whole and in one piece, however writes are chunked.
    #[test]
    fn lines_are_intact() {
        #[derive(Clone, Default)]
        struct Collect(Arc<Mutex<Vec<u8>>>);
        impl Write for Collect {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Collect::default();
        let out = Output::spawn(Box::new(sink.clone()), 4096);
        std::thread::scope(|s| {
            for t in 0..8 {
                let out = out.clone();
                s.spawn(move || {
                    for i in 0..200 {
                        let mw = out.make_writer();
                        let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&mw);
                        // A line written in several pieces stays one line.
                        write!(w, "thread-{t} ").unwrap();
                        write!(w, "line-{i} ").unwrap();
                        writeln!(w, "{}", "x".repeat(300)).unwrap();
                    }
                });
            }
        });
        out.flush(Duration::from_secs(5));
        let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1600);
        for l in text.lines() {
            assert!(
                l.starts_with("thread-") && l.ends_with(&"x".repeat(300)),
                "{l:.60}"
            );
            assert_eq!(l.matches("thread-").count(), 1, "interleaved: {l:.80}");
        }
    }

    /// G7 B04: with the output parked, tracing warnings raised on the store
    /// writer thread (backlog overflow) cannot stop store writes or reads.
    #[test]
    fn parked_output_does_not_stop_writes_even_for_tracing_on_the_writer_thread() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let parked = Parked::new();
            let out = Output::spawn(Box::new(parked.clone()), 16);
            assert!(
                crate::telemetry::init_with("warn", &out),
                "the process-wide subscriber is installed by this test"
            );
            let (_dir, store, clock) = store(&["log"]);
            store.set_event_retention(EventRetention {
                retention: Duration::from_secs(86_400),
                max_rows: 100_000,
                prune_every: 5,
                max_pending_per_sink: 3,
                terminal_retention: Duration::from_secs(86_400),
            });
            store.set_diagnostic_log(Arc::new(LogSink::new(Box::new(parked.clone()), None)));
            let dropped = counters::get(counters::LOG_LINES_DROPPED_TOTAL, &[]);
            let rng = OsRng;
            let began = Instant::now();
            for _ in 0..300 {
                let ev = EventBuilder::new(
                    &*clock,
                    &rng,
                    EventKind::LoginSucceeded,
                    Outcome::Success,
                    "r",
                )
                .build();
                tokio::time::timeout(
                    Duration::from_secs(2),
                    store.directory().import_providers(vec![], None, vec![ev]),
                )
                .await
                .expect("a store write was blocked by output")
                .unwrap();
            }
            let rows = tokio::time::timeout(Duration::from_secs(2), store.events().count_rows())
                .await
                .expect("a store read was blocked")
                .unwrap();
            assert!(rows.0 > 0);
            assert!(began.elapsed() < Duration::from_secs(10));
            assert!(
                counters::get(counters::LOG_LINES_DROPPED_TOTAL, &[]) > dropped,
                "warnings that did not fit were dropped and counted"
            );
            parked.release();
        });
    }

    /// G7 B06: delivery attempts to a stuck log sink occupy no blocking
    /// thread (the pool is capped at 4 here) and a full queue is a retryable
    /// failure, not a lost delivery.
    #[test]
    fn deliveries_to_a_parked_sink_do_not_use_the_blocking_pool() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let parked = Parked::new();
            let (_dir, store, clock) = store(&["log"]);
            let rng = OsRng;
            for _ in 0..40 {
                let evs: Vec<_> = (0..40)
                    .map(|_| {
                        EventBuilder::new(&*clock, &rng, EventKind::LoginSucceeded, Outcome::Success, "r").build()
                    })
                    .collect();
                store.directory().import_providers(vec![], None, evs).await.unwrap();
            }
            let sink: Arc<dyn crate::event::sinks::Sink> =
                Arc::new(LogSink::new(Box::new(parked.clone()), None));
            let worker = DeliveryWorker::new(store.events(), sink, clock.clone());
            let mut attempts = 0;
            for _ in 0..60 {
                attempts += tokio::time::timeout(Duration::from_secs(5), worker.run_once())
                    .await
                    .expect("a delivery round was blocked");
            }
            assert!(attempts >= 1500, "{attempts} attempts");
            // The blocking pool is free: a store read (which uses it) completes.
            tokio::time::timeout(Duration::from_secs(1), store.events().count_rows())
                .await
                .expect("the blocking pool is starved by delivery attempts")
                .unwrap();
            // A full queue left deliveries pending with a retryable error.
            let failed: i64 = store
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM event_deliveries WHERE state='pending' AND last_error='log_queue_full'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(failed > 0, "queue-full deliveries stay pending for a retry");
            parked.release();
        });
    }
}
