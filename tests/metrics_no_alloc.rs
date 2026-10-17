//! Hot-path metric recording allocates nothing once a series exists.
use hopae::telemetry::metrics::{self, AUTH_OUTCOMES, Surface};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;
thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn recording_existing_series_is_allocation_free() {
    let record = || {
        AUTH_OUTCOMES.inc(["forward_auth", "google", "allow", "ok"]);
        AUTH_OUTCOMES.inc(["hop1", "none", "deny", "unknown_handle"]);
        metrics::GRPC_REQUESTS.inc([
            metrics::grpc_profile("/hangang.hopae.v1.Authentication/Verify"),
            metrics::grpc_code(Some(b"7")),
        ]);
        metrics::RATE_LIMITED.inc(["verify"]);
        metrics::STORE_FAILURES.inc(["busy"]);
        metrics::observe(Surface::Hop1, std::time::Instant::now());
    };
    record(); // first sight stores the label strings
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..1000 {
        record();
    }
    assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    assert!(AUTH_OUTCOMES.get(["forward_auth", "google", "allow", "ok"]) >= 1001);
}
