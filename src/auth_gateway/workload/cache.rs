//! Short-TTL positive cache of verified workload credentials. The key is the
//! SHA-256 of the presented token (the token itself is never stored). An
//! entry lives at most `ttl` and never beyond the token's own expiry; a hit
//! still passes the live revocation check and the namespace/ServiceAccount
//! scope of the connector. Memory is bounded by `max_entries` (oldest first).
use super::identity::Workload;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

pub(crate) struct Entry {
    pub workload: Arc<Workload>,
    /// Token expiry, Unix milliseconds.
    pub expires_ms: u64,
    /// Entry validity, Unix milliseconds.
    pub until_ms: u64,
}

type Entries = (HashMap<[u8; 32], Entry>, VecDeque<([u8; 32], u64)>);

pub(crate) struct Cache {
    ttl_ms: u64,
    max_entries: usize,
    inner: Mutex<Entries>,
}

impl Cache {
    pub(crate) fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            ttl_ms,
            max_entries,
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }
    pub(crate) fn enabled(&self) -> bool {
        self.ttl_ms > 0 && self.max_entries > 0
    }
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).0.len()
    }
    pub(crate) fn get(&self, key: &[u8; 32], now_ms: u64) -> Option<(Arc<Workload>, u64)> {
        if !self.enabled() {
            return None;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (map, _) = &mut *guard;
        match map.get(key) {
            Some(e) if e.until_ms > now_ms && e.expires_ms > now_ms => {
                Some((e.workload.clone(), e.expires_ms))
            }
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }
    pub(crate) fn insert(
        &self,
        key: [u8; 32],
        workload: Arc<Workload>,
        expires_ms: u64,
        now_ms: u64,
    ) {
        if !self.enabled() {
            return;
        }
        let until_ms = now_ms.saturating_add(self.ttl_ms).min(expires_ms);
        if until_ms <= now_ms {
            return;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        // Drop expired entries from the front, then the oldest beyond capacity.
        while let Some((k, until)) = order.front().copied() {
            let stale = map
                .get(&k)
                .is_none_or(|e| e.until_ms != until || until <= now_ms);
            if stale || map.len() >= self.max_entries {
                order.pop_front();
                if map.get(&k).is_some_and(|e| e.until_ms == until) {
                    map.remove(&k);
                }
            } else {
                break;
            }
        }
        map.insert(
            key,
            Entry {
                workload,
                expires_ms,
                until_ms,
            },
        );
        order.push_back((key, until_ms));
    }
    /// Drop every entry of one ServiceAccount incarnation (revocation).
    pub(crate) fn evict_service_account(&self, namespace: &str, uid: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.retain(|_, e| {
            !(e.workload.namespace == namespace && e.workload.service_account_uid == uid)
        });
    }
    /// Drop every entry bound to one Pod UID (revocation).
    pub(crate) fn evict_pod(&self, namespace: &str, uid: &str) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.retain(|_, e| {
            !(e.workload.namespace == namespace
                && e.workload.pod.as_ref().is_some_and(|p| p.uid == uid))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn workload(uid: &str) -> Arc<Workload> {
        Arc::new(Workload {
            issuer: "https://issuer.example.test".into(),
            cluster_id: "c".into(),
            namespace: "blue".into(),
            service_account: "worker".into(),
            service_account_uid: uid.into(),
            pod: None,
            secret: None,
            node: None,
        })
    }
    #[test]
    fn entries_respect_ttl_token_expiry_capacity_and_eviction() {
        let cache = Cache::new(1000, 2);
        cache.insert([1; 32], workload("a"), 10_000, 100);
        assert!(cache.get(&[1; 32], 1099).is_some());
        assert!(cache.get(&[1; 32], 1100).is_none(), "ttl bounds the entry");
        cache.insert([2; 32], workload("a"), 500, 100);
        assert!(cache.get(&[2; 32], 499).is_some());
        assert!(
            cache.get(&[2; 32], 500).is_none(),
            "token expiry bounds the entry"
        );
        cache.insert([3; 32], workload("a"), 10_000, 200);
        cache.insert([4; 32], workload("b"), 10_000, 200);
        cache.insert([5; 32], workload("b"), 10_000, 200);
        assert!(cache.len() <= 2, "capacity is bounded");
        assert!(cache.get(&[5; 32], 300).is_some());
        cache.evict_service_account("blue", "b");
        assert!(cache.get(&[5; 32], 300).is_none());
        let disabled = Cache::new(0, 10);
        disabled.insert([1; 32], workload("a"), 10_000, 100);
        assert!(disabled.get(&[1; 32], 101).is_none());
    }
}
