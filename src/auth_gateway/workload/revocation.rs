//! Optional watch-backed revocation for offline-verified workload tokens.
//!
//! Offline JWT verification cannot see that the ServiceAccount or the Pod a
//! token is bound to was deleted (TokenReview would refuse such a token). In
//! `watch` mode the connector keeps a metadata-only index of the
//! ServiceAccounts (and, for Pod-bound tokens, the Pods) of every allowed
//! namespace, maintained by LIST + WATCH (`PartialObjectMetadata`, bookmarks,
//! relist on `410 Gone`). The hot path only reads this index:
//!
//! * the bound ServiceAccount must be present with the token's UID (a deleted
//!   ServiceAccount or one re-created under the same name refuses the token);
//! * for Pod-bound tokens, the Pod must be present with the token's UID and
//!   not terminating (`deletionTimestamp` unset);
//! * the index must be **current**: confirmed by a successful LIST, an event,
//!   a bookmark or a (re-)established watch within `max_staleness`. Each
//!   watch request asks the server to end after a third of that bound, so a
//!   silent stream is renewed well inside it. Otherwise the connector fails
//!   closed (`Unavailable`): bounded staleness, never silent acceptance.
//!
//! ServiceAccount deletions and UID changes are also reported as lifecycle
//! signals so that Pumgye can orphan bindings of the retired principal.
//! Credentials: a narrowly scoped token with `list`/`watch` on
//! `serviceaccounts` (and `pods`) in the allowed namespaces only.
use super::super::runtime::Error;
use super::cache::Cache;
use super::http::{self, Bearer};
use super::identity::{self, WorkloadAttributes};
use super::metrics;
use super::signals::{Signal, Sink, WorkloadRef};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::time::Instant;

const LIST_ACCEPT: &str = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
const WATCH_ACCEPT: &str = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1";
const LIST_PAGE: usize = 500;
const LIST_PAGE_BYTES: usize = 4 * 1024 * 1024;
const WATCH_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Resource {
    ServiceAccounts,
    Pods,
}

impl Resource {
    fn path(self) -> &'static str {
        match self {
            Resource::ServiceAccounts => "serviceaccounts",
            Resource::Pods => "pods",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Meta {
    uid: String,
    terminating: bool,
}

#[derive(Default)]
struct Index {
    ready: bool,
    confirmed: Option<Instant>,
    objects: HashMap<String, Meta>,
}

/// Status for the management view.
#[derive(Clone, Debug, serde::Serialize)]
pub struct RevocationStatus {
    pub mode: &'static str,
    pub ready: bool,
    pub staleness_ms: Option<u64>,
    pub max_staleness_ms: u64,
    pub objects: usize,
    pub overflow: bool,
}

pub(crate) struct Revocation {
    service: String,
    issuer: String,
    cluster_id: String,
    trust_domain: Option<String>,
    client: reqwest::Client,
    origin: url::Url,
    bearer: Bearer,
    namespaces: Vec<String>,
    resources: Vec<Resource>,
    max_staleness: Duration,
    max_objects: usize,
    indexes: RwLock<HashMap<(Resource, String), Index>>,
    overflow: std::sync::atomic::AtomicBool,
    stale_reported: std::sync::atomic::AtomicBool,
    sink: Mutex<Option<Sink>>,
    cache: Mutex<Option<Weak<Cache>>>,
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}
fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

/// Refusal reasons of [`Revocation::check`] (metrics labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Stale,
    ServiceAccountAbsent,
    ServiceAccountReplaced,
    PodAbsent,
    PodTerminating,
}

impl Refusal {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Refusal::Stale => "revocation_stale",
            Refusal::ServiceAccountAbsent => "service_account_absent",
            Refusal::ServiceAccountReplaced => "service_account_replaced",
            Refusal::PodAbsent => "pod_absent",
            Refusal::PodTerminating => "pod_terminating",
        }
    }
    pub(crate) fn error(self) -> Error {
        match self {
            Refusal::Stale => Error::Unavailable,
            _ => Error::Invalid,
        }
    }
}

impl Revocation {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        service: &str,
        issuer: &str,
        cluster_id: &str,
        trust_domain: Option<&str>,
        client: reqwest::Client,
        origin: url::Url,
        bearer: Bearer,
        namespaces: Vec<String>,
        resources: Vec<Resource>,
        max_staleness: Duration,
        max_objects: usize,
    ) -> Self {
        Self {
            service: service.to_owned(),
            issuer: issuer.to_owned(),
            cluster_id: cluster_id.to_owned(),
            trust_domain: trust_domain.map(str::to_owned),
            client,
            origin,
            bearer,
            namespaces,
            resources,
            max_staleness,
            max_objects,
            indexes: RwLock::new(HashMap::new()),
            overflow: std::sync::atomic::AtomicBool::new(false),
            stale_reported: std::sync::atomic::AtomicBool::new(false),
            sink: Mutex::new(None),
            cache: Mutex::new(None),
        }
    }

    pub(crate) fn attach(&self, sink: Option<Sink>, cache: &Arc<Cache>) {
        if let Some(sink) = sink {
            *self.sink.lock().unwrap_or_else(|p| p.into_inner()) = Some(sink);
        }
        *self.cache.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::downgrade(cache));
    }

    fn emit(&self, signal: Signal) {
        if let Some(sink) = self.sink.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            sink.emit(signal);
        }
    }

    fn cache(&self) -> Option<Arc<Cache>> {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
    }

    pub(crate) fn watches_pods(&self) -> bool {
        self.resources.contains(&Resource::Pods)
    }

    /// The hot-path check: index reads only, no API request.
    pub(crate) fn check(
        &self,
        namespace: &str,
        service_account: &str,
        service_account_uid: &str,
        pod: Option<(&str, &str)>,
    ) -> Result<(), Refusal> {
        if self.overflow.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Refusal::Stale);
        }
        let indexes = read(&self.indexes);
        let current = |resource: Resource| -> Result<&Index, Refusal> {
            let index = indexes
                .get(&(resource, namespace.to_owned()))
                .filter(|i| i.ready)
                .ok_or(Refusal::Stale)?;
            let age = index.confirmed.map(|t| t.elapsed()).ok_or(Refusal::Stale)?;
            if age > self.max_staleness {
                return Err(Refusal::Stale);
            }
            Ok(index)
        };
        let accounts = current(Resource::ServiceAccounts)?;
        match accounts.objects.get(service_account) {
            None => return Err(Refusal::ServiceAccountAbsent),
            Some(m) if m.uid != service_account_uid => {
                return Err(Refusal::ServiceAccountReplaced);
            }
            Some(_) => {}
        }
        if let (Some((name, uid)), true) = (pod, self.watches_pods()) {
            let pods = current(Resource::Pods)?;
            match pods.objects.get(name) {
                Some(m) if m.uid != uid => return Err(Refusal::PodAbsent),
                Some(m) if m.terminating => return Err(Refusal::PodTerminating),
                Some(_) => {}
                None => return Err(Refusal::PodAbsent),
            }
        }
        Ok(())
    }

    /// For the explain API: whether a ServiceAccount is currently present.
    pub(crate) fn service_account_state(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Result<Option<String>, Refusal> {
        let indexes = read(&self.indexes);
        let index = indexes
            .get(&(Resource::ServiceAccounts, namespace.to_owned()))
            .filter(|i| i.ready)
            .ok_or(Refusal::Stale)?;
        if index
            .confirmed
            .is_none_or(|t| t.elapsed() > self.max_staleness)
        {
            return Err(Refusal::Stale);
        }
        Ok(index.objects.get(service_account).map(|m| m.uid.clone()))
    }

    pub(crate) fn status(&self) -> RevocationStatus {
        let indexes = read(&self.indexes);
        let mut ready = true;
        let mut oldest: Option<Duration> = None;
        let mut objects = 0;
        for resource in &self.resources {
            for namespace in &self.namespaces {
                match indexes.get(&(*resource, namespace.clone())) {
                    Some(i) if i.ready => {
                        objects += i.objects.len();
                        let age = i.confirmed.map(|t| t.elapsed()).unwrap_or(Duration::MAX);
                        oldest = Some(oldest.map_or(age, |o| o.max(age)));
                    }
                    _ => ready = false,
                }
            }
        }
        let staleness_ms = oldest.map(|d| d.as_millis().min(u64::MAX as u128) as u64);
        if let Some(ms) = staleness_ms {
            metrics::revocation_staleness(&self.service, ms);
        }
        RevocationStatus {
            mode: "watch",
            ready,
            staleness_ms,
            max_staleness_ms: self.max_staleness.as_millis() as u64,
            objects,
            overflow: self.overflow.load(std::sync::atomic::Ordering::Acquire),
        }
    }

    fn total_objects(indexes: &HashMap<(Resource, String), Index>) -> usize {
        indexes.values().map(|i| i.objects.len()).sum()
    }

    fn workload_ref(&self, namespace: &str, name: &str, uid: &str) -> WorkloadRef {
        let w = identity::Workload {
            issuer: self.issuer.clone(),
            cluster_id: self.cluster_id.clone(),
            namespace: namespace.to_owned(),
            service_account: name.to_owned(),
            service_account_uid: uid.to_owned(),
            pod: None,
            secret: None,
            node: None,
        };
        let (_, attributes): (_, WorkloadAttributes) = w
            .resolve(
                self.trust_domain.as_deref(),
                identity::SubjectMode::ServiceAccount,
                "offline_jwks",
            )
            .expect("service-account subject always resolves");
        WorkloadRef::of(&self.service, &attributes)
    }

    fn retired(
        &self,
        resource: Resource,
        namespace: &str,
        name: &str,
        old: &Meta,
        new: Option<&Meta>,
    ) {
        match resource {
            Resource::ServiceAccounts => {
                if let Some(cache) = self.cache() {
                    cache.evict_service_account(namespace, &old.uid);
                }
                let replacement = new.map(|m| {
                    identity::principal_ref(&self.issuer, &self.cluster_id, namespace, name, &m.uid)
                });
                self.emit(Signal::Retired {
                    workload: self.workload_ref(namespace, name, &old.uid),
                    cause: if new.is_some() {
                        "uid_changed"
                    } else {
                        "deleted"
                    },
                    replacement,
                });
            }
            Resource::Pods => {
                if let Some(cache) = self.cache() {
                    cache.evict_pod(namespace, &old.uid);
                }
            }
        }
    }

    /// Apply a complete LIST: replaces the index; objects that disappeared
    /// (or changed UID) while the watch was down are retired.
    fn apply_list(
        &self,
        resource: Resource,
        namespace: &str,
        objects: HashMap<String, Meta>,
    ) -> bool {
        let mut indexes = write(&self.indexes);
        let key = (resource, namespace.to_owned());
        let others =
            Self::total_objects(&indexes) - indexes.get(&key).map_or(0, |i| i.objects.len());
        if others + objects.len() > self.max_objects {
            self.overflow
                .store(true, std::sync::atomic::Ordering::Release);
            indexes.remove(&key);
            return false;
        }
        let previous = indexes.remove(&key);
        let mut retired = Vec::new();
        if let Some(previous) = &previous
            && previous.ready
        {
            for (name, old) in &previous.objects {
                match objects.get(name) {
                    Some(new) if new.uid == old.uid => {}
                    new => retired.push((name.clone(), old.clone(), new.cloned())),
                }
            }
        }
        indexes.insert(
            key,
            Index {
                ready: true,
                confirmed: Some(Instant::now()),
                objects,
            },
        );
        drop(indexes);
        for (name, old, new) in retired {
            self.retired(resource, namespace, &name, &old, new.as_ref());
        }
        true
    }

    fn confirm(&self, resource: Resource, namespace: &str) {
        if let Some(index) = write(&self.indexes).get_mut(&(resource, namespace.to_owned())) {
            index.confirmed = Some(Instant::now());
        }
    }

    fn apply_event(
        &self,
        resource: Resource,
        namespace: &str,
        kind: &str,
        name: &str,
        meta: Meta,
    ) -> bool {
        let mut indexes = write(&self.indexes);
        let total = Self::total_objects(&indexes);
        let Some(index) = indexes.get_mut(&(resource, namespace.to_owned())) else {
            return false;
        };
        index.confirmed = Some(Instant::now());
        let old = match kind {
            "ADDED" | "MODIFIED" => {
                if !index.objects.contains_key(name) && total >= self.max_objects {
                    self.overflow
                        .store(true, std::sync::atomic::Ordering::Release);
                    return false;
                }
                let old = index.objects.insert(name.to_owned(), meta.clone());
                old.filter(|o| o.uid != meta.uid).map(|o| (o, Some(meta)))
            }
            "DELETED" => match index.objects.get(name) {
                Some(o) if o.uid == meta.uid => index.objects.remove(name).map(|o| (o, None)),
                _ => None,
            },
            _ => None,
        };
        drop(indexes);
        if let Some((old, new)) = old {
            self.retired(resource, namespace, name, &old, new.as_ref());
        }
        true
    }

    fn mark_unready(&self, resource: Resource, namespace: &str) {
        if let Some(index) = write(&self.indexes).get_mut(&(resource, namespace.to_owned())) {
            index.ready = false;
        }
    }

    fn url(&self, resource: Resource, namespace: &str, query: &[(&str, &str)]) -> Option<url::Url> {
        let mut url = self
            .origin
            .join(&format!(
                "/api/v1/namespaces/{namespace}/{}",
                resource.path()
            ))
            .ok()?;
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in query {
                q.append_pair(k, v);
            }
        }
        Some(url)
    }

    fn meta(value: &serde_json::Value, namespace: &str) -> Option<(String, Meta)> {
        let m = value.get("metadata")?;
        let name = m.get("name")?.as_str()?;
        let uid = m.get("uid")?.as_str()?;
        if m.get("namespace").and_then(|v| v.as_str()) != Some(namespace)
            || !identity::object_name(name)
            || !identity::uid(uid)
        {
            return None;
        }
        Some((
            name.to_owned(),
            Meta {
                uid: uid.to_owned(),
                terminating: m.get("deletionTimestamp").is_some_and(|v| !v.is_null()),
            },
        ))
    }

    async fn list(
        &self,
        resource: Resource,
        namespace: &str,
    ) -> Result<(HashMap<String, Meta>, String), &'static str> {
        let mut objects = HashMap::new();
        let mut cont: Option<String> = None;
        loop {
            let limit = LIST_PAGE.to_string();
            let mut query = vec![("limit", limit.as_str())];
            if let Some(c) = cont.as_deref() {
                query.push(("continue", c));
            }
            let url = self.url(resource, namespace, &query).ok_or("url")?;
            let body = http::get_json(
                &self.client,
                &url,
                &self.bearer,
                LIST_ACCEPT,
                LIST_PAGE_BYTES,
                Duration::from_secs(30),
            )
            .await?;
            let doc: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "list_invalid")?;
            if doc.get("kind").and_then(|v| v.as_str()) != Some("PartialObjectMetadataList") {
                return Err("list_invalid");
            }
            for item in doc
                .get("items")
                .and_then(|v| v.as_array())
                .ok_or("list_invalid")?
            {
                let (name, meta) = Self::meta(item, namespace).ok_or("list_invalid")?;
                objects.insert(name, meta);
                if objects.len() > self.max_objects {
                    return Err("overflow");
                }
            }
            let md = doc.get("metadata").ok_or("list_invalid")?;
            match md
                .get("continue")
                .and_then(|v| v.as_str())
                .filter(|c| !c.is_empty())
            {
                Some(c) if c.len() <= 4096 => cont = Some(c.to_owned()),
                Some(_) => return Err("list_invalid"),
                None => {
                    let rv = md
                        .get("resourceVersion")
                        .and_then(|v| v.as_str())
                        .filter(|v| !v.is_empty() && v.len() <= 128)
                        .ok_or("list_invalid")?;
                    return Ok((objects, rv.to_owned()));
                }
            }
        }
    }

    /// One watch request; returns the next resourceVersion, or `Err("gone")`
    /// when a relist is required.
    async fn watch_once(
        &self,
        resource: Resource,
        namespace: &str,
        rv: &str,
    ) -> Result<String, &'static str> {
        let timeout = (self.max_staleness.as_secs() / 3).clamp(1, 290);
        let timeout_s = timeout.to_string();
        let url = self
            .url(
                resource,
                namespace,
                &[
                    ("watch", "1"),
                    ("allowWatchBookmarks", "true"),
                    ("resourceVersion", rv),
                    ("timeoutSeconds", &timeout_s),
                ],
            )
            .ok_or("url")?;
        let deadline = Instant::now() + Duration::from_secs(timeout + 5);
        let mut response = tokio::time::timeout_at(
            deadline,
            http::open_stream(&self.client, &url, &self.bearer, WATCH_ACCEPT),
        )
        .await
        .map_err(|_| "timeout")??;
        // An established watch confirms the index as of now.
        self.confirm(resource, namespace);
        let mut rv = rv.to_owned();
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let chunk = match tokio::time::timeout_at(deadline, response.chunk()).await {
                Err(_) => return Ok(rv), // client-side bound on a silent stream
                Ok(Err(_)) => return Err("transport"),
                Ok(Ok(None)) => return Ok(rv),
                Ok(Ok(Some(chunk))) => chunk,
            };
            buffer.extend_from_slice(&chunk);
            while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=pos).collect();
                let line = &line[..line.len() - 1];
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let event: serde_json::Value =
                    serde_json::from_slice(line).map_err(|_| "watch_invalid")?;
                let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let object = event.get("object").ok_or("watch_invalid")?;
                match kind {
                    "ERROR" => {
                        metrics::revocation_event(&self.service, resource.path(), "error");
                        let code = object.get("code").and_then(|v| v.as_u64());
                        return Err(if code == Some(410) {
                            "gone"
                        } else {
                            "watch_error"
                        });
                    }
                    "BOOKMARK" => {
                        metrics::revocation_event(&self.service, resource.path(), "bookmark");
                        self.confirm(resource, namespace);
                    }
                    "ADDED" | "MODIFIED" | "DELETED" => {
                        let (name, meta) = Self::meta(object, namespace).ok_or("watch_invalid")?;
                        metrics::revocation_event(
                            &self.service,
                            resource.path(),
                            &kind.to_ascii_lowercase(),
                        );
                        if !self.apply_event(resource, namespace, kind, &name, meta) {
                            return Err("overflow");
                        }
                    }
                    _ => return Err("watch_invalid"),
                }
                if let Some(next) = object
                    .get("metadata")
                    .and_then(|m| m.get("resourceVersion"))
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.is_empty() && v.len() <= 128)
                {
                    rv = next.to_owned();
                }
            }
            if buffer.len() > WATCH_LINE_BYTES {
                return Err("watch_invalid");
            }
        }
    }

    /// The per-(resource, namespace) loop: LIST, then WATCH until the stream
    /// needs a relist; backoff on failure. Stops when the connector is gone.
    async fn run(weak: Weak<Self>, resource: Resource, namespace: String) {
        let mut failures: u32 = 0;
        'relist: loop {
            let Some(this) = weak.upgrade() else { return };
            let listed = this.list(resource, &namespace).await;
            let mut rv = match listed {
                Ok((objects, rv)) => {
                    metrics::revocation_event(&this.service, resource.path(), "relist");
                    if !this.apply_list(resource, &namespace, objects) {
                        metrics::revocation_event(&this.service, resource.path(), "overflow");
                    }
                    failures = 0;
                    rv
                }
                Err(reason) => {
                    metrics::revocation_event(&this.service, resource.path(), reason);
                    if reason == "overflow" {
                        this.overflow
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                    tracing::warn!(service = %this.service, resource = resource.path(), reason, "workload revocation list failed");
                    drop(this);
                    failures = failures.saturating_add(1);
                    tokio::time::sleep(backoff(failures)).await;
                    continue 'relist;
                }
            };
            drop(this);
            loop {
                let Some(this) = weak.upgrade() else { return };
                match this.watch_once(resource, &namespace, &rv).await {
                    Ok(next) => {
                        rv = next;
                        failures = 0;
                    }
                    Err("gone") => {
                        metrics::revocation_event(&this.service, resource.path(), "expired");
                        continue 'relist;
                    }
                    Err(reason) => {
                        metrics::revocation_event(&this.service, resource.path(), reason);
                        if reason == "overflow" || reason == "watch_invalid" {
                            this.mark_unready(resource, &namespace);
                        }
                        drop(this);
                        failures = failures.saturating_add(1);
                        tokio::time::sleep(backoff(failures)).await;
                        continue 'relist;
                    }
                }
            }
        }
    }

    /// Start one task per (resource, namespace) on the current runtime.
    pub(crate) fn start(self: &Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for resource in self.resources.clone() {
            for namespace in self.namespaces.clone() {
                handle.spawn(Self::run(Arc::downgrade(self), resource, namespace));
            }
        }
        // Staleness reporter: one signal per transition.
        let weak = Arc::downgrade(self);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(this) = weak.upgrade() else { return };
                let status = this.status();
                let stale = status.overflow
                    || !status.ready
                    || status
                        .staleness_ms
                        .is_none_or(|ms| ms > status.max_staleness_ms);
                let was = this
                    .stale_reported
                    .swap(stale, std::sync::atomic::Ordering::AcqRel);
                if was != stale {
                    this.emit(Signal::RevocationStale {
                        service: this.service.clone(),
                        stale,
                    });
                }
            }
        });
    }
}

fn backoff(failures: u32) -> Duration {
    Duration::from_millis((250u64 << failures.min(7)).min(30_000))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn revocation(max_staleness: Duration) -> Revocation {
        Revocation::new(
            "orders",
            "https://issuer.example.test",
            "example-cluster",
            Some("cluster.example.test"),
            reqwest::Client::new(),
            url::Url::parse("https://kubernetes.example.test/").unwrap(),
            Bearer::None,
            vec!["blue".into()],
            vec![Resource::ServiceAccounts, Resource::Pods],
            max_staleness,
            8,
        )
    }

    fn meta(uid: &str) -> Meta {
        Meta {
            uid: uid.into(),
            terminating: false,
        }
    }

    #[tokio::test]
    async fn index_refuses_deleted_replaced_and_terminating_objects_and_stale_views() {
        let r = revocation(Duration::from_secs(60));
        assert_eq!(r.check("blue", "worker", "sa-1", None), Err(Refusal::Stale));
        let (sink, mut rx) = super::super::signals::channel();
        let cache = Arc::new(Cache::new(1000, 10));
        r.attach(Some(sink), &cache);
        r.apply_list(
            Resource::ServiceAccounts,
            "blue",
            HashMap::from([("worker".to_string(), meta("sa-1"))]),
        );
        assert_eq!(
            r.check("blue", "worker", "sa-1", Some(("worker-pod", "pod-1"))),
            Err(Refusal::Stale),
            "pods not yet listed"
        );
        r.apply_list(
            Resource::Pods,
            "blue",
            HashMap::from([("worker-pod".to_string(), meta("pod-1"))]),
        );
        assert_eq!(
            r.check("blue", "worker", "sa-1", Some(("worker-pod", "pod-1"))),
            Ok(())
        );
        assert_eq!(
            r.check("blue", "worker", "sa-0", None),
            Err(Refusal::ServiceAccountReplaced)
        );
        assert_eq!(
            r.check("blue", "other", "sa-1", None),
            Err(Refusal::ServiceAccountAbsent)
        );
        assert_eq!(
            r.check("blue", "worker", "sa-1", Some(("worker-pod", "pod-0"))),
            Err(Refusal::PodAbsent)
        );
        r.apply_event(
            Resource::Pods,
            "blue",
            "MODIFIED",
            "worker-pod",
            Meta {
                uid: "pod-1".into(),
                terminating: true,
            },
        );
        assert_eq!(
            r.check("blue", "worker", "sa-1", Some(("worker-pod", "pod-1"))),
            Err(Refusal::PodTerminating)
        );
        // Re-creation under the same name retires the old principal.
        r.apply_event(
            Resource::ServiceAccounts,
            "blue",
            "ADDED",
            "worker",
            meta("sa-2"),
        );
        assert_eq!(
            r.check("blue", "worker", "sa-1", None),
            Err(Refusal::ServiceAccountReplaced)
        );
        match rx.try_recv().unwrap() {
            Signal::Retired {
                workload,
                cause,
                replacement,
            } => {
                assert_eq!(cause, "uid_changed");
                assert_eq!(workload.service_account_uid, "sa-1");
                assert_eq!(
                    replacement.as_deref(),
                    Some(
                        identity::principal_ref(
                            "https://issuer.example.test",
                            "example-cluster",
                            "blue",
                            "worker",
                            "sa-2"
                        )
                        .as_str()
                    )
                );
                assert_eq!(
                    workload.spiffe_id.as_deref(),
                    Some("spiffe://cluster.example.test/ns/blue/sa/worker")
                );
            }
            other => panic!("{other:?}"),
        }
        // A deletion missed during a watch outage is found by the relist.
        r.apply_list(Resource::ServiceAccounts, "blue", HashMap::new());
        assert!(matches!(
            rx.try_recv().unwrap(),
            Signal::Retired {
                cause: "deleted",
                ..
            }
        ));
        assert_eq!(
            r.check("blue", "worker", "sa-2", None),
            Err(Refusal::ServiceAccountAbsent)
        );
    }

    #[tokio::test]
    async fn staleness_and_overflow_fail_closed() {
        let r = revocation(Duration::from_millis(50));
        r.apply_list(
            Resource::ServiceAccounts,
            "blue",
            HashMap::from([("worker".to_string(), meta("sa-1"))]),
        );
        r.apply_list(Resource::Pods, "blue", HashMap::new());
        assert_eq!(r.check("blue", "worker", "sa-1", None), Ok(()));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(r.check("blue", "worker", "sa-1", None), Err(Refusal::Stale));
        r.confirm(Resource::ServiceAccounts, "blue");
        assert_eq!(r.check("blue", "worker", "sa-1", None), Ok(()));
        let many: HashMap<String, Meta> = (0..9)
            .map(|i| (format!("sa{i}"), meta(&format!("u{i}"))))
            .collect();
        assert!(!r.apply_list(Resource::ServiceAccounts, "blue", many));
        assert_eq!(r.check("blue", "worker", "sa-1", None), Err(Refusal::Stale));
        assert!(r.status().overflow);
    }
}
