# Operations

<!-- doc-rev: 8 -->

[Documentation](README.md) · [한국어](ko/OPERATIONS.md)

How to run, observe, maintain and recover a Hopae instance in milestones M1 and M4-min.
Every setting named here is defined in the [configuration
reference](CONFIG.md); the protocol with the gateway is the [gateway
contract](GATEWAY_CONTRACT.md). A production Docker Compose template and a
gateway route example are in the repository's `deploy/` directory.

## Prerequisites and configuration

- A gateway that can send the forward-authentication check Hopae answers (Hangang with gateway change HC-3 for production; see the [compatibility matrix](GATEWAY_CONTRACT.md#versioning)).
- One JSON configuration file ([CONFIG.md](CONFIG.md)) and the environment variables it names: the gateway caller key and, for each provider, the client secret. Keep them in a private env file, never in the configuration file or the image.
- A writable, private state directory (`state_dir`) on local storage that supports POSIX advisory locks and SQLite WAL (a local disk or a Docker volume; not a network file system).
- One instance per state directory. M1 is a single-instance product; there is no shared store before M2.
- Two public routes on the gateway: the portal host (public, proxied to `listen.portal`) and each protected application host (carrying the `auth` fragment that `hopae --check` prints).
- Both listeners bind loopback by default. The gateway listener must never be publicly reachable; the caller key is a second barrier, not the first.
- To use the management console (optional): a third public route for a dedicated console host, proxied to `listen.admin` and carrying the `auth` fragment **without** `strip_request_cookies` (the `hopae-admin` route in `deploy/hangang-routes.example.json`; `hopae --check` prints it), the gateway's address in `trusted_proxies`, and `admin.public_url` set. See [administration](ADMIN.md) and [the console](#management-console).

## Behavior

### Running Hopae

```sh
hopae --check --config /etc/hopae/hopae.json     # validate; print the route fragment; exit 0 or 2
hopae run     --config /etc/hopae/hopae.json     # serve (alias: serve; the default command)
```

Always run `--check` first and after every configuration change, with the same
environment the service will have. On success `run` prints stable lines on
stdout (the `admin` line only when `admin.public_url` is set) and then serves:

```text
portal listening on 127.0.0.1:8700
gateway listening on 127.0.0.1:8701
admin listening on 127.0.0.1:8702
```

Start order is fixed: instance lock, read-only precheck of an existing
database, backup of an older database, store opened and migrated, providers
imported (with the `config.loaded` event in the same transaction),
administrator grants imported from `admin.users[]`, applications mirrored,
portal listener bound, admin listener bound (when enabled), gateway listener
bound last, ready. A failure at any step exits before a listener answers a
request.

Stop with `SIGTERM` or `SIGINT`. Hopae stops accepting, gives in-flight
requests 5 seconds, stops its background workers (they flush on the way out),
checkpoints the SQLite write-ahead log and exits `0`. `SIGHUP` is logged and
ignored; configuration changes need a restart (reload arrives in M6).

Exit status: `0` clean stop or successful command; `2` invalid or unsafe
configuration, missing caller-key variable, missing `--config`, or a second
instance on the same state directory; `1` any other runtime failure. A
supervisor that restarts on failure should not restart on `2` without a
change: the same start will fail the same way.

### State directory

`state_dir` is created with mode `0700` and holds:

| Path | Content | Handling |
| --- | --- | --- |
| `hopae.db` (or `store.path`) | The SQLite database in WAL mode: users, identities, sessions, handles, transactions, handoff codes, events and delivery rows, providers, applications | Back up before every upgrade. Contains hashed credentials only: handles, codes and keys are stored as SHA-256 digests, never as values. Treat it as sensitive anyway (it holds email addresses and subjects). |
| `hopae.db-wal`, `hopae.db-shm` | SQLite write-ahead log and shared memory | Never copy or delete by hand while the process runs; they are folded into the database at a clean stop. |
| `hopae.lock` | Instance lock | See below. |
| `hopae.db.bak-v<N>` | Backup written before a migration (`hopae.db.bak-v2` when 0003 is applied) | See below. |

The database file is created with a restrictive mode before SQLite writes to
it. Provider client secrets and caller keys are not stored in the state
directory: they live only in the environment.

### The instance lock

At start Hopae takes an exclusive advisory lock on `<state_dir>/hopae.lock` and
holds it for the life of the process. A second `hopae run` on the same state
directory fails immediately with `store locked by another instance` and exit
`2`, before the database is touched. The operating system drops the lock when
the process exits or crashes, so there is no stale lock to clean up and the
file itself is safe to leave in place. `hopae --check`, `hopae providers
import` and `hopae admin` do not take the lock.

In a container, the lock is only effective if both instances see the same
state volume; do not run a second container "to try a new image" against the
live volume. Stop the old one first.

### Upgrade and migration backups

Schema migrations are embedded in the binary and applied at start, forward
only, each in its own transaction. Before anything is written, Hopae runs a
read-only **precheck** of an existing database: it reads the recorded version,
refuses a newer one and validates the foundation of the recorded version. Only
a database that passed the precheck is backed up, and only then is a migration
applied; a refused database is left byte for byte as it is, with no backup.
Before applying any migration to an
existing database that is older than the binary, Hopae writes a consistent
copy next to it as `hopae.db.bak-v<N>`, where `<N>` is the schema version found
(mode `0600`, written with `VACUUM INTO` to a temporary file that is renamed into place only when complete, so WAL content is included and an interrupted run never replaces the previous backup). No
backup is made for a new, empty or already current database. An existing
backup of the same version is replaced. A database written by a newer binary is
refused (the start fails). So is a database of schema version 2 written by a
pre-release development build, recognizable by a missing
`sessions.authz_version_at_auth` column, `users_primary_email` or
`event_deliveries_event_id` index, or `txn_admissions` table: the
start fails with exit status 2 and the message "development database from a
pre-release schema; delete it". Before the first release schema version 2 was
edited in place, so such a database cannot be upgraded; delete it. That was
the last in-place edit of migration `0002` (it gained the `logout` transaction
purpose, recognizable by the `login_txns` check constraint): once a deployment
holds a database, **every schema change is a new numbered migration**, applied
forward only after the backup above, and an applied migration file is never
edited again.

Migration `0003` (milestone M4-min, schema version 3) adds the
administrator grant table, the session columns for freshness provenance
(`auth_time_source`, `bound_ua_prefix`), the reauthentication column of login
transactions and replacement indexes on `events`, `users` and `sessions` for
the console listings. Existing sessions get `auth_time_source =
hopae_completion`. Creating the new event indexes reads the events table once,
so the first start after the upgrade takes longer on a large event history. A
binary that predates 0003 refuses the migrated database (it is newer than that
binary supports), so rolling back past 0003 means restoring the `.bak-v2` file
or your own copy (below).

Upgrade procedure:

1. Run the new binary's `hopae --check` against the current configuration.
2. Stop the running instance (`SIGTERM`) so the database is checkpointed.
3. Copy the state directory (or at least `hopae.db`) somewhere safe. The automatic backup covers a failed migration; it does not replace this copy, which also protects against a bad release.
4. Start the new binary. Read the log for `schema foundation validated (v2)`, `database backup written before migration` and `store ready: ... (schema vN)`; from schema 2 to 3 the backup is `hopae.db.bak-v2`.
5. Keep the previous image or binary until the new one has served real traffic.

Rollback: stop Hopae, restore the saved copy (or the `.bak-v<N>` file) over
`hopae.db`, remove any `hopae.db-wal` and `hopae.db-shm` left beside it, and
start the previous binary. Sessions created after the backup are lost, and so
are administrator grants and audit events written after it; users sign in
again.

### Management console

The console is a third listener, `listen.admin` (default `127.0.0.1:8702`),
bound only when `admin.public_url` is set. It has no health endpoint; `/healthz`
stays on the portal. Enable it in this order:

1. Pick the console host (`hopae-admin.example.test` in the examples), give it DNS and TLS on the gateway and register the `hopae-admin` route from `deploy/hangang-routes.example.json`: protected, backend `listen.admin`, the standard `auth` fragment, **no** `strip_request_cookies`. A route that strips Hopae's cookies makes every console request `403 login_required`.
2. Set `admin.public_url` (and, if needed, `listen.admin`, `admin.max_auth_age` and the other `admin.*` keys of [the configuration reference](CONFIG.md#management-console)). The gateway's address must be in `trusted_proxies`: the listener takes the client address, scheme and host from the forwarding headers of a trusted peer only, and with the default `admin.untrusted_peers = refuse` it answers any other peer `403 untrusted_peer` before reading a cookie. A non-loopback `listen.admin` produces a warning; it must never be publicly reachable.
3. Run `hopae --check`. It lists the console as the implicit application `admin`, prints the route fragment with the real host and admin address, `admin.untrusted_peers`, and per enabled provider the freshness capability (`reauth max_age: ...` or `reauth unsupported: console freshness is Hopae login age; ...`). With `gateway.admin_url` and the read-only token it also warns `console_route_without_auth` or `console_route_strips_cookies`. `--strict` turns every warning into an error.
4. Restart Hopae and bootstrap the first administrator: sign in once at the console host, read the user id from the `403 not_admin` page, run `hopae admin grant <user_id> --config <path>` and reload ([bootstrap](ADMIN.md#bootstrap-and-recovery)). In a container, `docker compose run --rm hopae admin grant <user_id> --config /etc/hopae/hopae.json` runs against the same state volume without stopping the instance.

`admin.users[]` is imported at every start after the provider import: a defective
entry is a warning in the log (skipped, never a start failure), and a live file
grant that no entry names any more is revoked. Grants made or revoked with
`hopae admin` are never undone by the file. Every console change, denial and
grant is an `admin.*` event ([audit events](ADMIN.md#audit-events)). A store
operation that reaches `admin.query_budget_ms` is interrupted, rolled back and
answered `503`; `hopae_store_interrupts_total` counts it.

Verify from the host that the listener trusts nothing but a valid handle (a
request without the console host in `x-forwarded-host` is `404`):

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'x-forwarded-host: hopae-admin.example.test' \
  http://127.0.0.1:8702/v1/me      # 403 login_required: no handle, nothing trusted from the request
```

### Caller-key rotation

The caller key is the shared secret the gateway sends in `x-hopae-gateway-key`.
Rotate it without a window in which verify calls fail:

1. Generate a new random value. Put it in Hopae's env file under a new variable name, for example `HOPAE_GATEWAY_KEY_NEXT`, and set `gateway.caller_key_next_env` to that name. Restart Hopae. It now accepts both keys; `hopae_verify_caller_key_total{slot="next"}` counts calls that used the new one.
2. Switch the gateway: set the new value as the variable that the route's `static_request_headers` references (for example `HANGANG_HOPAE_KEY`) and reload or restart the gateway. Watch the counters: `slot="current"` should fall to zero and `slot="next"` carry all traffic.
3. Promote: set `HOPAE_GATEWAY_KEY` to the new value, remove `gateway.caller_key_next_env` (and the next variable), and restart Hopae. The old key is now rejected.

Hopae records when the overlap began; `hopae --check` warns once
`caller_key_next_env` has been configured for more than 7 days (`--strict` makes
that an error). A key mismatch shows as `403 caller_unauthorized` on every
verify, a rising `hopae_verify_unauthorized_total`, and no state read or
written.

### TLS certificate renewal

Every mutual-TLS listener (the administrator listener, the native and gRPC
gateways) and the outbound mTLS clients of the projection receiver follow their
files: Hopae re-reads the certificate, key and CA every
`reload.tls_interval_secs` (default 10 s) and compares their content digest —
no file-system notifications, so a Kubernetes secret volume's symlink swap
and an in-place rewrite are both seen. With cert-manager, mount the secret as
a directory (not `subPath`) and point the configuration at `tls.crt`,
`tls.key` and `ca.crt`; a renewal needs no restart.

- A changed set is checked completely first: certificates parse, the private
  key matches the leaf, the CA file holds a certificate. Only then is the new
  configuration swapped in, atomically. New handshakes use it; established
  connections keep theirs until they close. Outbound clients switch to a new
  channel for every later call.
- Each load logs the leaf's fingerprint (`TLS material reloaded name=…
  fingerprint=sha256:…`); `GET /v1/status` → `reload.tls[]` shows each item's
  `fingerprint`, `reloads`, `last_reload_at`, `failing` and `error`.
- An invalid or half-written set (a key from the next certificate, an empty
  CA) changes nothing: the previous material stays in force,
  `hopae_tls_reload_failing{name}` is `1` and a warning names the cause. It
  clears when a valid set arrives or the files return to the material in use.
  Alert on it, and on certificates that are not renewed before expiry.
- A rotated client CA admits the clients it signs on their next handshake and
  refuses the old ones; rotate a CA by publishing a bundle with both
  certificates first.
- An OIDC provider's own trust (`providers[].tls`: a private CA, a client
  certificate) follows its files the same way, every `reload.tls_interval_secs`
  (`0` turns it off), under the name `provider:<id>` (`hopae_tls_reloads_total`,
  `hopae_tls_reload_failing`); a `private_key_jwt` key file
  (`providers[].client_assertion`) under `provider:<id>:client_assertion`.
  Rotate an assertion key by registering the new public key at the provider
  first (`hopae providers jwk <id>` prints it), then replacing the file. A
  valid change rebuilds the provider's client; requests in flight finish on
  the previous one. `GET /v1/status` → `providers[].tls` shows the trust source
  (`ca_file` or `system`), the CA and client certificate fingerprints,
  `reloads`, `failing` and `error`; `hopae_provider_tls_trust{provider,source}`
  is `1` for the source in use. `hopae --check` reads and checks the files.

### Provider secret rotation

Provider client secrets are read from the environment when Hopae starts and
when the provider registry is built; there is no reload. To rotate: create the
new secret at the provider (keep the old one valid if the provider allows two),
update the variable named by `providers[].client_secret_env` in the env file,
and restart Hopae. In-flight logins at the moment of the restart must be
repeated; established sessions are unaffected. If the variable is unset or
empty the provider starts `disabled` (the chooser omits it, `/healthz` reports
`disabled`) and Hopae logs a warning; other providers and existing sessions are
not affected.

Changing provider definitions in the file follows the import rule: the file
inserts or updates providers on every start, but the database is authoritative
for providers changed or removed at run time. To reassert a file entry over the
database, run `hopae providers import --force <provider_id> --config <path>`
and restart.

### Logs and events

Hopae writes to **stderr**; stdout carries only the startup lines above.

- **Process log**: human-readable `tracing` lines (with ANSI colour codes, even when stderr is not a terminal) at `log.level`: start-up steps, warnings (insecure modes, disabled providers, imported-provider skips), backup and shutdown messages, and errors. Provider failures log reason codes, never response bodies.
- **Event stream**: one JSON object per line, written by the `log` sink, with the same fields as the stored event: `event_id`, `at` (unix seconds), `kind`, `outcome` (`success`, `failure`, `info`), `reason`, `user_id`, `session_id`, `app_id`, `provider_id`, `client_ip`, `ua_sha256`, `ua_prefix`, `request_id`, `attrs`. Lines carry identifiers and reason codes only; no cookie, handle, code, token, secret or full email address is written. To separate the two streams, filter on lines that start with `{"`.

Event kinds: `login.started`, `login.succeeded`, `login.failed`,
`session.created`, `session.handoff`, `handoff.rejected`, `session.terminated`,
`handle.revoked`, `identity.linked`, `identity.conflict`, `csrf.rejected`,
`config.loaded`, `admin.providers_import`, `verify.denied`, `provider.error`,
`txn.evicted`, `events.dropped`, `sink.backlog_overflow`, and the console's
`admin.grant`, `admin.revoke`, `admin.user_disable`, `admin.user_enable`,
`admin.session_terminate`, `admin.sessions_terminate`, `admin.denied`. State-changing kinds
are written to the database in the same transaction as the change they
describe and then delivered to the log sink at least once (a line can repeat
after a crash; `event_id` identifies it). `verify.denied`, `provider.error`,
`txn.evicted`, `events.dropped` and `sink.backlog_overflow` are diagnostics:
best effort, sampled under load, and summarized by `events.dropped` when
dropped. Allowed verify calls are not logged unless `log.verify_allow` is `true`.

Events are pruned by age (`events.retention_days`) and count
(`events.max_rows`); delivery rows have their own retention
(`events.delivery_terminal_retention_days`) and pending backlog cap
(`events.max_pending_per_sink`). Terminated sessions and their handles are
swept hourly after `sessions.retention_days`.

Every portal response carries an `x-request-id` (the same value appears as
`request_id` in the events of that request); quote it when correlating a user
report with the log. Verify answers carry `x-hopae-reason` and `x-hopae-contract`
instead.

### `/healthz`

`GET /healthz` on the portal listener (and, through the gateway's portal route,
on the portal host) returns `200` with a JSON body whenever the process is
serving requests:

```json
{"status":"ok","ready":true,"store":"ok","providers":{"google":"ok"},"insecure_mode":false,"unauthenticated_caller":false}
```

- `ready` is `true` only after start-up finished and the primary store answered a query just now. `store` is `ok` or `unavailable`. The HTTP status stays `200` even when `ready` is `false`: it means "the process is alive and serving", so a supervisor or load balancer that must stop sending traffic to a Hopae with a broken store has to read the body, not the status.
- `providers` maps each provider id to `ok`, `degraded` (discovery or key fetch has failed; retried with backoff) or `disabled` (turned off, deleted or missing its secret).
- `insecure_mode` is `true` when `cookie.secure` is `false`; `unauthenticated_caller` is `true` when `gateway.allow_unauthenticated_caller` is `true`. Either being `true` in production is a misconfiguration.
- The body holds no secret and no user data. The endpoint is on the portal listener, so it is as public as the portal route; the gateway listener has no health endpoint.

Use `hopae --check` for configuration questions and `/healthz` for run-time
state; neither proves the gateway route is registered correctly. The reliable
end-to-end check is a browser login on a protected host.

### Counters

`GET /metrics` on the admin listener serves every counter below and the
families in the next table in the OpenMetrics text format
(`application/openmetrics-text; version=1.0.0`, ending in `# EOF`). Scrape it
on the admin listener (`listen.admin`, default `127.0.0.1:8702`; 8702 in the
Kubernetes package too, where 8703 is the gRPC gateway) over its mutual TLS
(`listen.admin_tls`). Use one of these credentials:

- a route-scoped service credential created with `--preset metrics`, which
  can read only `GET /metrics` (see [service credentials](SERVICE_CREDENTIALS.md)), or
- an administrator of any role.

The endpoint writes no audit record. It contacts no provider and no gateway.
It reads the store with the console's query budget; if the store doesn't
answer, `hopae_store_up` is `0` and the process-wide series are still served.

No label carries a subject, a user id, an email or an address. Label values
come from bounded sets: reason codes, configured provider and service ids,
and fixed surface, factor and profile names. Recording on the verify, gRPC
and event paths is an atomic increment into a fixed-capacity table. It takes
no lock and allocates nothing once a series exists
(`tests/metrics_no_alloc.rs`). A full table counts into
`hopae_metrics_series_overflow_total` instead of growing.

A Prometheus Operator endpoint (the token is the `hsc1.` credential; the
client certificate is the one bound to it):

```yaml
endpoints:
  - port: admin
    scheme: https
    path: /metrics
    bearerTokenSecret: {name: hopae-metrics, key: token}
    tlsConfig:
      ca: {secret: {name: hopae-admin-tls, key: ca.crt}}
      cert: {secret: {name: hopae-scrape-client, key: tls.crt}}
      keySecret: {name: hopae-scrape-client, key: tls.key}
      serverName: hopae-admin.example.test
```

A ServiceMonitor can't set request headers, so for `GET /metrics` alone the
`x-hopae-audience` header may be left out. The audience then defaults to this
instance's `admin.service_audience`, and the credential must allow it (the
CLI default). The certificate binding and the secret still apply.

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `hopae_auth_outcomes_total` | counter | `surface` (`forward_auth`, `hop1`, `grpc`), `provider` (on allow, else `none`), `outcome` (`allow`, `login`, `deny`, `handoff`, `redirect`, `switch`, `clean_redirect`), `reason` | Every authentication decision |
| `hopae_verify_duration_seconds` | histogram | `surface` | Decision latency (gRPC: the whole call) |
| `hopae_grpc_requests_total` | counter | `profile` (`verify`, `service_receipt`, `workload_receipt`, `human_receipt`, `projection_plan`, `service_projection`, `workload_projection`, `human_projection`, `other`), `code` (gRPC status name) | gRPC calls |
| `hopae_logins_total` | counter | `provider`, `outcome`, `reason` | Portal logins (`login.succeeded`, `login.failed`) |
| `hopae_sessions_created_total` | counter | `provider` | Sessions created |
| `hopae_sessions_revoked_total` | counter | `reason` | Sessions ended before expiry (logout, termination, revocation) |
| `hopae_handles_revoked_total` | counter | `reason` | Application handles revoked |
| `hopae_sessions_active` | gauge | — | Live sessions |
| `hopae_stepup_results_total` | counter | `factor` (`totp`, `webauthn`, `external`, `recovery_code`), `outcome` | Second-factor checks (step-up and login MFA) |
| `hopae_passkey_ceremonies_total` | counter | `ceremony` (`register`, `authenticate`, `revoke`), `outcome` (`success`, `failure`, `clone_suspected`) | Passkey ceremonies |
| `hopae_rate_limited_total` | counter | `surface` (`verify`, `login`, `settings`, `service_credential`) | Requests refused by a rate limit |
| `hopae_store_failures_total` | counter | `kind` (`busy`, `queue_full`, `conflict`, `other`) | SQLite failures (`busy` = locked past the busy timeout) |
| `hopae_store_up` | gauge | — | `1` when the store answered the scrape's status read |
| `hopae_users`, `hopae_event_rows` | gauge | — | Users; retained event rows |
| `hopae_event_relay_backlog` | gauge | `sink`, `state` (`pending`, `failed`) | Event deliveries waiting or given up |
| `hopae_projection_feed_rows` | gauge | — | Rows of the group projection change feed |
| `hopae_lifecycle_feed_head` | gauge | `source` (`ledger`, `outbox`) | Head positions of the subject lifecycle feed |
| `hopae_workload_principals` | gauge | — | Workload principals in the store |
| `hopae_workload_jwks_last_success_timestamp_seconds` | gauge | `service` | Last successful signing-key fetch (staleness = `time()` minus it) |
| `hopae_provider_state` | gauge | `provider`, `kind`, `state` (`ok`, `degraded`, `disabled`) | `1` for each provider's current state |
| `hopae_config_generation` | gauge | — | Configuration snapshot generation |
| `hopae_tls_leaf_expiry_seconds` | gauge | `name` | Seconds until the leaf certificate in use expires |
| `hopae_authentication_gateway_available`, `hopae_authentication_profiles_revision` | gauge | — | Authentication profiles in force |
| `hopae_events_last_prune_timestamp_seconds` | gauge | — | Last event prune |
| `hopae_metrics_series_overflow_total` | counter | — | Recordings dropped because a family was full |

Event-derived families (logins, sessions, factors, passkeys) count event rows
as they are written. A transaction that rolls back after the write is still
counted, which is rare.

The older counters keep their names and are exposed as they are
(`*_total` as counters, the rest as gauges):

| Counter | Labels | Counts |
| --- | --- | --- |
| `hopae_verify_decisions_total` | `decision`, `reason` | Every verify decision by outcome |
| `hopae_verify_denied_total` | `reason` | Every verify denial, counted before sampling |
| `hopae_verify_unauthorized_total` | none | Verify calls with a missing or wrong caller key |
| `hopae_verify_caller_key_total` | `slot` (`current`, `next`) | Verify calls authenticated by each configured key |
| `hopae_verify_overloaded_total` | none | Verify calls refused because `limits.gateway_max_concurrent` was exhausted |
| `hopae_verify_canonical_mismatch_total` | none | Verify calls whose canonical path disagreed with the gateway's |
| `hopae_store_errors_total` | none | Store failures on the verify path (`store_unavailable`) |
| `hopae_store_interrupts_total` | none | Store jobs interrupted inside SQLite at their deadline |
| `hopae_admin_requests_total` | `role`, `outcome` (`insecure_mode="true"` is added when `cookie.secure` is `false`) | Requests answered by the admin listener |
| `hopae_admin_denied_total` | `reason` | Console refusals (`untrusted_peer`, `login_required`, `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`, `actor_revoked`, `overloaded`) |
| `hopae_admin_mutations_total` | `kind` | Console mutations that changed something (`user_disable`, `user_enable`, `sessions_terminate`, `session_terminate`) |
| `hopae_admin_rows_examined_total` | `list` (`users`, `sessions`, `events`) | Candidate rows examined by console listings |
| `hopae_admin_grants_imported_total` | `outcome` | Grants applied by the import at start (`inserted`, `updated`, `revoked`, `unchanged`, `skipped`) |
| `hopae_events_total` | `kind`, `outcome` | Events recorded |
| `hopae_events_dropped_total` | `kind` | Diagnostic events dropped before reaching the store |
| `hopae_events_pruned_total` | none | Event rows removed by pruning |
| `hopae_event_deliveries_delivered_total` | `sink` | Deliveries completed |
| `hopae_event_deliveries_failed_total` | `sink`, `reason` | Deliveries given up (`retries_exhausted`, `backlog_overflow`, `pruned`) |
| `hopae_build_info` | `version` | Gauge, always `1` |
| `hopae_config_loaded_timestamp` | none | Gauge, unix seconds of the last configuration load |
| `hopae_tls_reloads_total` | `name` (`admin`, `native_gateway`, `grpc_gateway`, `projection_authority`, `provider:<id>`, `provider:<id>:client_assertion`), `result` (`reloaded`, `invalid`) | TLS material changes found by the poller |
| `hopae_tls_reload_failing` | `name` | Gauge, `1` while the newest material of `name` is invalid and the previous one is still served |
| `hopae_provider_tls_trust` | `provider`, `source` (`ca_file`, `system`) | Gauge, `1` for the trust source an OIDC provider's client uses |
| `hopae_config_reloads_total` | `result` (`reconciled`, `invalid`, `restart_required`) | Changes of the configuration file seen in `authentication.source = config` |
| `hopae_config_reload_failing` | none | Gauge, `1` while the newest configuration file is invalid and the previous profiles stay in force |

### Failure behavior

Verify fails closed: any condition Hopae cannot resolve is a denial, never an
allow, and the gateway turns anything it does not understand into `503`. The
reasons below appear in `verify.denied` events and `x-hopae-reason`.

| Condition | What clients see | What to look at |
| --- | --- | --- |
| Hopae down or unreachable | The gateway times out and answers `503` | Supervisor, process log, `exit` status; fix and restart |
| Store unavailable or database error | Verify `503` (`store_unavailable`); portal pages `503`; `/healthz` `ready:false`, `store:"unavailable"` | Disk full, permissions, a damaged file; process log errors; `hopae_store_errors_total` |
| Verify budget exceeded (`gateway.verify_budget_ms`) | Denied with `budget_exceeded` | Slow disk or contention; raise the budget only below the route's `auth.timeout_ms` |
| Concurrency cap reached | `503` (`overloaded`) at once | `limits.*_max_concurrent`; a flood is bounded, not queued |
| Wrong or missing caller key | `403` (`caller_unauthorized`) on every verify | Key in the route versus `caller_key_env`; rotation state |
| Gateway sends a malformed or unsupported contract | `400` or `403` (`contract_violation`, `contract_unsupported`, `path_not_canonical`, `wrong_listener`) mapped to `503` by the gateway | The route's `auth` fragment against `hopae --check` output |
| Identity provider unreachable or slow | Logins for that provider fail with a retry page (`provider_unavailable`); verify and existing sessions are unaffected | `provider.error` events, `/healthz` provider state |
| Unknown host or disabled application | Denied (`unknown_app`, `app_disabled`) | `apps[]` hosts and ports; `hopae --check` return origins |
| Clock skew beyond 60 seconds | Sessions look expired or ID tokens fail (`clock_skew`) | Time synchronization on the host |
| Second instance on one state directory | Start refused, exit `2` | Stop the other instance |
| Admin listener address already in use or equal to another listener | Start fails (exit `1` for a bind failure, `2` for `listen.admin` equal to the portal or gateway address) before any listener answers | `listen.admin`; `hopae --check` |
| Console store operation too slow or the store busy | The console answers `503 store_unavailable`; the change is rolled back; verify on the gateway listener is unaffected | `admin.query_budget_ms`, `hopae_store_interrupts_total`, process log |
| Database refused by the precheck (newer, pre-release, damaged) | Start (and every `hopae admin` command) refused, exit `2`; no backup, no migration | The error message; restore a copy |
| Event delivery failing | No effect on logins; rows retry, then become `failed`; a full backlog marks the oldest `failed` (`backlog_overflow`) | `sink.backlog_overflow`, `hopae_event_deliveries_failed_total` |
| Crash or power loss mid-write | The database recovers from the WAL at next start; at-most the last in-flight transaction is lost, and a login in progress must be repeated | Process log at start |

Operator-visible effects common to all failures: a reason code in the log, a
counter per reason where counters exist, and no secret in any message.

## Limitations and compatibility

- Single instance per state directory; no failover. Restart is fast and sessions persist across it. Multi-instance deployments need the M2 store.
- No hot reload of configuration, provider secrets or caller keys before M6; every change is a restart, during which verify fails closed (the gateway answers `503`) for the restart's duration.
- Metrics are exposed on the admin listener only (`GET /metrics`, mTLS plus an administrator or a `metrics` service credential); there is no unauthenticated metrics port. The management console (M4-min) reads and ends users and sessions; providers, applications and blacklists are managed from the configuration file, `hopae providers import` and `hopae admin`.
- Backups are file copies of a stopped (or checkpointed) database. An online backup tool is M7.
- Hopae does not terminate TLS and does not talk to the internet except to the configured identity providers (discovery, keys, token and user-info endpoints); there is no telemetry and no self-update before M6. Provider traffic ignores `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`: a proxy resolves the destination itself, which would bypass the connect-time address checks. There is no proxy option.

## Examples, verification and related pages

The deployment template (`deploy/compose.yaml`, `deploy/hopae.example.json`,
`deploy/env.example`, `deploy/hangang-routes.example.json`, the last with the
`hopae-admin` console route) shows a hardened
container: a read-only root file system, all capabilities dropped,
`no-new-privileges`, memory and process limits, rotated JSON logs, a private
state volume and host networking so that the loopback listeners are shared
with the gateway and nothing else. See `deploy/README.md` for the steps.

Verify a deployment:

```sh
hopae --version
hopae --check --config /etc/hopae/hopae.json && echo ok
curl -fsS http://127.0.0.1:8700/healthz        # ready:true, store:"ok"
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8701/_hopae/verify'        # 403 without the caller key
```

Related pages: [configuration reference](CONFIG.md), [gateway contract](GATEWAY_CONTRACT.md), [architecture](ARCHITECTURE.md) (behavior under failure), [threat model](THREAT_MODEL.md).
