# Operations

<!-- doc-rev: 2 -->

[Documentation](README.md) · [한국어](ko/OPERATIONS.md)

How to run, observe, maintain and recover a Hopae instance in milestone M1.
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

## Behavior

### Running Hopae

```sh
hopae --check --config /etc/hopae/hopae.json     # validate; print the route fragment; exit 0 or 2
hopae run     --config /etc/hopae/hopae.json     # serve (alias: serve; the default command)
```

Always run `--check` first and after every configuration change, with the same
environment the service will have. On success `run` prints three stable lines
on stdout and then serves:

```text
portal listening on 127.0.0.1:8700
gateway listening on 127.0.0.1:8701
```

Start order is fixed: instance lock, backup of an older database, store opened
and migrated, providers imported and applications mirrored (with the
`config.loaded` event in the same transaction), portal listener bound, gateway
listener bound last, ready. A failure at any step exits before a listener
answers a request.

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
| `hopae.db.bak-v<N>` | Backup written before a migration | See below. |

The database file is created with a restrictive mode before SQLite writes to
it. Provider client secrets and caller keys are not stored in the state
directory: they live only in the environment.

### The instance lock

At start Hopae takes an exclusive advisory lock on `<state_dir>/hopae.lock` and
holds it for the life of the process. A second `hopae run` on the same state
directory fails immediately with `store locked by another instance` and exit
`2`, before the database is touched. The operating system drops the lock when
the process exits or crashes, so there is no stale lock to clean up and the
file itself is safe to leave in place. `hopae --check` and `hopae providers
import` do not take the lock.

In a container, the lock is only effective if both instances see the same
state volume; do not run a second container "to try a new image" against the
live volume. Stop the old one first.

### Upgrade and migration backups

Schema migrations are embedded in the binary and applied at start, forward
only, each in its own transaction. Before applying any migration to an
existing database that is older than the binary, Hopae writes a consistent
copy next to it as `hopae.db.bak-v<N>`, where `<N>` is the schema version found
(mode `0600`, written with `VACUUM INTO`, so WAL content is included). No
backup is made for a new, empty or already current database. An existing
backup of the same version is replaced. A database written by a newer binary is
refused (the start fails). So is a database of schema version 2 written by a
pre-release development build, recognizable by a missing
`sessions.authz_version_at_auth` column or `users_primary_email` index: the
start fails with exit status 2 and the message "development database from a
pre-release schema; delete it". Before the first release schema version 2 was
edited in place, so such a database cannot be upgraded; delete it.

Upgrade procedure:

1. Run the new binary's `hopae --check` against the current configuration.
2. Stop the running instance (`SIGTERM`) so the database is checkpointed.
3. Copy the state directory (or at least `hopae.db`) somewhere safe. The automatic backup covers a failed migration; it does not replace this copy, which also protects against a bad release.
4. Start the new binary. Read the log for `database backup written before migration` and `store ready: ... (schema vN)`.
5. Keep the previous image or binary until the new one has served real traffic.

Rollback: stop Hopae, restore the saved copy (or the `.bak-v<N>` file) over
`hopae.db`, remove any `hopae.db-wal` and `hopae.db-shm` left beside it, and
start the previous binary. Sessions created after the backup are lost; users
sign in again.

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
`txn.evicted`, `events.dropped`, `sink.backlog_overflow`. State-changing kinds
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

Hopae keeps in-process counters. In M1 there is **no production exposition**:
the values are readable only through the loopback test-hooks listener of a
`test-hooks` build, which must never run in production. Prometheus text
exposition is M7. Until then, watch the event stream (`verify.denied` lines
carry the reason) and the gateway's own counters (`503` and `403` rates on
protected routes). The counter names, fixed for the later exposition:

| Counter | Labels | Counts |
| --- | --- | --- |
| `hopae_verify_decisions_total` | `decision`, `reason` | Every verify decision by outcome |
| `hopae_verify_denied_total` | `reason` | Every verify denial, counted before sampling |
| `hopae_verify_unauthorized_total` | none | Verify calls with a missing or wrong caller key |
| `hopae_verify_caller_key_total` | `slot` (`current`, `next`) | Verify calls authenticated by each configured key |
| `hopae_verify_overloaded_total` | none | Verify calls refused because `limits.gateway_max_concurrent` was exhausted |
| `hopae_verify_canonical_mismatch_total` | none | Verify calls whose canonical path disagreed with the gateway's |
| `hopae_store_errors_total` | none | Store failures on the verify path (`store_unavailable`) |
| `hopae_events_total` | `kind`, `outcome` | Events recorded |
| `hopae_events_dropped_total` | `kind` | Diagnostic events dropped before reaching the store |
| `hopae_events_pruned_total` | none | Event rows removed by pruning |
| `hopae_event_deliveries_delivered_total` | `sink` | Deliveries completed |
| `hopae_event_deliveries_failed_total` | `sink`, `reason` | Deliveries given up (`retries_exhausted`, `backlog_overflow`, `pruned`) |
| `hopae_build_info` | `version` | Gauge, always `1` |
| `hopae_config_loaded_timestamp` | none | Gauge, unix seconds of the last configuration load |

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
| Event delivery failing | No effect on logins; rows retry, then become `failed`; a full backlog marks the oldest `failed` (`backlog_overflow`) | `sink.backlog_overflow`, `hopae_event_deliveries_failed_total` |
| Crash or power loss mid-write | The database recovers from the WAL at next start; at-most the last in-flight transaction is lost, and a login in progress must be repeated | Process log at start |

Operator-visible effects common to all failures: a reason code in the log, a
counter per reason where counters exist, and no secret in any message.

## Limitations and compatibility

- Single instance per state directory; no failover. Restart is fast and sessions persist across it. Multi-instance deployments need the M2 store.
- No hot reload of configuration, provider secrets or caller keys before M6; every change is a restart, during which verify fails closed (the gateway answers `503`) for the restart's duration.
- No metrics endpoint before M7; counters are in-process only. There is no management API or console before M4; the supported management surface is the configuration file and `hopae providers import`.
- Backups are file copies of a stopped (or checkpointed) database. An online backup tool is M7.
- Hopae does not terminate TLS and does not talk to the internet except to the configured identity providers (discovery, keys, token and user-info endpoints); there is no telemetry and no self-update before M6. Provider traffic ignores `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`: a proxy resolves the destination itself, which would bypass the connect-time address checks. There is no proxy option.

## Examples, verification and related pages

The deployment template (`deploy/compose.yaml`, `deploy/hopae.example.json`,
`deploy/env.example`, `deploy/hangang-routes.example.json`) shows a hardened
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
