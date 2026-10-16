# S320 — Live reload: renewed TLS material and configuration-authoritative revocations take effect without a restart

<!-- scenario-status: draft -->

- Area: management
- Milestone: M4
- ADRs: 0016; Hangang ADR 0022 (Kubernetes-native package)
- Threat model: TM-45
- Gateway contract: n/a

## Goal

A cert-manager renewal of the secret mounted for the mTLS listeners is served
to new handshakes on every listener without a restart, and a ConfigMap change
that revokes a service credential in `authentication.source = config` stops
it within two seconds of the file changing, without a rollout; invalid
material or files change nothing and are visible.

## Preconditions and fixtures

- S320-1: `m4-admin` with `listen.admin_tls`, `listen.native_gateway_tls`, a native gateway and a gRPC gateway on loopback, all pointing at `tls.crt`/`tls.key` (server certificate A) and `ca.pem`; `reload.tls_interval_secs = 1`; a client certificate from the same CA; server certificate B from the same CA.
- S320-2: `m4-admin` with the subject-directory API profile (`api`, API keys `worker` and `retired`), `authentication.source = config`, `authentication.reload_interval_ms = 200`; an administrator.

## Main flow

### S320-1 Renewed TLS material on every listener

- Given: each listener answers a handshake with certificate A.
- When: B's certificate and key replace the files (write, then rename); later a key that does not match B replaces the key file; then B's key returns.
- Then: within five seconds each listener (administrator `http/1.1`, native `hop1`, gRPC `h2`) presents B, and `hopae_tls_reloads_total{name,result="reloaded"}` is 1 for each; the mismatched key raises `hopae_tls_reload_failing{name="admin"}` to 1 while every listener still presents B; restoring the key clears it.

### S320-2 A revoked key stops within two seconds

- Given: `worker`'s key authenticates (`200`).
- When: the file drops `worker`'s key; later the file becomes invalid (a port that is a string); then it is fixed and restores the key; then an unrelated key (`log.level`) changes.
- Then: verify refuses `worker` (`401`) within two seconds, on the same listeners (no restart); status shows profiles revision 2, not failing; `authentication.reconciled` records `cause: reload`, revision 2, actor `config`; the invalid file sets `reload.config.failing` with an error while revision 2 stays in force; the fix publishes revision 3, `worker` is accepted again and the failure clears; the unrelated change sets `restart_required` and is not applied.

## Abuse cases

| Category | Case | Applies |
| --- | --- | --- |
| Replay | — | no |
| Tampering | S320-1, S320-2 | yes: half-written or invalid material is never applied |
| Race / timing | S320-1 | yes: a rename-based update is read whole; a missing file mid-rotation is retried |
| Resource exhaustion | — | covered by unit tests: files are bounded to 1 MiB, polls run on the blocking pool |
| Confused deputy | — | no: only operator-mounted files are read |
| Spoofed or duplicated headers | — | no |
| Downgrade | S320-1 | yes: an invalid set never replaces a valid one |
| Enumeration | — | no |

## Observability expectations

- Log: `TLS material reloaded` with `name` and `fingerprint`; warnings for invalid material and files; `configuration reconciled live`.
- Metrics: `hopae_tls_reloads_total`, `hopae_tls_reload_failing`, `hopae_config_reloads_total`, `hopae_config_reload_failing`.
- Status: `GET /v1/status` → `reload.tls[]`, `reload.config`.
- Audit: `authentication.reconciled` with `cause: reload`.

## Test mapping

| Case | Test | File | Kind | Status |
| --- | --- | --- | --- | --- |
| S320-1 | `s320_1_renewed_tls_material_is_served_by_every_listener_without_a_restart` | `tests/scenarios/s320_live_reload.rs` | integration | passing |
| S320-2 | `s320_2_a_revoked_key_stops_authenticating_within_two_seconds_without_a_restart` | `tests/scenarios/s320_live_reload.rs` | integration | passing |

## Live verification

| Date | Hopae version | Gateway version | Provider | Environment label | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Not yet run on k3s; the kubelet's ConfigMap propagation delay adds to the two seconds (see the configuration-authoritative page). |

## Open questions

- Should outbound clients also drain established connections on rotation (today the next call uses a new channel; in-flight calls finish on the old one)?

## 한국어 요약

cert-manager가 mTLS 리스너용 시크릿을 갱신하면 재시작 없이 모든 리스너의 새 핸드셰이크에
새 인증서가 쓰이고, `authentication.source = config`에서 ConfigMap이 서비스 자격을
폐기하면 파일이 바뀐 뒤 2초 안에 거부됩니다. 잘못된 자료나 파일은 아무것도 바꾸지 않고
지표와 상태로 드러납니다.
