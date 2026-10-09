# ADR-0014: Handoff recovery depth applies to every rejection of a known code, and codes carry the transaction's client IP

- Status: Proposed
- Date: 2026-10-09
- Deciders: designer, orchestrator
- Scenarios: 003 (A13, 9), 002 (7)
- Threat model: TM-31
- Supersedes: none (amends the recovery rule of [ADR-0004](0004-session-model-and-cross-domain-handoff.md); ADR-0004 stays Accepted and links here)

## Context

- [ADR-0004](0004-session-model-and-cross-domain-handoff.md) bounds binding-race recovery by `recovery_depth`, carried on every handoff code and incremented when a code is rejected with `bind_mismatch` while the browser holds no valid handle. Other rejections of a known code answer the same unauthenticated `302` but at depth 0.
- During W1 integration the session implementer showed a deterministic loop outside `bind_mismatch`: when the portal and the application host observe different client IPs for one browser (dual-stack addressing, or two proxy paths), a code minted with the portal-observed IP is rejected on the application host for the IP check, the recovery transaction is created at depth 0, the portal mints another code with the same IP, and so on; only the per-IP failure cap stops it, with the user stuck.
- Two defects compound: the code's IP was taken from the portal request rather than from the transaction that the application-host verify created, and depth provenance stopped at one reason.

## Decision

1. `handoff_codes.client_ip` is copied from the **login transaction's** `client_ip` (recorded by the application-host verify call that started the login), never from the portal request that mints the code. Single sign-on and retry transactions are application-host transactions too, so the rule has no exception.
2. The recovery rule of ADR-0004 applies to **every rejection of a known code** on a document navigation while the browser holds no valid handle for that host — `bind_mismatch`, `code_ip_mismatch`, `code_host_mismatch`, `code_path_mismatch`, `code_stale_generation`, `code_expired`, `code_consumed` — not only to `bind_mismatch`: the burned code's `recovery_depth` is the provenance, the new transaction takes `recovery_depth + 1`, and a burned code whose depth already equals `handoff.max_recoveries` answers the relayed `403 handoff_recovery_exhausted` with no transaction created. An **unknown** code (no row) starts a transaction at depth 0 and is bounded by `handoff.per_ip_failures_per_minute`; it cannot loop deterministically because Hopae never mints an unknown code.
3. `code_ip_mismatch` is added to the contract's list of `handoff.rejected` reasons; the IP compared is the one the gateway reports for the redeeming request.

## Consequences

### Positive

- No deterministic redirect loop exists for any rejection reason; the bound is one number for all of them.
- Dual-stack and multi-proxy deployments work without special configuration.

### Negative

- A replayed consumed code from a browser without a handle (scenario 003-A1) now inherits the consumed code's depth; a browser that keeps replaying old codes reaches the exhaustion page sooner, which is the intended bound.

### Neutral

- Scenario 003-A13 states the generalization; 003-9 is unchanged.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Keep depth on `bind_mismatch` only and rely on the per-IP failure cap | The cap is a rate limit, not a loop breaker; the user sees ten redirects and then a rate-limit page without explanation. |
| Drop the IP check from redemption | Removes a cheap binding signal that stops a stolen code from another network; the correct fix is to compare like with like (application-host IP both times). |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending: a short confirmation pass alongside G7 of the W1 integration. |

## References

- [ADR-0004](0004-session-model-and-cross-domain-handoff.md), [gateway contract — cross-domain handoff](../GATEWAY_CONTRACT.md#cross-domain-handoff).

## 한국어 요약

핸드오프 코드의 클라이언트 IP는 포털 요청이 아니라 로그인을 시작한 애플리케이션
호스트 verify의 트랜잭션에서 복사합니다. 복구 깊이 규칙은 `bind_mismatch`뿐
아니라 알려진 코드가 거부되는 모든 사유에 적용되어, 어떤 사유로도 결정적인
리디렉션 루프가 생기지 않습니다. 알 수 없는 코드는 깊이 0에서 시작하고 IP별 실패
상한으로만 제한됩니다.
