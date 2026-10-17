# ADR-0023: Risk-based step-up from gateway network evidence

- Status: Proposed
- Date: 2026-10-17
- Deciders: designer, orchestrator (maintainer decision pending)
- Scenarios: 495
- Threat model: TM-79, TM-80
- Supersedes: none
- Related: [ADR-0008](0008-second-factor-extension-point.md), [ADR-0013](0013-gateway-adapter-boundary.md), [ADR-0018](0018-aal3-emission.md); Sumunjang `NetworkEvidence` (gRPC), Hangang decision events (`hangang.decision.v1`)

## Context

- Hopae decides a request from the session alone: lifetimes, binding,
  user status and the application's static step-up rules. It knows the
  client address, but nothing about the network the request comes from.
- Hangang already asks Sumunjang about every request before it asks Hopae.
  Sumunjang returns network evidence: a verdict and its stage, a reason
  code, the ASN, the country, the network zones that matched, the mode
  (`enforce` or `observe`) and the policy revision. Hangang records these in
  its decision events, but Hopae never sees them.
- Products that compete here (adaptive MFA, access policies with device or
  network posture) require a stronger or fresher factor when the context is
  risky, such as a reputation hit, an unusual country or a change of network
  in the middle of a session, and deny outright when the risk is high.
- Hopae must not trust anything the browser sent. The verify channel
  authenticates the gateway (the caller key, HOP1 or gRPC mTLS), but a
  gateway that relays an unexpected client header, or a stale value, must
  not be able to turn that header into a decision.

## Decision

1. **A signed, bounded risk context on verify.** With `risk` configured, the
   gateway sends one header on the verify call, `x-hopae-risk-context`,
   over HTTP or HOP1. The value is
   `v1.<base64url(JSON claims)>.<base64url(HMAC-SHA256)>`; the encoding has
   no padding and the whole value is at most 1,024 bytes.
   - **Claims.** Unknown claims are refused.
     - `iat`: unix seconds.
     - `level`: `low`, `elevated` or `high`.
     - `source`: `sumunjang`.
     - `mode`: `enforce` or `observe`.
     - `reason`: at most 64 bytes of `[a-z0-9._-]`.
     - Optional `score`: 0 to 100.
     - Optional `asn`: a u32.
     - Optional `country`: ISO 3166-1 alpha-2 upper case, or `XX` for unknown.
     - Optional `zones`: up to 8 ids of `[a-z0-9._-]{1,64}`.
     - Optional `rev`: the Sumunjang revision, a u64.
   - **MAC.** The MAC is computed over
     `"hopae-risk-context.v1\n" + <payload> + "\n" + <method> + "\n" + <client ip> + "\n" + <x-original-url>`,
     using the exact values of that verify request. A context therefore
     cannot be moved to another request, method, URL or client.
   - **Keys.** The key is dedicated: `risk.context_key_env`, plus optional
     `risk.context_key_next_env` for rotation. It is 32 to 4,096 bytes and is
     never the caller key.
   - **Freshness.** `|now − iat|` must be at most `risk.max_skew_secs`
     (default 30).
2. **Refusal of anything else.**
   - A present but invalid context is refused with
     `403 risk_context_invalid` for an application with a risk policy. That
     covers a malformed or oversized value, a duplicate header, an unknown
     claim, a bad MAC, a mismatched binding and a stale `iat`. A gateway that
     holds the key never sends one, so it is either tampering or a broken
     gateway.
   - Applications without a risk policy ignore the header. A gateway's
     problem must not take down every application.
   - An **absent** context follows the application's `risk.missing`:
     `ignore` (the default), `deny`, or a step-up.
3. **Per-application risk rules, in the step-up engine.** `apps[].risk.rules`
   is a list of rules.
   - **Conditions.** Each rule has a `when` with one or more of the
     following conditions, all of which must hold. A rule may also have a
     `path_prefix`.
     - `level_at_least`
     - `country_in`, `country_not_in`
     - `zone_in`, `outside_zones` (none of the listed zones matched)
     - `reason_in`
     - `country_changed`, `asn_changed` (compared with this session's last
       allowed request)
     - `new_country` (not among the user's countries seen within the TTL)
   - **Actions.** `then` is `deny` or `{"step_up": {"aal": 2|3,
     "max_age_secs": N}}`. `max_age_secs` is required: a risk step-up always
     asks for a fresh factor. Without freshness, an AAL 2 session would
     satisfy the rule at once.
   - **Evaluation.**
     - A matching step-up rule becomes an ordinary step-up rule for this
       request. It is evaluated with the application's static rules by the
       same engine (ADR-0008, ADR-0018), so the portal flow, the `401` and
       the `302` are unchanged.
     - `deny` answers `403 risk_denied`.
     - Rules that need no session (`level`, country, zone, reason) are
       evaluated before authentication too, so a high risk is refused before
       a sign-in starts.
4. **Session memory, bounded and coarse.** After an allowed request, Hopae
   keeps two in-process stores:
   - **Per session:** the country and ASN, with a TTL of
     `risk.memory.session_ttl_secs` (default 1 day) and at most
     `max_sessions` entries.
   - **Per user:** the countries seen, at most `countries_per_user`, with a
     TTL of `user_ttl_secs` (default 30 days) and at most `max_users` users.

   No address, zone or score is kept. Both stores evict the oldest entry.
   They are per process, so a restart or another replica starts empty:
   `*_changed` and `new_country` are then false, and only a newly seen
   difference triggers them.
5. **Visibility.**
   - `explain/authentication` accepts a hypothetical `risk` input and answers
     a `risk` section: the inputs, the matched rules and the action. Its
     trace has `risk_*` checks.
   - Events:
     - `risk.step_up_required` (diagnostic) carries the level, reason,
       country, ASN and rule index.
     - Denials are `verify.denied` with `risk_denied`,
       `risk_context_invalid` or `risk_context_missing`.
   - Metrics:
     - `hopae_risk_decisions_total{app,level,action}`
     - `hopae_risk_context_invalid_total{reason}`
     - `hopae_risk_memory_entries{store}`

## Consequences

### Positive

- An operator can require a fresh passkey or TOTP for risky traffic, and
  deny clearly high risk, per application and per path, without a new
  gateway decision model.
- The decision stays in Hopae's step-up engine, so explain, the portal and
  the events behave as for static rules.

### Negative

- The gateway must compute an HMAC per verify, and both sides must be
  provisioned with a shared key. The key is symmetric because both ends are
  operated together and the verifier gains nothing by forging its own input.
- Session memory is per process. With several replicas a change of country
  can go unnoticed until the same replica serves the session again. Sticky
  routing or a future shared store improves this.

### Neutral

- Without `risk`, nothing changes: the header is not read.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Trust plain headers (`x-hangang-risk-level`) from the authenticated caller | A gateway that relays a client header by mistake would hand the decision to the client; the MAC with the request binding removes that class. |
| Ed25519-signed context | Verify is the hottest path; HMAC is cheaper and the gateway, not Hopae, is the only party that should produce contexts. Hopae holding the key gains nothing. |
| Query Sumunjang from Hopae | A second network call per verify, a second view of the client address, and Sumunjang would see identity traffic; the gateway already has the evidence. |
| Persist session memory in the store | A write on every allowed verify; the coarse, best-effort signal does not justify it in this slice. |

## Adversarial review

| Pass | Date | S1 | S2 | S3 | S4 | Outcome |
| --- | --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — | Pending: reviewed with the Hangang side of the contract. |

## References

- [ADR-0008](0008-second-factor-extension-point.md), [ADR-0018](0018-aal3-emission.md), [Gateway contract](../GATEWAY_CONTRACT.md#risk-context), [Configuration](../CONFIG.md#risk-based-step-up), [Authentication explain](../AUTHENTICATION_EXPLAIN.md)

## 한국어 요약

Hangang은 요청마다 Sumunjang 네트워크 증거를 받습니다. Hopae는 `risk`가 설정되면
verify 요청의 `x-hopae-risk-context`에서 그 증거를 받습니다. 값은 수준, 사유, ASN, 국가,
영역, 모드를 담은 JSON이고, 전용 키로 만든 HMAC-SHA256으로 서명되며, 메서드·클라이언트
주소·원래 URL에 묶입니다. 위변조되었거나 오래된 컨텍스트는 위험 정책이 있는 애플리케이션에서
`403 risk_context_invalid`로 거부합니다. 애플리케이션별 위험 규칙(`apps[].risk.rules`)은
일치하면 신선도가 붙은 단계 상승 규칙을 더하거나(같은 단계 상승 엔진에서 평가) 요청을
거부합니다(`risk_denied`). 세션별 국가·ASN과 사용자별 국가는 TTL과 개수 제한이 있는
프로세스 메모리에 거친 값만 둡니다. explain, 이벤트(`risk.step_up_required`), 지표로
입력과 결정을 확인할 수 있습니다.
