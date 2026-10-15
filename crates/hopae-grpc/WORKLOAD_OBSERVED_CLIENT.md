# Workload observed SDK client

This additive SDK module is enabled by `native-client`. It uses the dedicated
`WorkloadAuthenticationReceipts` service. Existing `observed_client` Service
validation and endpoint selection remain unchanged. Server activation and a
complete Workload permit/projection/dispatch chain are separate gates.

`workload_observed_client::Client::new_workload` consumes startup-owned
`WorkloadTrustPolicy`, shared `EndpointConfig`/`Limits`, an explicit `ClockRates`
and an actual `ReceiverClock`. The policy pins issuer, signing key/epoch, exact
identity authority, configured service/audience scopes and generation floors.
These public configuration values and prepared requests are metadata, not proof
or permission capabilities. Native owners must retire the old client before
replacing configuration. Linux BOOTTIME is required; unsupported clocks have no
UTC/Instant fallback.

`prepare` binds canonical final HTTP request metadata; `prepare_issue_digest`
binds an already computed immutable final digest. Neither inspects future HTTP
bytes. Native callers own exact final-body/header preparation and downstream
owner, authorization and send-boundary fences. Issue sends verification headers
to the fixed authenticated mTLS peer; raw incoming identity, AAL or generation
claims cannot select the principal class.

`issue` returns an opaque, non-Clone `Observation` only after authenticating the
RPC, its fresh correlation ID, signature and exact context/report binding.
Kind3/AAL0, canonical `s_` plus48 lowercase hex, canonical `wobs1` authority and
nonce, profile/application generations, signing key/epoch, registry generation,
service/audience and final request hash must agree. The32-hex report clock domain
must equal the signed epoch nonce. This schema kind3 does not change the existing
internal stable-subject hashing discriminant. Unknown source epochs and Service
receipts are refused.

An issuance preparation has unresolved source identity. Use the returned
`observation.request()` for `check`; the original preparation never becomes the
resolved signed context by mutation. `prepare_observation` freezes public context
with the exact final digest and configured trust. `observe` still verifies the
signature and queries the fixed owner: preparation alone grants nothing.

Every RPC has an actual receiver clock anchor before transport dispatch.
Source remaining admission is converted with shared `receipt_time` oscillator,
delay and millisecond quantum bounds into a receiver-local lower expiry. Source
absolute ticks are never compared with receiver absolute ticks. Full signed
expiry derives a separate retention upper bound. Remaining admission is not a
cache TTL; nonzero cache_ttl_ms is refused. B's original pre-authentication source
budget is at most1second and cannot renew. Source record miss, retirement,
expiration or a rejected RPC yields `Refused`, without Service/strict fallback.
The SDK intentionally does not expose remote status details as authorization.

`refresh` consumes the old observation and intersects its admission deadline
with the new bound; it may extend retention only to preserve full signed proof
cleanup safety. It cannot lengthen usable admission. A new proof requires new
native authentication. `check` samples current local time, registry floor and
client retirement. Native clock read/reversal/overflow/unsupported/retirement
failures irreversibly retire this client; ordinary single-proof expiration does
not retire unrelated requests. `retention_elapsed` remains separate from
admission, including after client retirement. Neither check nor an authenticated
observation establishes a remote revocation lease, permission or credential.

Tests use an actual local mTLS typed RPC peer and real ReceiverClock for
correlation, owner binding, source restart, scope/class/epoch mismatch,
cancellation, registry advance, retirement and expiration. Independent arithmetic
vectors use controlled numeric clock samples for foreign offsets, delay, rates,
quantization and full signed retention. Runtime's controlled clock backend is
private to its own tests; no injectable public clock/capability constructor was
added. This is SDK qualification, not actual Kubernetes/source/full-chain proof.

## 한국어

`native-client`의 Workload 전용 SDK 모듈을 추가했습니다. 기존 Service API와 검증은
유지합니다. 시작 시 고정한 issuer·키·authority·scope·세대 하한과 실제 mTLS RPC,
kind3/AAL0 및 wobs1/nonce/서명/최종 요청 해시를 모두 확인해야 불투명 관측이 생깁니다.
공개 설정·준비 메타데이터와 숫자 TTL·서명만으로 관측을 만드는 API는 없습니다.

RPC 전에 수신 BOOTTIME을 기록하고 지연·시계 오차·밀리초 양자를 보수적으로 변환합니다.
원천 절대 시각을 수신 절대 시각과 비교하지 않습니다. 원래 인증 시작 기준 최대1초의
예산은 갱신할 수 없고, refresh는 이전 허용 만료와 교집합만 취합니다. 전체 서명 수명의
재생 방지 보존 상한은 별도이며 허용 기간으로 승격하지 않습니다. 원천 레코드가 없거나
퇴역·만료·시계 실패이면 거부하며 Service나 UTC 경로로 fallback하지 않습니다.

설정 교체 전에 기존 클라이언트를 퇴역해야 합니다. 관측은 인증된 시점 근거이며 권한·자격
증명·원격 철회 lease가 아닙니다. 실제 Pum 정책·projection·최종 전송 검증과 Kubernetes
전체 체인 검증은 후속 단계입니다. 이번 테스트는 실제 로컬 mTLS RPC와 별도 결정적
시간 산술 벡터이며, 공개 가짜 시계나 숫자 capability 생성자는 추가하지 않았습니다.
