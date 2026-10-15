# Workload observed 프로토콜

최초 프로토콜 단계는 서버 활성화 없이 additive 선언만 추가했습니다. 현재는
[네이티브 Workload owner](WORKLOAD_NATIVE_OWNER.md)가 명시적 설정으로 인증
IssueObserved/ObserveTime 서비스를 선택 등록합니다. Workload 권한·소비형 projection은
별도 후속 구현 게이트입니다. 기존 Service RPC/message/method path, trust, epoch 및
기본 설정의 의미를 유지합니다. Workload는 wire kind3/AAL0,
Service는 kind2/AAL0입니다. Parser와 protobuf message는 인증 capability가 아니며
strict/UTC Workload endpoint를 추가하지 않습니다. Human 세션·팩터는 별도 후속 계약입니다.

원천은 애플리케이션 범위에서 명시적으로 켠 실제 native Kubernetes TokenReview만
허용합니다. 요청자가 identity/kind/AAL/revision/검증 시각을 주장할 수 없습니다.
인증 성공만으로 권한을 부여하지 않으며 Pum의 같은 compiler/View에서 typed Workload
권한과 network/role/class/assurance를 모두 평가해야 합니다.

## Additive RPC

`hangang.hopae.v1`에 다음 선언을 추가합니다.

- `WorkloadAuthenticationReceipts/IssueObserved`: WorkloadReceiptRequest →
  WorkloadReceiptObservedReply.
- `WorkloadAuthenticationReceipts/ObserveTime`: WorkloadReceiptObservationRequest →
  WorkloadReceiptTimeReply.
- `WorkloadObservedCredentialProjection/Project`: 기존 ProjectionRequest →
  ObservedProjectionReply, permission_contract는 정확히3.

전용 receipt message는 대응하는 기존 Service 형태의 field tag를 유지합니다.
clock_domain은 signed epoch의 **32자리 소문자 nonzero hex nonce 그 자체**이며 prefix나
authority/generation suffix를 붙이지 않습니다. owner_now_ms는 정확히 그 issuer
BOOTTIME domain의 값입니다. remaining_ms는 admission 전용, cache_ttl_ms는 항상0입니다.
기존 correlation/canonical context/hash/정수범위/크기/rate/key-owner 검사도 유지해야
합니다. 새 request/proof Debug는 verification header와 receipt bytes를 숨깁니다.

Pum 후속 전용 서비스는 WorkloadObservedProjectionPermits의 Issue와 Observe이며
기존 AuthenticatedResourceRequest/PermitValidationRequest 및 observed reply를 재사용합니다.
Hop package에 Pum 서비스를 추가하거나 Pum 서버를 활성화하는 변경은 아닙니다.
기존 Service endpoint는 Workload를, 새 endpoint는 Service/Human/unknown kind 및
Workload의 nonzero AAL을 거부해야 하며 다른 경로로 fallback하면 안 됩니다.

## Canonical epoch

`hopae_grpc::workload_epoch`는 인증/예산을 만들지 않는 순수 owner metadata parser입니다.

    wobs1:<nonce32>:<authority>:p:<profile>:a:<application>

nonce는 process마다 새 암호학적 32자리 소문자 hex이며 all-zero를 금지합니다.
authority는 운영자가 신뢰한 정확한1..40 ASCII `[A-Za-z0-9_.:-]` 문자열이며 축약·해시·
대소문자 정규화를 금지합니다. profile/application은1..9007199254740991의 canonical
unsigned decimal이며 leading zero/sign/공백을 금지합니다. 전체128 bytes 이하이며
최대117입니다. 고정 prefix/nonce 뒤 오른쪽 마지막 `:a:`, 그 앞 마지막 `:p:`를
분리하고 재인코딩 bytes가 같아야 합니다. 숫자 suffix에 colon이 없으므로 authority에
colon/delimiter처럼 보이는 문자열이 있어도 모호하지 않습니다.

예: `wobs1:11112222333344445555666677778888:example-hopae:p:7:a:11`.
이 nonce는 설명용입니다. 파싱은 인증이 아닙니다. 초기 profile-owned 원천에서만
identity revision과 credential_generation 모두 profile입니다. 새 원천에는 별도
검토된 version 계약이 필요합니다. 논리 epoch authority와 TokenReview issuer URL/
cluster realm은 다른 값입니다. Subject hashing 입력은 그대로 유지합니다. 기존
Workload subject hash discriminator byte2와 wire kind3를 혼동하면 안 됩니다.
Subject는 기존 `s_`+48자리 lowercase hex를 유지하며 prefix만으로 Service를 뜻하지 않습니다.

## 원래 admission과 replay retention

인증/store/network callback **전** BOOTTIME을 잡고 원래 deadline D를 entry+1000ms 및
보수적인 원래 token/provider expiry 이하로 정합니다. Signed Workload authentication
receipt expiry도 같은 source domain에서 **반드시 D 이하**여야 합니다. 서명·profile
renewal·RPC retry·Observe·나중 성공으로 수명을 새로 시작하면 안 됩니다. Native wall/
token-expiry 검사는 추가 제한이며 elapsed age를 대체하지 않습니다. 마지막 callback/
sign/output에서도 원래 stamp를 유지하고 마지막 시계 의존 작업 후 owner를 검사합니다.
가짜 UTC나 외부 절대시각의 min을 사용하지 않습니다.

선택적인 bounded source record는 정확한 receipt hash/nonce/process domain 및 captured
profile/application/key owner에 묶어야 합니다. Record miss/eviction/retirement/replacement는
항상 거부하며 remaining_ms나 요청 context에서 새 deadline을 재구성하면 안 됩니다.
Stateless 대안은 signed expiry 자체가 정확한 원래 deadline을 보존하고 native current
owner 검사를 수행할 때만 허용합니다. Capacity 초과는 거부하고 비싼 작업 전 예약하며
필수 record 저장 전 receipt를 공개하면 안 됩니다. 갱신 불가 설계에서는 원래 token의
보관이 필요하지 않습니다. 외부 Pod/SA 철회는 최초 TokenReview와 이 원래 proof에 따른
측정된 지연 한계가 있으며 즉시 철회나 Observe마다 새 TokenReview를 수행한다고 주장하지
않습니다. 강화하려면 보호된 token-reference 계약을 별도 검토해야 합니다.

시계 읽기 실패·역행/불연속·captured owner 교체는 해당 원래 observation을 영구 철회합니다.
Peer 복구나 정상 시계 읽기로 되살리면 안 됩니다. Process clock 연속성이 불명확하면
그 domain을 철회하며 새 정상 domain과 새 native 인증이 필요합니다.

Source eligibility, 선택적인 source-record 저장 수명, durable consumed-nonce retention은
서로 다릅니다. 만료 source record 제거는 miss가 영구 fail-closed일 때만 가능합니다.
Paired auth/permit 소비 기록은 짧아진 admission이나 source 소멸과 관계없이 **전체 signed
proof retention upper bound**까지 유지합니다. Authentication retention은 검증한 signed
expiry와 인증된 owner_now에서 계산하며 remaining_ms로 줄이면 안 됩니다. Pum의
proof_remaining_ms는 retention 전용이고 remaining_ms는 admission 전용입니다.
기존 RPC 전 receiver anchor와 명시적 rate/quantization, admission 교집합 및 retention
비단축 계산을 재사용합니다. Numeric helper가 identity/권한을 만들지 않습니다.

Contract1/2/3과 Service/Workload는 같은 atomic paired ledger와 기존 signing-key/nonce
identity 규칙을 공유합니다. RPC/class/contract/context digest 변화로 새 replay namespace를
만들면 안 됩니다. Source-record capacity/cancellation도 durable 소비 기록을 초기화하지 않습니다.

## Native policy 및 이행 게이트

Pum의 선택적 workload_users는 기존 users와 같은 compiler/CompiledPolicy/정확한 source
View에서 평가하되 양방향 fallback을 금지합니다. 동일 subject bytes가 두 map에 있어도
권한을 분리하며 Workload AAL0로 양수 assurance 요구를 만족할 수 없습니다. 실제 policy/
route/plan/network/application/profile/key 철회 fence를 유지합니다.

Mapping v1은 기존 workload-coordinate 입력까지 기존 legacy users 출력과 candidate_only/
직렬화 필드를 그대로 보존하며 typed Workload grant로 바꾸지 않습니다. Template의 두 map은
모두 비어 있어야 합니다. 명시적 v2만 Workload grant를 workload_users에, native_subject
legacy grant를 users에 기록하며 한 grant에 두 종류를 동시에 넣지 않습니다. Candidate version/
class metadata로 구분하고 v1에 새 empty/null field를 추가하면 안 됩니다. 기존 인증된 source
publication/View owner 검사가 있어야 활성화되며 Kubernetes RBAC 일치만으로 앱 권한을 주지 않습니다.

활성화 전 실제 TokenReview → typed Pum resource Allow → shared consuming Hop projection →
Root opaque SDK/raw I/O gate → 독립 backend counter까지 검증해야 합니다. Clock/callback/sign
지연, record miss, capacity/cancellation, 원래 expiry, restart nonce, class/epoch/method mismatch,
전체 signed replay retention, v1 byte 호환성, v2 typed 분리, source 철회 및 외부 철회 지연을
검증합니다. 합성 서명·생성 client·parser vector만으로 전체 지원을 주장하지 않습니다.
Service strict/observed 회귀 검증을 유지하며 dependency 공개/서버 활성화/서명/배포는 parent가 통제합니다.
