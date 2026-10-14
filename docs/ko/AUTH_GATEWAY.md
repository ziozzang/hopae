# 서비스 인증 게이트웨이

<!-- translation-status: source=../AUTH_GATEWAY.md source-rev=32 status=current -->

[문서](README.md) · [English](../AUTH_GATEWAY.md) · [네이티브 통합](HANGANG_NATIVE.md)

미릴리스 `auth_gateway::request_binding`은 변환 요청 digest 기본 함수를 구현합니다.
SHA-256에 `hangang-zerotrust:credential-projection:request:v1`과 NUL byte를 넣고
네이티브 서비스 참조·대상 참조·대문자 method·검증된 정확한 origin-form path/query·
완전한 entity의 32-byte SHA-256을 순서대로 각각 32-bit big-endian 길이와 함께
해시합니다. percent encoding·query 순서를 유지하며 route 해석·URL 정규화는 하지
않습니다. 네이티브 라우팅이 대상·route 버전을 제공하고 재검증해야 합니다. 아직 모르는
streaming body에는 별도 계약이 필요하고 빈 body 해시로 대체하지 않습니다.

서비스 `ab`, 대상 `c`, method `GET`, `/private?x=1`, 빈 entity 해시의 독립 벡터는
`234488f459d8b3069a74d308d639fa9bfb402b12a9544a413c06c6136a8dab11`입니다.
잘못되거나 모호한 대상·너무 큰 필드는 거부합니다. receipt 인증·재사용 입장·권한·
자격 발급은 아니며 아직 구현하지 않은 실제 변환 경로에 연결되지 않았습니다.

미릴리스 `auth_gateway::receipt`는 기존 lock의 ed25519-dalek 2.2.0을 사용해 엄격한
Ed25519 검증을 추가합니다. 146-byte receipt는 version·purpose, big-endian u64
밀리초 시각 2개, native binding 32 bytes, CSPRNG nonce 32 bytes, 서명 64 bytes입니다.
`hangang-zerotrust:projection-receipt:v1`과 NUL 및 정확한 82-byte payload에 서명합니다.
인증·허용 목적을 구분하고 설정된 키도 분리하며 수신자가 선택해야 합니다. 클라이언트
키를 신뢰하지 않습니다. 약한 키·다른 목적/binding·잘못된 길이·미래/만료·1초 초과를
거부하며 검증 결과는 직접 생성·Clone·Serde가 불가능한 receipt wrapper로 반환합니다.

신원·issuer/key epoch·전체 요청/대상·버전·인증/결정 chain을 묶는 native binding
builder는 구현해야 합니다. 서명 확인만으로 현재 권한을 증명하지 않으며 key registry·
시계 rollback fence·회수·원자적 nonce 소비·issuer/receiver endpoint 연결은 후속입니다.
실제 발급·배포 동작은 바뀌지 않습니다.

미릴리스 `receipt_binding`은 네이티브 문맥의 canonical digest를 제공합니다. 공통
필드는 signer 참조/key epoch, 신원 authority epoch, namespace가 결합된 subject
참조, 신원 종류/AAL, 신원 revision/자격 generation, 서비스/대상, 요청 SHA-256입니다.
사람은 AAL 1–3, 서비스·워크로드·네트워크는 AAL 0이며 참조는 제한된 식별자, revision은
양수 JSON-safe 정수입니다. 호출자 필드의 인증은 아니며 서명·검증 전에 소유자가
해당 값을 만들어야 합니다.

인증은 정책·네트워크 주장이 없는 stage 1입니다. permit stage 2는 정확한 서명된 인증
receipt SHA-256, decision/resource/action, 품계 authority epoch와 catalog/policy/
network/route/plan revision을 추가합니다. domain
`hangang-zerotrust:projection-receipt-binding:v1`과 NUL 및 u32 big-endian 길이를
사용하며 revision은 u64 big-endian, 종류/AAL은 byte입니다. 종류 코드는 사람=1,
서비스=2, 워크로드=3, 네트워크=4입니다. 테스트 3건에 독립 Python 벡터와 서명된 다른
문맥 거부를 포함합니다. 실시간 소유권·키 registry·replay/회수·endpoint 연결은 후속입니다.

미릴리스 `receipt_keys::Registry`는 네이티브 issuer 참조·receipt 용도·key epoch로
수신자 소유 공개 키를 선택하고 canonical binding·엄격한 서명을 검증합니다. wire가
자기 검증 키를 고르지 못합니다. 전체 불변 view를 만들며 활성 키 64개, authority/용도
floor 128개, 과거 키 소유권 256개로 제한합니다. revision/epoch rollback, 같은 epoch
키 변경, 제거 키 부활, 약한/중복 키, 회수된 키를 포함한 다른 authority/용도 재사용을
거부합니다. 새 registry revision에서 같은 활성 키/epoch는 유지할 수 있고 제거된 키는
floor를 유지해 더 높은 epoch로만 다시 등록합니다. 조회 시 issuer 문자열을 할당하지 않습니다.

현재 메모리 갱신 fence이며 이전 상태 없는 새 registry로 과거 floor를 증명하지 못합니다.
문맥은 검증된 신원·결정에서 만들어야 합니다. 배포 전 DB 게시·재시작/복구 floor·원자적
활성화·membership·replay 소비·실제 endpoint 연결이 필요합니다.

미릴리스 `receipt_key_store`는 기존 소유자 `meta` table에 공개 registry·floor·이력을
저장합니다. 네이티브 publication은 호출자 권한 fence·기대 revision·전체 설정을 받아
쓰기 전에 컴파일하고 commit 직전에 권한을 다시 검사하며 registry와 참조 전용
revision/actor/digest 감사를 원자적으로 저장합니다. 실패 시 설치할 registry를 반환하지
않습니다. 성공 결과 활성화는 소유자 책임이며 runtime endpoint·자동 snapshot 설치는
추가하지 않았습니다.

load는 활성 항목·floor·공개 값 소유권을 복원·검증해 잘못된/중복/고아/약한/불일치
자료와 128 KiB 초과 문서를 거부합니다. 신뢰된 최소 revision으로 오래되거나 사라진
상태를 거부하며 일반 재시작에는 제거 이력이 유지됩니다. 오래된 DB 전체 복원은 외부
최소 버전·authority epoch fence가 필요하며 DB가 자기 rollback을 증명하지 못합니다.
registry/store 테스트 5건은 재시작·오래된 게시·권한 회수·감사 실패 rollback을 검증합니다.
비공개 signing key를 저장하거나 운영 DB를 변경하지 않았습니다.

미릴리스 `receipt_authority`는 DB 게시와 공유 불변 verifier를 ArcSwap으로 연결합니다.
유지하는 단일 mutable 소유자가 commit/설치 순서를 직렬화하고 registry Arc는 commit
전에 할당해 이후 await·실패 가능한 소유자 작업 없이 설치합니다. 실패한 게시에는 이전
snapshot을 유지합니다. 검증 결과는 캡처한 registry revision을 가진 non-Clone receipt이며
로컬 pointer 현재 상태 검사로 이후 게시 전 결과를 거부합니다. 이는 보조 검사입니다.
nonce 소비·발급 transaction에서 commit/설치 사이 구간을 포함해 DB revision을 다시
확인해야 합니다. 독립 writer·분산 follower·시작/API 연결은 후속입니다. receipt 테스트
11건에 서명된 실시간 제거·공유 verifier 갱신·재시작 거부를 포함하며 배포 요청 경로에는
이 라이브러리 소유자를 활성화하지 않았습니다.

미릴리스 소스는 네이티브 서비스 자격 검증 후 선택적인 제한된 Lua 사용 조건을
적용합니다. [서비스 사용 조건 설정](../CONFIG.md#service-authentication-lua-eligibility-unreleased)을
참고하세요. 스크립트는 자격 인증·신원 변환·인증등급 변경·품계 권한 판단을 대체하지
못하며 아래는 네이티브 커넥터 설명입니다.

런타임 connector는 선택적인 IP 조건과 함께 자체 서비스 API 키를 인증하거나 고정된
외부 검증 서버에 Bearer credential을 릴레이합니다.
`authentication_gateway`로 활성화하며 이 설정이 없으면 기존 OIDC/세션 라우트를
유지합니다. HTTP와 HOP1 모두 API credential을 읽기 전에 동일한 caller 키·제한된
동시성·forwarded 요청 문맥 검증을 적용합니다.

```json
{"authentication_gateway":{"authority_id":"example","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"HOPAE_ORDERS_API_KEY","subject":"scheduler"}],"networks":["192.0.2.0/24"],"session_fallback":false}]}}
```

각 profile은 설정된 application ID·정확한 host·port와 맞아야 하며 범위가 겹치면
거부합니다. 참조 credential은 32–1024바이트 printable ASCII여야 하고 생성한
비밀값을 사용합니다. 공개 설정에는 환경변수 참조만 둡니다. 시작 검사는
미등록/잘못된/중복 credential을 거부합니다. 키의 선택적인 `expires_at`은 절대
Unix 밀리초입니다. 프로세스 안에서 관찰한 만료를 시계 되돌림으로 취소할 수
없지만 재시작을 넘는 영속 만료 watermark는 후속 작업입니다.

런타임은 제한된 profile·credential·network node의 SHA-256 credential index와
IPv4/IPv6 prefix tree를 메모리에 유지합니다. 요청에서 SQLite나 provider를
호출하거나 credential을 저장하지 않습니다. 현재 버전은 파일 소유이며 시작할 때
컴파일합니다. 참조·만료·network 변경에는 재시작이 필요합니다. DB 소유 게시·회전
API·관리 UI·분산 무효화는 구현 작업으로 남아 있습니다.

Profile은 제시한 Bearer credential을 선택합니다. 없는 credential은 거부하되
`session_fallback:true`가 명시적으로 기존 세션 엔진을 허용할 수 있습니다.
잘못된/중복/형식 오류/만료/network 거부 credential은 브라우저 세션으로 전환하지
않습니다. Network 조건은 인증된 forwarded client 주소를 쓰며 새로운 신원
주장을 받지 않습니다. 예약된 로그인/로그아웃 경로는 기존 세션 동작을 유지합니다.

인증 성공은 principal kind·authority/issuer·realm·설정 subject로 만든 불투명한
`s_…` 신원을 출력합니다. `x-hopae-principal-kind: service`·`x-hopae-aal: 0`·인증된 `x-hopae-service-id`를
출력하며 사람 계정·검증된 이메일·MFA를 만들지 않습니다. 응답에는 credential이
없고 `Cache-Control: no-store`를 적용합니다. 인증은 서비스 권한 부여가 아니므로
Hangang/품계가 서비스 매트릭스를 집행합니다. Hangang은 서비스 kind·AAL 0·정확한
인증 서비스 audience를 검증하고 강제되는 품계 게이트를 요구하며 정책/변환과
upstream 전송 전에 Authorization credential을 소비합니다. 역할이 AAL 0을
명시적으로 허용해야 하고 API 키로 사람/MFA 요구를 만족할 수 없습니다.

`tools/service_stack_smoke.py`는 실제 격리된 한강·호패·품계 프로세스를 실행합니다.
`--sumunjang-binary /path/to/sumunjang`을 추가하면 네트워크 판정까지 포함하고
서비스 매트릭스에 집행 근거를 필수로 요구합니다. `--grpc`는 세 판정 교환 모두
mTLS gRPC를 사용하며 생략하면 같은 네 프로세스에서 HOP1/PPG1/HGD1을 사용합니다.
인증·IP/등급/메서드 권한·잘못된 자격 거부·영속 권한 회수/복원·서비스 격리·
upstream 자격 소비·원천 장애 시 거부를 검증합니다. 모든 거부 요청은 애플리케이션
백엔드 호출 수를 늘리지 않아야 합니다. 네트워크 차단 해제/복원과 서버 장애/재연결도 확인합니다.
초기 파일에 기존 허용이 남아 있어도 실제 품계 재시작 후 권한 회수가 유지되는지 확인합니다.

`--external-verifier`는 실제 API 릴레이 장애와 열린 서킷의 추가 호출 억제를 검증합니다.
`--durable-restart`는 초기 파일이 그대로여도 영속 프로파일 삭제가 실제 호패 재시작에
살아남는지 확인합니다. 이는 로컬 기능 검증이며 실제 K8s 배포·운영 반영·기존 스트림을
포함한 전체 자격 수명주기·분산 처리량은 별도 작업입니다. LDAP와 자체 사람 인증에는
별도 검증이 있고 더 넓은 커넥터 조합·표준 introspection 호환·전체 변환/수명주기 검증은 남아 있습니다.

## 외부 API 검증 릴레이

Profile은 `api_keys` 대신 `api_relay`를 설정할 수 있고 둘은 동시에 사용할 수
없습니다. 고정 `url`·신뢰하는 `issuer` namespace·선택적 `verifier_key_env`·
`timeout_ms`(1–1000, 기본 100)를 설정합니다. 명시적으로 활성화한 루프백 fixture
외에는 HTTPS가 필수입니다. 사설 목적지는 `allow_private_endpoints:true`가
필요합니다. 리다이렉트·URL 자격 정보/질의/fragment·환경 프록시를 거부하고 실제
연결 시 공인 DNS 주소를 검증합니다. 설정 issuer/realm이 신원을 결정하며 응답으로
다른 issuer 또는 사람 assurance를 선택할 수 없습니다.

Connector는 JSON `{service_id, client_ip}`를 POST하고 원래 credential을 민감한
Bearer Authorization 헤더로 보냅니다. 선택적인 verifier credential은 민감한
`x-hopae-verifier-key` 헤더를 사용합니다. 요청에서 URL을 받지 않습니다. Verifier는
`active`·`subject`·`service_id`·`expires_at` 필드만 있는 JSON을 반환합니다. Active
응답은 정확한 서비스·제한된 subject·응답 수신 이후 5초 안의 절대 Unix 밀리초
만료가 필요합니다. 근거는 최대 1초이며 만료 검증에 네트워크 시간을 포함합니다.
거짓 assurance/추가 필드·다른 audience·만료된 응답은 거부합니다. 기존 서비스
namespace와 AAL 0을 사용하고 이후 품계가 권한을 별도로 집행합니다.

Connector당 최대 64개 요청과 지속 HTTP 연결을 사용하고 전체 기한·64 KiB 응답
제한을 적용합니다. Credential 거부는 401, 백엔드/계약 오류·포화·타임아웃은 세션
fallback 없이 503입니다. 연속 백엔드/의미 오류 3회 후 프로세스 로컬 서킷을
30초 동안 열고 단일 복구 probe를 허용합니다. 취소는 probe를 해제하고 일반적인
credential 거부는 서킷 장애로 세지 않습니다. 이 첫 verifier 계약에는 결과 캐시·
upstream credential 교환·영속 quarantine·관리 게시·RFC 7662 필드 adapter를
구현하지 않았습니다.

## 조합된 인증 근거 기한

`compose_verified` 코어 계약은 검증된 subject와 서비스 audience를 보존하고 전달된
근거의 가장 이른 만료 또는 1초 중 더 짧은 기한을 사용합니다. Any/All은 미등록·중복
커넥터·만료 근거·충돌하는 namespace subject·불일치 audience를 거부합니다. 읽기
전용 결과에는 assurance 수준 주장이 없으며 서비스/network 근거가 여러 개라도 사람
MFA가 되지 않습니다. audience 유지·최초 만료·1초 상한·만료 거부를 검증했습니다.
조합 기초 계층이며 런타임 connector 실행 조합과 명시적으로 검증된 provider 간
subject 관계는 남아 있습니다. 기존 요청 프로필은 설정된 커넥터를 사용합니다.

## 사용자 2차 인증과 확장 계약 — 구현 백로그

Google Authenticator와 호환되는 네이티브 TOTP, 외부 인증 API 호출,
Lua 등을 통한 확장 가능한 adapter를 필수 범위에 추가합니다. 모델에
`FactorKind::Totp`·AAL 2가 있다는 것만으로 MFA가 구현된 것은 아닙니다.
서비스 API 증거는 AAL 0이며 네트워크 증거만으로 사용자 소유 요인이 되지 않습니다.

요인 엔진은 1차 인증 provider adapter와 분리합니다. Challenge는 내부 user ID,
1차 provider 증거, session/transaction, 서비스 audience, 브라우저 binding,
요구 보증 수준, 정책 revision, 만료, single-use nonce를 묶습니다. Adapter는
타입 증거만 반환하고 코어가 독립 요인을 결합하며 challenge 소비·OTP 재사용
상태를 원자 commit한 뒤 자격 세대·핸들을 교체하고 보증 수준을 발급합니다.
신원·provider·정책·등록·세션 변경은 대기 challenge를 무효화합니다.
성공 OTP를 캐시해 다른 challenge를 승인하지 않습니다.

네이티브 등록은 사용자별 무작위 seed를 DB 밖 버전 키로 암호화합니다.
코드 확인 전에는 pending이며 provisioning 자료는 인증된 portal에서 한 번만
표시하고 Hangang broker·감사로 내보내지 않습니다. 초기 제안은 30초·6자리
HMAC-SHA-1 TOTP와 제한된 인접 시간창이며 실제 authenticator 호환성을 검증합니다.
마지막 승인 counter를 replica 간 원자 CAS로 저장하고 시계 역행으로 코드를
재사용할 수 없게 합니다. 계정·challenge·네트워크 시도 제한과 DB 권위 하의
성공 소비를 적용합니다. 등록·교체·해제는 최근 인증과 적절한 step-up을 요구합니다.
복구 코드는 개별 hash·single-use·감사를 적용하고 복구 결과를 무제한 MFA로
승격하지 않습니다. 회수는 정책에 따라 세션·stream을 종료하거나 등급을 낮춥니다.
OTP는 피싱 저항 요인이 아닙니다.

외부 요인 API는 운영자가 승인한 고정 HTTPS endpoint·신원을 사용하며 redirect,
env proxy, 요청이 선택한 URL을 금지합니다. 크기·deadline·동시성·서킷을 제한하고
요청 nonce·user·audience·operation을 응답에도 묶어 짧은 만료와 인증된 provider
결과를 검증합니다. 단순 `success=true`로 MFA를 부여하지 않습니다. 거부와 provider
장애를 구분하고 필수 요인 장애에서 우회·key fallback 없이 거부합니다. 출처와
요인 capability 제한으로 비밀번호·IP 검사를 독립 소유 요인으로 주장하지 못하게 합니다.

Lua adapter는 제한된 context·불투명 secret handle만 받고 instruction·메모리·시간
상한, 제한된 library와 승인된 host 네트워크 호출을 사용합니다. Script 배포는 검증,
revision CAS·감사·롤백을 요구합니다. 세션 발급·임의 DB 쓰기·보증 수준 선택·원문
자격 노출은 허용하지 않습니다. TOTP는 Rust 네이티브이며 Lua는 별도 검증할
선택적 확장 수단입니다.

알고리즘 vector, 등록·교체·복구, 프로세스 간 동시 재사용, 시계 역행, challenge
교환, 요인 회수, 외부 API 대체·장애·서킷 복구, sandbox 탈출·자원 소진,
서비스 step-up과 Hangang 관리자·stream 전파를 검증하고 내부 도그푸딩을 수행합니다.
알고리즘 참고: [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238),
[RFC 4226](https://www.rfc-editor.org/rfc/rfc4226). 위 프로토콜 설정·수명주기는 호패의
설계 제안이며 RFC가 등록·외부 API 설계를 정의하는 것은 아닙니다.

## TOTP 계산 소스 상태

`src/factor/totp.rs`에 HMAC-SHA-1/256/512 dynamic truncation, 6·8자리 ASCII
숫자, 고정 30초 step과 양쪽 최대 한 step 검사를 구현했습니다. Seed는 20–128
byte로 제한하고 Debug를 가리며 소유 byte를 drop 시 지웁니다. 예상 OTP·HMAC
버퍼도 지우며 제출값은 기존 Secret wrapper를 사용합니다. 시간창 후보는 모두
constant-time byte 비교를 수행합니다. 음수 시간·비정상 코드를 거부합니다.
결과는 호출자가 준 마지막 승인 watermark보다 큰 일치 counter일 뿐이며,
user binding·요인 출처·보증 수준이 없고 단독으로 세션을 만들 수 없습니다.

집중 테스트 2건이 RFC 6238 Appendix B의 18개 vector, 큰 timestamp,
앞자리 0, 6자리 기본값, 잘못된 입력, 제한 시간창, 시계 역행을 포함한 watermark
거부를 검증합니다. 실제 authenticator 등록은 아직 검증하지 않았습니다.
등록 endpoint·저장 seed 암호화·복구·영속 동시 재사용 CAS·MFA 세션·관리자 통합,
외부 요인·Lua adapter는 이번 계산 변경에 포함되지 않습니다. 이 수명주기 요구를
완료해야 TOTP 인증 지원을 달성한 것으로 판단합니다.

## Seed envelope 소스 상태

`src/factor/seed_cipher.rs`에 XChaCha20-Poly1305 envelope를 추가했습니다.
기존 운영 CSPRNG로 생성한 새 24-byte nonce, 버전 외부 32-byte 키,
목적·key ID·내부 user·등록 ID를 길이 구분한 associated data를 사용합니다.
Envelope 필드는 비공개이며 제한된 JSON 파싱은 1024-byte 초과 문서,
미지원 버전·잘못된 암호문 길이를 거부합니다. Key·복호화 평문 버퍼는 소유
메모리를 지우고 Debug는 key·envelope 내용을 가립니다. 평문 seed·키를
직렬화하지 않으며 복호화 실패는 하나의 타입 오류로 반환합니다.

집중 테스트는 왕복, 다른 user·등록·key로 대체, 암호문·nonce·버전 변조,
새 nonce, 제한된 식별자·입력을 확인합니다. 아직 DB·등록 UI에 연결되지
않았습니다. 운영 키 로딩·keyring 교체·백업·폐기, pending 등록,
재사용 CAS·복구·세션 통합은 필수로 남습니다. 유효한 과거 암호문의 재사용은
막지 않으므로 소유 DB가 등록 revision·회수를 검사해야 합니다.
암호 API 참고: [RustCrypto chacha20poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/).

## TOTP 소유 저장소 소스 상태

Schema v5에 암호화 등록 envelope, pending·active·revoked 상태, revision,
마지막 counter, pending 만료를 저장합니다. Unique index로 사용자당 pending·active를
각각 하나로 제한합니다. Factors 저장소는 active 사용자에게 10분 만료 pending을
만듭니다. 활성화는 owner·revision·미만료 pending·사용자 활성 상태를 검사한 뒤
revision을 올리고 검증된 counter를 기록합니다. 소비는 예상 revision의 active
owner·등록과 엄격히 큰 counter를 요구합니다. 회수는 revision을 올립니다.
호출자가 준 이벤트는 변경과 함께 commit하고 거부 시 성공 이벤트를 기록하지 않습니다.

SQLite 회귀는 owner 불일치, 재사용·낮은 counter, revision·회수와 독립된 두
writer 연결의 같은 counter 경합을 검사합니다. 다중 프로세스·fleet 검증은 아닙니다.
Counter는 신뢰한 호출자가 이미 검증해야 합니다. Challenge·세션의 원자 완료,
요인 전용 감사, 조회·등록 서비스, 만료 pending 정리·교체·복구·UI는 미완성이며
HTTP handler에서 이 연산을 호출하지 않습니다. 소스 schema v5는 내부 미배포입니다.
오래된 바이너리가 업그레이드 DB를 열 수 없어 롤백은 일관된 이전 스키마 백업
복원을 요구합니다.

## 내부 등록 조회와 수명주기 검증

Factors 경계는 정확한 owner·ID로 암호화 등록을 조회합니다. Active 사용자의
active 또는 미만료 pending만 반환하며 회수·만료·다른 owner·비활성 사용자
상태는 조회되지 않습니다. 내부 row는 직렬화하지 않고 envelope Debug도 가립니다.
콘솔 broker 응답으로 내보내면 안 됩니다. 인증 서비스는 설정된 keyring으로
복호화하고 최종 쓰기에서 수명주기 revision을 다시 검사해야 합니다.

SQLite 수명주기 회귀는 pending 조회·복호화, 정확한 만료 거부, 만료 pending
회수, 필수 이벤트 삽입 실패 시 활성화 롤백, 독립 reopen을 통한 active revision·
counter 보존, 비활성 사용자 조회·소비 거부와 회수 가능을 확인합니다.
롤백 테스트는 기존 필수 이벤트의 ID 중복을 인위적으로 만들어 실패시키며
요인 전용 감사 의미를 구현하지는 않습니다. 전체 프로세스 재시작,
challenge·세션 원자 처리, pending 정리·교체, 등록·복구 UI·키 관리·내부 MFA
도그푸딩은 필수로 남아 있습니다.

## 네이티브 검증과 소유 저장소 소비

`src/factor/service.rs`는 owner에 묶인 암호화 등록 조회, 키 검증·복호화,
네이티브 6자리·30초 TOTP 프로파일을 revision 검사 DB 변경에 연결합니다.
등록 확인은 이미 active인 상태를 거부하고 인증 소비는 pending을 거부합니다.
등록 확인 counter를 활성화 때 소비해 곧바로 인증에 재사용하지 못하게 합니다.
조회 후 회수·owner 비활성화·경쟁 소비는 최종 쓰기에서 거부됩니다.
직렬화하지 않는 결과는 목적·owner·등록·변경 후 revision·counter·검증 시간을
기록하며 AAL·세션 권위를 부여하지 않습니다.

실제 저장소 회귀는 등록을 한 번 확인하고 다음 유효 코드를 두 요청이 동시에
검증하면 정확히 하나만 승인함을 확인합니다. 내부 서비스이며 HTTP route는
아닙니다. 시도 제한·최근 인증·challenge binding·challenge와 세션의 원자 완료,
keyring 선택·요인 전용 감사·복구·UI·내부 도그푸딩은 남아 있습니다.
Counter만 소비한 뒤 별도 트랜잭션으로 안전하지 않게 세션을 승격하면 안 되며,
통합 완료는 하나의 원자 쓰기로 구현해야 합니다.

## 내부 v3→v5 마이그레이션·백업 롤백 검증

실제 내부 호패 schema-v3 DB를 SQLite backup API로 비공개 검증 디렉터리에
복사했습니다. 현재 Store 구현이 오프라인 후보를 v5로 마이그레이션했고,
integrity check·집계 내용 비교로 기존 13개 업무 테이블의 보존을 확인했습니다.
일관성 백업을 복원하면 v3와 원래 내용이 재현됐습니다. 업그레이드 후보를
포함한 모든 복사에 backup API를 사용합니다. 주 파일만 복사하면 WAL의
마이그레이션을 놓쳐 잘못된 롤백 결과를 얻을 수 있습니다.

현재 운영 `0.0.2-profile-console-9b307c0` 이미지를 네트워크·운영 상태 mount
없는 격리 컨테이너에서 실행했습니다. `admin list`는 복원 v3를 열고,
검증된 v5 후보는 새 스키마로 거부했습니다. 자격증명·CLI 출력은 공개 증거에
포함하지 않았고 운영 DB는 마이그레이션하지 않았습니다. 오프라인 데이터와
구버전 CLI 호환 검증이며 전체 앱 부팅·provider 로그인·배포 준비 완료는 아닙니다.

재현은 `cargo build --example qualify_owner_migration` 후
`python3 tools/qualify_owner_migration.py --database <owner-db> --output <new-private-directory> --qualifier target/debug/examples/qualify_owner_migration`입니다.
Rust helper는 기존 `migration-candidate.db`만 허용하고 Python은 입력 DB를
마이그레이션하지 않습니다. 후보·백업에는 비공개 신원·세션 자료가 있으므로
비공개로 보관합니다. 내부 반영 전 후보 이미지·전체 부팅 회귀 검증과
마이그레이션을 고려한 롤백이 아직 필요합니다.

## 내부 owner-v5 배포와 도그푸딩 — 2026-10-13

소스 `d876909`의 정적 Linux-musl 바이너리를
`hopae:0.0.2-owner-v5-d876909` 이미지로 구성했습니다. 별도 loopback 후보가
실제 소유 상태의 일관성 비공개 복사본으로 schema v5 부팅에 성공했습니다.
HTTP·지속 연결 mTLS HOP1은 기존 서비스 key를 승인하고 누락·잘못된 key를 거부했습니다.

운영 반영은 이전 인스턴스를 정지하고 일관된 schema-v3 백업을 만든 뒤,
이미지 선택만 변경해 재시작했습니다. Schema v5·health를 확인하고 실제 Hangang
HTTPS 서비스 권한·거부·자격 소비, 호패·수문장·품계 통합 메뉴·매트릭스,
SSO 진입·로그아웃·익명·Origin 격리·네이티브 mTLS 회귀가 통과했습니다.
설정·기존 provider 선택은 유지했습니다. 이전 스키마 비공개 백업과
마이그레이션 롤백을 보관하며 공개 증거에 자격·신원·세션 row를 포함하지 않습니다.

최신 내부 primitive·API profile 서킷 연속성의 배포이며 LDAP 로그인이나 OTP
등록·step-up 활성화는 아닙니다. 운영 설정·UI는 아직 미완성입니다. 실제 외부
사용자 SSO 로그인·디렉터리 회수·업스트림 자격 변환·요인 challenge와 세션의 원자 처리,
분산 follower·membership·전체 스택 처리량·공개 다중 플랫폼 릴리즈도 남아 있습니다.
내부 서비스·콘솔 도그푸딩을 지속하며 전체 제로트러스트 목표는 active입니다.

## 등록 준비 소스 상태

`src/factor/enrollment.rs`는 기존 CSPRNG로 새 20-byte seed를 만들고
SHA1·6자리·30초의 Google Authenticator 형식 `otpauth` URI를 구성합니다.
Owner·등록 binding으로 암호화하고 pending 저장에 성공한 뒤에만 provisioning
자료를 반환합니다. Issuer·account label은 길이를 제한하고 colon·control을
거부하며 percent-encode합니다. Prefix·query issuer가 일치하고 Base32 padding은
생략합니다. URI wrapper는 직렬화·clone하지 않고 소유 메모리를 지우며 Debug를
가립니다. 명시적 노출은 향후 인증된 등록 응답용이며 기존 저장 seed에서
provisioning 자료를 다시 복구하는 API는 없습니다.

집중 테스트 3건은 URI 필드·encoding·잘못된 label·실제 pending commit 후
반환을 확인합니다. 중복 준비는 기존 row를 교체하거나 URI를 다시 반환하지 않고
거부합니다. 브라우저의 한 번 표시를 보장한 것은 아닙니다. 최근 인증·CSRF/Origin,
no-store·referrer·CSP 응답 제한, QR·확인·복구·해제 UI·시도 제한·keyring 로딩,
challenge와 세션 원자 처리는 남아 있습니다. 등록 route는 활성화하지 않았습니다.
과거 원본 [Google key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)을
encoding 참고로 사용하며 현재 실제 앱 scan은 아직 검증하지 않았습니다.

## 만료 pending 교체와 필수 요인 감사

새 pending 등록 생성은 같은 active 사용자의 만료 pending을 회수하고 새 row를
넣는 작업을 한 트랜잭션에서 수행합니다. 살아 있는 pending은 중복 준비를
막으며 삽입·호출자 필수 감사 실패 시 정리·새 등록 모두 롤백합니다. 정리된
이전 row는 revision을 올리고 회수 상태로 남아 시계 역행으로 되살아나지 않습니다.
기존 active 요인을 교체하거나 등록 HTTP route를 제공하는 것은 아닙니다.

저장소는 호출자 이벤트가 없어도 필수 `factor.enrollment_prepared`,
`factor.enrollment_activated`, `factor.enrollment_expired`, `factor.totp_consumed`,
`factor.enrollment_revoked`를 생성합니다. Owner·등록 식별자와 저장소 correlation
표식만 포함하고 동일 transactional outbox를 사용합니다. Seed·URI·code·counter·key는
감사 속성에 넣지 않습니다. 저장소 변경에 대한 이벤트이며 counter 소비 감사만으로
challenge에 묶인 MFA 세션이나 HTTP actor를 증명하지 않습니다.

실제 저장소 회귀는 살아 있는 pending 거부, 만료 교체, 필수 이벤트 중복 시
롤백, 6개 수명주기 이벤트와 pending outbox를 확인합니다. 최근 인증·actor
연결, active 요인 원자 교체, challenge·세션 완료, 복구·UI·내부 MFA 도그푸딩은
아직 남아 있습니다.

## 운영자 참조 keyring 소스 상태

`src/factor/keyring.rs`는 active 암호화 키 하나와 명시적으로 유지하는 복호화
키를 최대 16개까지 불변 메모리에 컴파일합니다. 설정은 ID·환경 변수 참조만
포함합니다. 비밀을 읽기 전에 전체 참조의 ID 길이·일반 환경 변수 이름,
ID·참조 중복·active ID 존재를 검사합니다. 값은 정확히 43자리 padding 없는
Base64url에서 32 byte로 해석돼야 합니다. 0 키·누락·잘못된 값·실제 키 중복은
거부합니다. 읽은 문자열·복호화 byte는 메모리를 지우고 keyring Debug를 가립니다.

암호화는 active 키만 쓰며 envelope 복호화는 정확한 유지 key ID를 선택합니다.
Active 키·환경·네트워크로 fallback하지 않습니다. 테스트 2건은 active 교체 후
이전 복호화 유지, 키 폐기 시 거부, 잘못된·중복 참조·값을 확인합니다.
설정 로딩 컴포넌트이며 활성 root 설정이나 HTTP·관리자 키 관리 endpoint는
아닙니다. 앱 시작 로딩·안전한 revision 교체·재암호화·외부 키 보관·백업·폐기
정책·등록 HTTP 흐름·내부 MFA 검증은 남아 있습니다. 운영자는 충분히 무작위인
키를 생성해야 하며 구조 검사가 entropy를 증명하지 않습니다. 재암호화 전에
참조 키를 폐기하면 해당 요인이 비활성화됩니다.

## 요인 서비스의 keyring 연결

등록 준비는 컴파일한 keyring을 받아 active 키로만 암호화합니다. 네이티브
TOTP 검증은 소유 상태를 한 번 조회하고 envelope가 지목한 정확한 유지 키를
선택해 복호화합니다. 누락·폐기 키는 counter·등록 변경 전에 동일하게 거부하며
호출자의 단일 키 선택·active 키 재시도·환경 조회·네트워크 fetch를 하지 않습니다.
Keyring은 서비스 호출 동안 불변입니다.

실제 저장소 테스트는 active 키 교체 후 유지 키 검증, pending 상태를 바꾸지 않는
폐기 거부, 등록 준비·동시 single-use 검증을 확인합니다. Root 설정·앱 시작 로딩,
키 폐기에 대한 정책 publication fencing, envelope 재암호화, 등록·step-up
HTTP·UI와 challenge·세션 원자 완료는 미완성입니다. 현재 내부
`owner-v5-d876909` 이미지에는 이번 소스 변경이 없습니다. 키 교체 테스트가
운영 키 관리나 전체 MFA 수명주기를 완성했다는 의미는 아닙니다.

## 시작 keyring 연결

Root `totp_keyring`의 참조 구조·값을 preflight에서 검사합니다. 앱 bind는
인스턴스 lock·DB 열기·마이그레이션·listener 전에 keyring을 컴파일하고
불변 Arc로 유지합니다. 잘못된 값은 일정한 비밀 없는 오류로 거부합니다.
설정이 없으면 기존 시작·provider 동작을 유지합니다. 설정 회귀는 key 파싱·참조
검사·오류 비밀 제거를 확인하고 bind 회귀는 누락된 키가 상태 디렉터리를
생성하지 않음을 확인합니다.

Bootstrap 연결이며 요인 HTTP 지원 완료는 아닙니다. 실행 중 키 배포·폐기 검사,
재암호화·최근 인증·시도 제한·등록·step-up UI·challenge와 세션 원자 처리·내부
MFA 도그푸딩은 남아 있습니다. 현재 내부 `owner-v5-d876909` 이미지는 이 설정
이전 버전이며 해당 설정을 넣지 않았습니다.

## Schema-v5 기반 구조 검사

시작·CLI 기반 검증이 TOTP 소유 테이블·수명주기·암호문 열, STRICT mode,
사용자별 두 unique partial index를 요구합니다. 이름만 확인하지 않고 고유성·
partial 여부·정확한 owner 열·pending 또는 active 조건을 검사합니다.
손상된 구조는 기존 읽기 전용 precheck에서 백업·마이그레이션 전에 schema-v5
오류로 거부합니다. 모든 테이블 제약이나 row의 암호학적 내용을 검증하는 것은 아닙니다.

회귀 테스트는 새 in-memory DB를 마이그레이션한 뒤 테이블·counter 열·index
존재·고유성·owner 열·조건을 손상시킵니다. 각 손상은 거부하고 정상 v5는 통과합니다.
전체 앱·복구 검증, 요인 HTTP·UI, challenge·세션 원자 완료와 이후 변경의
내부 배포는 아직 남아 있습니다.

## 등록 준비의 네이티브 소유자 권한 확인

세션 서비스는 portal handle의 사용자·수명·binding, AAL 1 이상, 5분 이내
인증·현재 사용자 권한 버전·live provider row를 확인한 뒤 FactorActor를
발급할 수 있습니다. 직렬화하지 않고 Debug를 가리며 원문 cookie 없이
5초 쓰기 lease를 갖습니다. 권한 확인 등록 서비스는 actor에서 seed owner를
가져와 호출자가 다른 user를 지정하지 못하게 합니다.

Pending 쓰기 트랜잭션은 lease 시간·시계 역행, 정확한 session·handle·host,
자격 세대·인증 시간·권한 버전, 활성 user·provider, 미회수 handle·session,
AAL·절대·idle 수명을 다시 검사합니다. 기존 active 요인이 있으면 초기 등록을
거부하며 교체에는 별도 step-up이 필요합니다. 검사한 commit 후에만 URI를
반환합니다. 기존 검사 없는 저장소·준비 primitive는 신뢰한 내부·운영자 API로
남으며 최종 사용자 HTTP handler에서 사용하면 안 됩니다.

실제 저장소 회귀는 내부 actor를 fixture에서 구성하고 정상 등록과 조회 후
회수·세대·버전 변경, provider 삭제, 오래된 인증·수명, lease 만료,
active 요인 등 12개 변경을 검사합니다. 쓰기 경계 검증이며 브라우저 actor
발급·전송 검증은 아닙니다. HTTPS·CSRF/Origin·시도 제한·요청 감사 연결,
확인·해제 검사·키 폐기 배포·challenge와 세션 원자 완료의 HTTP·서비스
통합은 남아 있습니다. 등록 route·MFA 세션 승격은 활성화하지 않았습니다.

## 소유자 검사 확인·해제와 세션 회수

권한 확인 등록 완료는 pending owner의 코드·정확한 유지 키를 검증하고 최근
세션 쓰기 검사 아래 활성화합니다. 권한 확인 해제는 같은 검사와 예상 등록
revision을 요구합니다. Active 요인 해제는 session·handle AAL 2와 최근
TOTP/WebAuthn 기록도 필요합니다. AAL 숫자만 있거나 복구 기록만으로는
부족하며 트랜잭션 안에서 기록·현재 AAL을 조회 시점 세션과 대조합니다.

신뢰한 운영자 회수를 포함해 active 요인을 회수하면 같은 트랜잭션에서
owner의 모든 live 세션을 종료하고 자격 세대를 올리며 handle·미소비 handoff
code를 회수합니다. 요인 상태·필수 감사도 함께 저장합니다. Pending 취소는
세션을 종료하지 않습니다. 종료 사유는 `factor_revoked`이며 active 해제 후에는
보수적으로 새 로그인을 요구합니다.

실제 저장소 회귀는 합성 session·factor 기록으로 조회 후 회수, 소유 요인 없는
AAL 거부, 권한 해제·session·handle·code 종료를 확인합니다. 강제 감사 실패는
요인 해제·세션·code 종료를 함께 롤백합니다. 네이티브 MFA 발급·브라우저
검증은 아닙니다. HTTPS·CSRF/Origin·등록 challenge binding·복구·UI·해제 전송,
OTP challenge·세션 승격 원자 처리·키 폐기 검사·Hangang 열린 stream 회수는
미완성입니다. 이번 변경으로 요인 HTTP route를 활성화하지 않습니다.

추가 네이티브 서비스 fixture는 실제 RFC 기반 OTP를 확인합니다. 잘못된 코드는
pending을 유지하고 올바른 코드는 owner 검사 아래 확인되며 반복 확인은 거부합니다.
Actor는 내부 fixture에서 구성하므로 브라우저 세션 발급·운영 MFA 검증은 아닙니다.

## 초기 등록 HTTP·portal 연결

Keyring 설정 시 `/security/totp`에 네이티브 영문·한국어 등록 화면·상태와 POST
준비·확인 route를 제공합니다. Keyring이 없으면 404입니다. HTTPS·최근 본인 portal
세션을 요구하며 준비·확인의 CSRF 목적을 구분해 handle에 묶습니다. Origin은
정확히 일치해야 합니다. Body·등록 ID 길이를 제한하고 필수 필드는 하나씩만
받으며 코드는 ASCII 6자리만 허용합니다. CSRF-valid 제출은 기존 프로세스별
IP 시도 예산을 사용합니다.

준비는 소유자 검사 commit 후에만 수동 인증 앱 설정 키를 표시합니다. URL·query·
감사·상태·후속 GET에 seed를 넣지 않고 완료 후 새로고침은 등록 상태를 보여줍니다.
No-store·기존 엄격 CSP·same-origin referrer 정책을 사용합니다. 실제 Chromium
form 실험에서 no-referrer는 Origin null을 만들고 same-origin은 CSRF에 필요한
정확한 Origin을 유지했습니다. 설정 키는 생성 응답·인증 앱에만 남으며 QR·
브라우저의 한 번 표시 보장·실제 모바일 앱 scan은 아직 검증하지 않았습니다.

소유한 OIDC 실제 프로세스 fixture가 로그인·암호화 등록 준비·표시 Base32에서
독립 코드 계산·실제 router·adapter·저장소 확인을 수행합니다. 익명·평문 HTTP·
Origin 누락·다른 CSRF 목적·반복 확인 거부, 로그·새로고침의 키 미노출,
AAL 1 세션 유지를 검사합니다. 권한 확인 요인 감사도 portal request ID를 사용합니다.

OTP 로그인·step-up·challenge와 세션 원자 승격은 활성화하지 않습니다.
계정·분산 시도 제한·완전한 브라우저 UI 검증·최근 인증 갱신 UX·취소·해제·복구,
QR·Hangang 메뉴·임베딩·키 폐기·내부 운영 배포는 남아 있습니다. 현재 내부
`owner-v5-d876909`는 keyring을 설정하지 않았고 새 HTTP route 이전 버전입니다.

## 네이티브 브라우저 TOTP 소스 갱신

[2차 인증 확장 계약](SECOND_FACTOR_EXTENSIONS.md#네이티브-브라우저-otp-흐름)에
keyring 설정·결합 챌린지와 CSRF·영속 설정 세대 검사·원자 교체·상승 핸드오프를
포함한 OTP 브라우저 흐름을 구현했습니다. 자체 OIDC·HTTP 프로세스로 보호 접근과
이전 자격 거절을 검증합니다. 이전 구현 기록은 과거 단계를 설명합니다.
외부 MFA API·Lua 커넥터를 활성화하거나 복구·키 수명주기·모바일·UI·fleet
검증을 대신하지 않으며 내부 이미지는 유지합니다.

미릴리스 `receipt_replay::consume`은 불투명한 검증 receipt, 신뢰된 네이티브 시계와 권한 fence를 받습니다. SQLite immediate transaction에서 DB registry revision·유효기간·저장된 clock watermark를 재검사하고 authority/용도/nonce hash를 한 번 소비한 뒤 호출자 DB 작업과 마지막 권한/만료 검사를 함께 commit합니다. 실패하면 작업·소비를 취소하고 마지막 시각에는 monotonic 작업 시간을 포함합니다. callback은 취소 불가능한 네트워크 출력·자격 노출을 성공한 commit 이후로 미뤄야 합니다.

소유자 meta의 nonce ID·정렬된 만료 인덱스를 사용해 호출마다 최대 128개 만료 쌍을 정리하며 counter 생성 후 전체 ledger를 scan하지 않습니다. 활성 100만 개 한계·인덱스 불일치는 거부합니다. clock floor는 정리 후 시계 역행 재사용을 막지만 DB 전체 복원에는 외부 epoch/최소 버전 fence가 필요합니다. receipt 테스트 12건은 중복 소비·작업 취소·작업 중 만료·정리/시계 역행·오래된 registry를 포함합니다. 운영에 활성화하거나 자격을 발급하지 않으며 전체 스택 성능 검증이 아닙니다.

receipt 동시성 검증은 독립 SQLite 연결 8개를 소비 전에 동기화해 정확히 한 호출만 commit하고 별도로 증가한 소유자 작업 counter도 1이며 DB 재연결 후 같은 receipt를 거부하는 것을 확인합니다. 마지막 권한 검사가 실패하면 nonce·작업을 취소하고 이후 허용된 재시도는 성공합니다. receipt 테스트 14건이 통과했으며 단일 소비 transaction 검증이지 다중 node membership·자격 endpoint 활성화·10k/100k 처리량 검증은 아닙니다.

호출자 작업과 마지막 권한 검사 이후, 만료 검사와 commit 직전에 DB registry revision을 다시 확인합니다. 작업 안에서 registry를 변경하는 회귀 테스트는 registry·nonce·관련 작업이 함께 rollback되고 정상 재시도는 성공함을 확인합니다. receipt 테스트 15건이 통과했습니다. 자격 endpoint 연결 전 소스 라이브러리 단계입니다.

## 인증된 자격 변환 증명 쌍 승인

미릴리스 `projection_admission`은 네이티브 키 registry로 두 receipt를 검증하고 신원 authority epoch·subject/종류/AAL·신원 revision/자격 generation·서비스·대상·정확한 요청 digest의 일치를 검사합니다. permit은 서명이 포함된 전체 인증 receipt의 SHA-256과 결합해야 합니다. issuer/key 선택은 용도별이며 다른 신원·요청의 정상 서명 permit도 승인되지 않습니다. 문맥은 검증된 네이티브 소유자에서 가져와야 하며 호출자가 제공한 분류 자체를 인증하지 않습니다.

필드가 비공개이고 Clone 불가능한 승인 객체는 두 nonce와 관련 DB 작업을 하나의 소유자 transaction에서 소비하며 DB registry·시각·마지막 권한 검사를 재사용합니다. 두 번째 nonce가 이미 소비됐거나 어느 receipt든 만료되면 전체 작업을 취소합니다. 독립 SQLite 연결 8개에서 정확히 한 증명 쌍만 승인되는 것을 포함해 새 공격 시나리오 테스트 4건과 인증 gateway 테스트 총 44건 및 fmt/clippy/경계 검사가 통과했습니다. 자격 endpoint·signer 서비스·운영 변환 경로는 아직 활성화하지 않았습니다. 실시간 신원/정책/네트워크/plan 검사는 호출자 guard의 책임이며 자격 노출은 commit 성공 이후여야 합니다.

## 네이티브 자격 변환 소스 코어

미릴리스 `projection::Projector`는 서비스/대상별로 중복 없는 참조 전용 plan 최대 128개를 컴파일합니다. 자원·행위·최소 AAL과 `identity_header` 또는 `bearer_reference`를 고정하며 임의 헤더·URL·인라인 비밀값은 허용하지 않습니다. 서명 검증된 승인 문맥에 자원/행위·plan 버전·두 receipt의 공통 유효 구간을 보존하고 plan 불일치는 자격 조회·nonce 소비 전에 거부합니다.

첫 실시간 소유자 검사 후 증명 쌍 소비 transaction 안에서 변환을 실행합니다. 네이티브 동기 resolver는 설정된 참조만 받으며 제한된 로컬 vault 접근을 사용해야 합니다. 길이가 제한된 RFC 6750 토큰 문법으로 헤더 주입을 막고 임시·반환 문자열은 drop 시 zeroize합니다. 마지막 권한/만료/registry 검사가 실패하면 출력 폐기와 두 nonce rollback을 수행합니다. 출력은 Clone·Debug·직렬화가 불가능하며 네이티브 서비스·대상·요청 digest·시각이 일치해야 sensitive HTTP 헤더로 변환됩니다. 헤더는 `x-hopae-subject` 또는 `authorization`으로 고정합니다. 권한 판정 전 일반 auth-proxy 응답 헤더 경로에는 이 값을 넣으면 안 됩니다.

새 테스트 5건은 마지막 권한 회수·resolver 장애/잘못된 토큰·오래된 plan/AAL/자원/행위·출력 대상/요청/시각 검사·제한된 참조 전용 설정을 확인합니다. 인증 gateway 테스트 49건과 fmt/clippy/경계 검사가 통과했습니다. 소스 코어 단계이며 관리자 게시/원자 활성화·발급 audit/outbox·네이티브 signer/endpoint 연결·Hangang 최종 집행/stream 회수·JWT/HMAC/mTLS 모드·분산/전체 스택 성능 검증은 남아 있습니다. 운영 설정과 이미지는 유지합니다.

## 영속 자격 변환 plan 소유자

미릴리스 `projection_authority`는 참조 전용 plan의 revision CAS·문서 digest·영속 비활성 tombstone·참조 전용 게시 audit을 하나의 immediate transaction에 저장합니다. 인증된 관리자 guard를 쓰기 전과 commit 전에 실행하며 마지막 문서 byte 검사로 guard 내부 변경도 거부합니다. 원하는 설정 버전은 다음 소유자 버전과 같아야 합니다. 제한된 로딩에서 설정/digest·외부 최소 버전을 검증하고 저장된 비활성화를 시작 설정으로 덮어쓰지 않습니다.

단독 소유자는 컴파일된 Arc를 commit 전에 준비하고 성공 직후 실패 가능한 작업 없이 설치합니다. 공유 ArcSwap reader는 불변 projector에서 서비스/대상을 조회합니다. 증명 쌍 승인 시 작업 전후에 cached SQLite statement로 현재 DB 문서 byte를 빌려 정확히 비교하며 요청 경로에서 JSON decode·plan 재컴파일·임시 문서 할당을 하지 않습니다. 따라서 DB 교체/비활성화 뒤 예전 snapshot을 보유한 요청도 commit/install 구간을 포함해 자격을 조회하지 못합니다. 여전히 DB를 사용하는 승인 단계이며 10k/100k 처리량·분산 membership 검증은 아닙니다.

테스트 5건은 재시작/비활성화/최소 버전·오래된 별도 게시자·관리자/audit 실패 시 DB와 메모리 유지·손상/버전 불일치·이전 reader 거부와 재활성화 후 새 서명 permit·마지막 guard의 plan 변경과 nonce 전체 rollback을 확인합니다. 애플리케이션 시작·위임 관리자 endpoint/UI·발급 audit/outbox 연결은 남아 있으며 운영 상태는 유지합니다.

이 소스 갱신의 인증 gateway 테스트 총 54건과 fmt/clippy/경계 검사가 통과했습니다.

## 애플리케이션 시작과 보호된 plan 관리

미릴리스 소유자를 readiness 전에 로드해 Services·AdminState에 유지합니다.
시작 선언의 버전 1 plan은 DB 소유자 row가 없을 때만 가져오고 DB 상태/비활성
tombstone을 우선합니다. 시작·게시 시 선언된 서비스/대상/자원/행위/자격 방식·
참조와 최소 AAL을 검사합니다. 보호된 참조 전용 GET/PUT·서명된 Hangang 게시
변환은 네이티브 관리자·CSRF·replay·마지막 관리자 검사를 재사용합니다.
[설정 문서](CONFIG.md#자격-변환-plan-미릴리스)에 필드·버전 동작을 기록합니다.
실제 Hopae HTTP 프로세스로 viewer 거부·CSRF·필수 버전·잘못된 capability·
오래된 쓰기·재시작 후 비활성/재활성화를 확인합니다. 소스의 plan 소유권/관리
연결이며 gateway 자격 발급 활성화는 아닙니다. 운영 배포·위임 모듈 UI는 남아
있습니다.

시작/관리자 연결 갱신의 전체 target 네이티브 테스트는 898건 통과·42건 제외이며
fmt/clippy/경계/문서/시나리오 커버리지도 통과했습니다. 의존성 감사는 기존
검증 전용 RSA 예외와 rustls-pemfile 유지보수 중단 허용 경고 아래 통과한 것으로
제약 없는 clean audit은 아닙니다. 서명 위임 projection 조회/게시에는 replay·
오래된 버전·네이티브 grant 회수 검증을 포함합니다. 불변 v0.0.3 릴리스 자산과
운영 이미지는 유지합니다.

## 콘솔 패키지 0.1.5 자격 변환 관리

Hopae Hangang 패키지에 자격 변환 탭을 추가해 서비스/대상/자원/행위/AAL/자격
참조를 텍스트 전용 표로 요약하고 JSON 편집기를 제공합니다. viewer는 편집/게시가
불가능합니다. 저장 시 다음 설정 버전을 부여하고 조회한 소유자 버전을 함께
전달하며 충돌하면 편집 내용을 유지합니다. 명시적 null은 전체 비활성화입니다.
manifest에 참조 전용 GET·변경 POST 게시 경로를 선언합니다. 실제 Chromium에서
영문 관리자/한국어 viewer·악성 텍스트·JSON 오류 시 게시 거부·충돌 내용 유지·
정상 버전 부여/비활성화·viewer 검사를 확인했고 기존 프로필 화면도 통과했습니다.
패키지 소스 검증은 운영 배포·자격 발급 검증을 대신하지 않습니다.

내부 dogfooding은 `hopae:0.0.3-projection-1319351`·hash pin된 콘솔 패키지
0.1.5를 사용합니다. 최적화 정적 후보는 소유자 DB 복사본에서 projection
bootstrap readback·기존 서비스 HTTP/pooled mTLS·실제 Chromium 외부 MFA/TOTP를
검증합니다. 운영 API/매트릭스/모듈/SSO/네이티브 회귀와 실제 Hangang 브라우저
프로필/자격 변환 탭이 통과했습니다. 기존 운영 설정·키는 보존하고 자격 변환은
미설정/비활성입니다. 운영 브라우저 검증은 게시 없이 소유자 문서/버전을
보존합니다. 정지 상태의 일관된 소유자/위임 DB 백업·이전 이미지·플러그인
registry 백업을 유지합니다. Rust 소스는 898건 통과·42건 제외로 검증한 갱신과
동일합니다. 관리자 경로 dogfooding이며 자격 발급·처리량 검증은 아닙니다.
불변 태그 릴리스 자산은 유지합니다.

## 네이티브 세션 receipt 발급 소스

검증 엔진은 성공한 human 신원에 비공개 seal을 결합합니다. 검증된 서비스·
user/session/provider ID·인증 시각·만료·AAL·user/session/config generation·
검증 시각을 domain 분리·길이 prefix SHA-256으로 결합합니다. 공개 생성자·
serde/Clone 경로가 없으며 발급에 쓰는 공개 신원 필드를 바꾸면 seal 검사가
실패합니다. email/groups/display는 receipt claim이 아닙니다. 기존 gateway
응답 wire 동작은 유지합니다.

미릴리스 `receipt_issuer::Issuer`는 인증 전용 Ed25519 signer·고정 issuer/key/
신원 epoch·공개키 pin·선언된 서비스/대상 쌍 최대 128개·네이티브 clock/RNG를
보유합니다. 미선언 대상은 소유자 검사/서명 전에 거부합니다. 컴파일된 scope를
빌려 조회하고 발급 출력은 불변 signer metadata를 Arc로 공유해 scope 목록을
복사하지 않습니다. 소비한 seed buffer와
signer 자료는 zeroize합니다. 네이티브 seal·실시간 소유자 검사를 거쳐 검증된
신원에서 principal/AAL/revision을 가져오고 nonce를 생성한 뒤 마지막 소유자/
시각 검사를 반복합니다. lease는 신원 만료·검증 후 1초보다 길지 않고 config
generation을 신원 epoch에 포함합니다. monotonic 작업 시간과 프로세스 내
clock watermark로 만료/시계 역행을 검사합니다. 출력은 Clone/Debug/직렬화가
불가능하며 일반 auth 응답 헤더에 자동으로 들어가지 않습니다.

실제 SQLite 검증 엔진 시나리오에서 receiver key registry로 서명을 확인하고
서비스/user/session/provider/인증 시각/만료/AAL/generation 변경·공개키 pin
불일치·마지막 소유자 거절·작업 중 만료·시계 역행을 거부합니다. 소스의 서명
연결이며 RPC 발급 활성화는 아닙니다. 실시간 session/handle/user/provider/
config/key epoch 검사는 발급 guard의 책임입니다. 영속 signer/key 게시·
재시작/분산 시각 floor·service/workload 발급·인증된 전송 연결은 남아 있습니다.

검증: 전체 target gates는 899건 통과·42건 제외이며 마지막 불변 metadata
공유 개선 후 실제 발급 시나리오와 전체 target fmt/clippy/경계 검사도
통과했습니다. 문서/시나리오 커버리지 검사가 통과하며 의존성 감사는 기존
검증 전용 RSA 예외·rustls-pemfile 허용 경고를 적용합니다. 이 소스는 배포하지
않았고 내부 이미지는 projection-1319351입니다. 인증된 adapter는 네이티브
route에서 정확한 요청/서비스/대상을 가져오고 애플리케이션/경로별 인증 수준과
실시간 소유자 상태를 재검사해야 합니다. 비공개 신원 seal은 원래 인증 metadata
검증이지 권한 허용·요청 분류·분산 최신성 보장은 아닙니다.

## 프로필 소유 서비스 receipt 발급과 회수 검사

`Snapshot::authenticate_for_receipt`는 자체 key·설정된 relay 검증 후 비공개·
Clone/serde 불가능한 ServiceAuthentication을 반환합니다. 버전은 요청 필드가
아닌 소유자 snapshot에서 가져옵니다. `Issuer::issue_service`는 Service
evidence만 받아 AAL 0을 고정하고 설정된 서비스/대상·evidence 만료/검증 시각에
결합합니다. 프로필 버전을 신원 revision/자격 generation과 서비스 전용 신원
epoch에 사용합니다. 기존 gateway 헤더와 canonical subject hash를 공유해
자체/relay namespace 구분을 유지합니다. 실시간 signer guard는 현재 프로필/
key 소유권·애플리케이션/경로 인증 수준·네트워크를 재검사해야 하며 자료 교체 시
소유자 프로필 generation도 갱신해야 합니다. workload/network 발급은 미지원입니다.

새 게시 fence는 DB 게시 전 reader를 unavailable로 만들고 commit/install
구간을 포함해 유지한 뒤 미리 할당한 불변 snapshot을 활성화합니다. 실패한
게시에서는 이전 상태를 교체하지 않고 availability를 복원합니다. gateway
서비스 인증은 작업 전 availability·작업 후 현재 snapshot 동일성을 검사하며
이전 relay 결과는 신원 헤더·session fallback 없이 거부합니다. 요청마다 DB를
조회하지 않고 atomic 상태·Arc 동일성을 검사합니다. 영속/분산 최신성은 signer
guard가 별도로 검사해야 합니다.

발급 테스트 3건은 자체/혼합 relay 서명·Service/AAL0·만료 한계·namespace
구분·거짓 MFA 응답 거부·범위/종류 거부·회수·마지막 guard·역행을 검증합니다.
게시 테스트는 transaction fence·실패 후 복원을 확인하고 제어된 HTTP/네이티브
adapter 테스트는 원격 verifier 대기 중 프로필을 회수해 신원 헤더 없는 503을
요구합니다. 인증 gateway 테스트 58건·네이티브 human 발급 회귀·fmt/clippy/
경계 검사가 통과했습니다. 전체 운영 반영 검증은 별도입니다.

이 갱신의 전체 네이티브 gates는 904건 통과·42건 제외이며 fmt/clippy/경계/
문서/시나리오 커버리지·기존 제한된 의존성 감사 정책(검증 전용 RSA 예외·
rustls-pemfile 유지보수 중단 경고)도 통과했습니다. receipt RPC 활성화는
남아 있으며 gateway 회수 fence는 기존 서비스 인증에도 독립적으로 적용됩니다.

내부 dogfooding은 `hopae:0.0.3-service-fence-ec1ed5d`와 기존 pin된 콘솔
패키지 0.1.5를 사용합니다. 최적화 DB 복사본 bootstrap/HTTP/pooled mTLS/
Chromium MFA/TOTP·운영 API/매트릭스/모듈/SSO/네이티브/브라우저 회귀가
통과했습니다. 운영 설정/키를 보존하고 변환은 비활성이며 receipt RPC는
활성화하지 않습니다. 정지 상태의 일관된 소유자/위임 DB 백업·이전
projection-1319351 이미지를 유지합니다. 제어된 회수 race는 네이티브
테스트로 검증했으며 운영 smoke는 프로필을 변경하거나 분산/fleet 동작을
증명하지 않습니다. 태그 릴리스 자산은 유지합니다.

네이티브 Kubernetes Pod-bound 인증을 참조형 프로필과 HTTP/HOP1 회수 검사에 연결했습니다. [워크로드 계약](KUBERNETES_WORKLOAD.md)을 참고하십시오. 실제 클러스터 활성화·워크로드 receipt 발급은 아직 남았습니다.

## 서비스 커넥터 관측 (미릴리스)

인증된 `GET /v1/status`에 `authentication_gateway`를 추가합니다. 소유자 리비전·
게시 중 가용성·활성 여부와 제한된 커넥터 관측을 제공합니다. 각 행은 서비스 ID·
커넥터 종류·커넥터 서킷 상태·현재 잔여 처리 용량만 포함합니다. 같은 profile의
여러 포트는 한 행으로 표시합니다. 자격 참조/값·신원·검증 URL·목적지는 노출하지
않습니다. 소유자가 사용 중이거나 사용할 수 없으면 null이며 정상 서킷의 근거가
아닙니다. 콘솔 상태 화면은 조회만 하며 서킷을 초기화하지 않습니다.

서비스 커넥터 서킷의 관측이며 하위 HTTP origin·사람의 공급자 서킷 전체를 포함하지
않습니다. 상태는 즉시 바뀔 수 있고 요청을 허가하거나 인증 근거 수명을 연장하지
않으며 조회 중 공급자 네트워크 호출을 하지 않습니다. 서명 기반 자격 변환의 실제
요청 전달은 아직 별도 통합 과제이며 상태 조회로 활성화되지 않습니다.

## 공용 네이티브 요청 바인딩 계약 (미릴리스)

공급자와 독립된 `hopae-grpc` 계약 crate에서
`request_binding::{Request, digest, InvalidRequest}`를 제공합니다. 호패는 같은
구현을 재노출하며 소비자는 고정 계약을 정적으로 링크해 해시 규칙 복제를 피합니다.
고정 digest 벡터·필드 경계·메서드/본문/경로/쿼리 변경·잘못된 origin-form 거부
검사의 의미는 유지됩니다. 요청 바인딩의 일치만 제공하며 신원 인증·권한 발행·
자격 변환 RPC를 활성화하지 않습니다. 한강은 클라이언트 주장 대신 실제 최종
전달 요청의 문맥을 공급해야 합니다.

## 공용 receipt 암호 구현 (미릴리스)

공급자와 독립된 계약은 기존 146-byte v1 receipt의 `receipt` 암호 구현도
제공합니다. 도메인을 분리한 Ed25519 서명·엄격한 검증·용도/바인딩/nonce 검사와
최대 1초 수명을 유지하며 호패는 같은 구현을 재노출합니다. 바인딩 비교는
상수 시간입니다. 발행자/키 선택·최신 소유자 상태 검사·원자적 재사용 방지는
전송 계층으로 옮기지 않습니다. 서명 검증만으로 권한이나 upstream 자격을
제공하지 않습니다. 계약 검사와 소유자 승인 회귀 검사 10개가 통과했습니다.
이 분리로 receipt RPC나 실제 자격 전달을 활성화하지는 않습니다.

같은 계약이 `PrincipalKind`와 `receipt_binding` 문맥/타입도 소유합니다. 네이티브
신원·키 세대·서비스/대상/요청 범위와 권한 체인의 소유자 리비전을 포함하며 호패는
변환 계층 없이 재노출합니다. 기존 인증/권한 고정 벡터와 모든 필드 검사를 유지하고
순수 계약 검사 7개·소유자 키/발행/재사용 검사 13개가 통과했습니다. 타입은 주장을
표현할 뿐이므로 원천 인증·고정된 최신 키 선택·현재 소유자/재사용 검사는 계속
필요합니다. 이 소스 분리로 전송이나 자격 전달을 활성화하지 않습니다.

## 네이티브 서비스 인증→receipt 어댑터 (미릴리스)

`Issuer::authenticate_service_and_issue`는 불변 소유자 reader에서 실제 profile
인증을 서명에 연결합니다. 인증 전 설정된 서비스/대상을 검사하고 필수 네이티브
guard가 호출자/경로 권한을 확인합니다. guard 작업과 서명 전후 동일 활성 snapshot·
게시 가용성을 검사합니다. 신원 근거는 profile 소유자가 생성하며 서비스 AAL 0과
제한된 인증 근거 만료를 유지합니다.

실제 소유자/자체 key로 검증 가능한 receipt를 발행하고 마지막 guard에서 게시
가용성을 바꾸는 검사가 통과했습니다. 변경된 소유자에서는 receipt를 반환하지
않습니다. 기존 범위·만료·시계 후퇴·혼합 namespace 검사도 통과했습니다.
아직 RPC 경로를 활성화하지 않았으며 peer 인증·설정된 발행자 자원·요청 문맥
구성·분산 수신자의 최신 상태·권한/자격 변환 전송은 후속 연결 과제입니다.

## 단일 인증의 내부 게이트웨이 근거 전달 (미릴리스)

네이티브 발행자 자원이 설정되면 기존 게이트웨이 파이프라인은 검증한 서비스 인증을
불투명한 프로세스 내부 응답 확장 값으로 보존합니다. 일반 HTTP 헤더/본문·HOP1
응답으로 직렬화하지 않습니다. 호출자 인증·profile 신선도·애플리케이션/step-up
거부는 기존 경로를 따르며 발행자 설정이 없으면 일반 경로를 유지합니다. 후속
receipt RPC는 두 번째 외부 검증 호출 없이 이 근거를 소비할 수 있습니다.

`CapturedService::issue`는 네이티브 guard 전후 정확한 profile·검증한 애플리케이션
snapshot을 검사합니다. 숫자 세대가 같아도 애플리케이션 snapshot을 교체하면
발행을 거부합니다. 실제 프로세스 내부 라우터 검사는 인증된 내부 근거·receipt
헤더/본문 부재·거부된 호출자의 근거 부재를 확인했습니다. 서명 검사에서 근거
재사용과 애플리케이션 교체 거부를 확인했습니다. RPC·사람/워크로드 발행·권한
근거·upstream 자격 전달 연결은 아직 남아 있습니다.
