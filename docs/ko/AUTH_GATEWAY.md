# 서비스 인증 게이트웨이

<!-- translation-status: source=../AUTH_GATEWAY.md source-rev=9 status=current -->

[문서](README.md) · [English](../AUTH_GATEWAY.md) · [네이티브 통합](HANGANG_NATIVE.md)

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

`tools/service_stack_smoke.py`는 mTLS HOP1/PPG1의 실제 격리된 세 프로세스를
실행합니다. 인증·IP/등급/메서드 권한·미등록/잘못된 credential 거부·gateway 설정을
다시 쓰지 않는 영속 권한 회수/복원·서비스 간 격리·credential 소비·품계 장애 시
거부를 검증합니다. 수문장은 이 fixture 밖에 있으며 전체 스택 처리량 측정이 아닙니다.
운영 배포와 기존 스트림 credential 회수를 포함한 전체 수명주기는 별도 작업입니다.

LDAP·자체 사람 비밀번호·표준 introspection adapter·실제 connector 관계의
Any/All 결합·upstream credential 변환·전체 credential 수명주기·전체 스택 100k QPS
검증은 남아 있습니다. 기존 OIDC 서킷은 provider 호출을 보호하고 외부 verifier 릴레이에도 범위가
정해진 서킷을 적용합니다. 인메모리 API 키 connector에는 원격 백엔드가 없습니다.

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
