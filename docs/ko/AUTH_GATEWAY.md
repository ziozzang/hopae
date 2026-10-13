# 서비스 인증 게이트웨이

<!-- translation-status: source=../AUTH_GATEWAY.md source-rev=3 status=current -->

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
