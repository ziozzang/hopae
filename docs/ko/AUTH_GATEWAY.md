# 서비스 인증 게이트웨이

<!-- translation-status: source=../AUTH_GATEWAY.md source-rev=1 status=current -->

[문서](README.md) · [English](../AUTH_GATEWAY.md) · [네이티브 통합](HANGANG_NATIVE.md)

첫 런타임 connector는 선택적인 IP 조건과 함께 서비스 API 키를 인증합니다.
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
`s_…` 신원을 출력합니다. `x-hopae-principal-kind: service`와 `x-hopae-aal: 0`을
출력하며 사람 계정·검증된 이메일·MFA를 만들지 않습니다. 응답에는 credential이
없고 `Cache-Control: no-store`를 적용합니다. 인증은 서비스 권한 부여가 아니므로
Hangang/품계가 서비스 매트릭스를 집행해야 합니다. Parent의 비인간 assurance
처리와 credential 소비/변환은 후속 작업이며 완성된 전체 서비스 권한 흐름으로
취급하지 않습니다.

LDAP·자체 사람 비밀번호·원격 API 릴레이/introspection·실제 connector 관계의
Any/All 결합·upstream credential 변환·전체 credential 수명주기·전체 스택 100k QPS
검증은 남아 있습니다. 기존 OIDC 서킷은 provider 네트워크 호출을 보호하며
인메모리 API 키 connector에는 서킷을 적용할 원격 백엔드가 없습니다.
