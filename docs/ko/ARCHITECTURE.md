# 아키텍처

<!-- translation-status: source=../ARCHITECTURE.md source-rev=8 status=current -->

[문서 목차](README.md) · [English](../ARCHITECTURE.md)

Hopae는 게이트웨이의 포워드 인증 확인에 답하는 단일 바이너리 ID 제공자입니다.
이 페이지는 마일스톤 M0과 M1이 구축하는 구성 요소, 신뢰 경계, 요청 흐름,
데이터 모델, 저장소, 크레이트 구성, 장애 시 동작을 설명합니다. 결정은
[ADR](../adr/)에 기록하고, 게이트웨이와의 전송 계약은
[게이트웨이 계약](GATEWAY_CONTRACT.md)에, 위협과 완화책은
[위협 모델](THREAT_MODEL.md)에 있습니다. *나중에*로 표시한 절은 이후
마일스톤이 채워 넣을 형태를 설명하며, 데이터 모델은 아무것도 뜯어고치지 않도록
지금 그 마일스톤들을 위해 설계되어 있습니다.

## 사전 요구 사항과 설정

| 항목 | M1 요구 사항 |
| --- | --- |
| 게이트웨이 | `forward_response`가 `true`이고 정적 요청 헤더로 호출자 키를 실어 보내는 외부 인가 라우트(`auth`)를 가진 Hangang(게이트웨이 변경 HC-3, M1과 함께 구현). 정확한 라우트 조각은 [게이트웨이 계약](GATEWAY_CONTRACT.md)을 참고하세요 |
| 호출자 키 | 게이트웨이 라우트와 Hopae가 공유하는 무작위 비밀. `gateway.caller_key_env`로 참조하며, 모든 verify 호출은 이를 `x-hopae-gateway-key`에 실어야 합니다 |
| 포털 호스트 | 로그인 포털 전용 호스트 이름(예제에서는 `auth.example.test`). 같은 게이트웨이의 공개 라우트로 제공됩니다 |
| 전송 | 브라우저와 게이트웨이 사이는 HTTPS. 게이트웨이가 TLS를 종단하며, Hopae의 게이트웨이 리스너는 게이트웨이의 네트워크 네임스페이스(기준 배포에서는 호스트 루프백)에서만 접근할 수 있고 그래도 호출자 키를 요구합니다 |
| 기본 저장소 | 쓰기 가능한 상태 디렉터리의 SQLite 파일(기본값). M2부터 다중 인스턴스 배포에는 PostgreSQL([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |
| Redis/Valkey | M2부터 선택 사항으로, 무효화 채널과 시도 차단 카운터에만 사용합니다. 세션 상태나 결정 상태는 절대 보관하지 않습니다 |
| 제공자 | 환경에서 읽는 클라이언트 ID와 클라이언트 비밀을 가진 OIDC 제공자 하나(M1에서는 Google) |

Hopae는 JSON 파일 하나([설정 참조](CONFIG.md) 참고. YAML은 지원하지 않습니다)와
비밀 정보용 환경 변수로 설정합니다. 모든 설정 키는 시작 시와
`hopae --check`에서 검증하며, 알 수 없는 키는 거부합니다.

## 구성 요소

```text
                       ┌──────────────────────────── 신뢰 경계: 공개 인터넷 ──────────────────┐
   브라우저 ───HTTPS──▶│ 게이트웨이(Hangang)                                                │
                       │  라우트 app.example.test  ──auth──▶ GET http://hopae:8701/_hopae/verify │
                       │  라우트 other.example.org ──auth──▶ (동일)                           │
                       │  라우트 auth.example.test ──proxy─▶ http://hopae:8700/ (포털)        │
                       └────────────────────────────────────────────────────────────────────┘
                                   │ 사설 네트워크 / 루프백 (신뢰 경계: 게이트웨이 ↔ Hopae)
                       ┌───────────┴────────────────────────────────────────────────────────┐
                       │ Hopae 프로세스                                                     │
                       │  포털 리스너 :8700   게이트웨이 리스너 :8701   관리 리스너 :8702      │
                       │  ┌────────┐ ┌────────┐ ┌─────────┐ ┌────────┐ ┌───────┐ ┌───────┐  │
                       │  │ portal │ │ verify │ │ session │ │identity│ │policy │ │ event │  │
                       │  └────────┘ └────────┘ └─────────┘ └────────┘ └───────┘ └───────┘  │
                       │  ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌──────┐ ┌─────┐ │
                       │  │ provider │ │ gateway  │ │ factor  │ │ store  │ │cache │ │ lua │ │
                       │  │ (oidc…)  │ │ adapter  │ │ (M5)    │ │sqlite/ │ │redis │ │(M5) │ │
                       │  └──────────┘ └──────────┘ └─────────┘ │postgres│ └──────┘ └─────┘ │
                       │                                        └────────┘                  │
                       └──────────┬───────────────────────────────┬─────────────────────────┘
                                  │ HTTPS (아웃바운드만)            │ 사설 네트워크
                                  ▼                               ▼
                         ID 제공자                          SQLite 파일 / PostgreSQL / Redis
                         (Google, Kakao, Naver, SMTP)
```

| 구성 요소 | 책임 | 마일스톤 |
| --- | --- | --- |
| 포털 | 로그인 선택 화면, 제공자 리디렉션, 제공자 콜백, 단계 상승 페이지, 로그아웃 확인, 상태 확인. 포털 호스트에서만 제공합니다. | M1 |
| Verify | 게이트웨이의 확인에 답합니다: 쿠키 핸들 → 세션 → 바인딩 정책 → 애플리케이션 정책 → 단계 상승 규칙 → 신원 헤더. 이 경로에서는 제공자를 호출하지 않습니다. | M1 |
| 게이트웨이 어댑터 | 게이트웨이의 전송 형식(헤더, 상태 코드, 쿠키)을 핵심 결정 타입으로, 그리고 그 반대로 변환합니다. M1에서는 Hangang 어댑터. 범용 포워드 인증 어댑터와 OIDC 제공자 어댑터는 *나중에*([ADR-0013](../adr/0013-gateway-adapter-boundary.md)). | M1 |
| 세션 | 세션, 호스트별 핸들, 로그인 트랜잭션, 핸드오프 코드, 수명, 취소, 모든 기기에서 로그아웃. | M1 |
| 신원 | 사용자, 제공자 신원, 연결 정책, 그룹. | M1(연결은 M3) |
| 정책 | 애플리케이션(호스트), 바인딩 정책, 수명, 단계 상승 요구 사항, 차단(M2), 경로 규칙(M2). | M1 |
| 제공자 | `Provider` 트레이트. 범용 OIDC 클라이언트(PKCE, nonce, 디스커버리, JWKS 캐시). Kakao, Naver, 이메일 매직 링크, 비밀번호는 *나중에*. | M1(나머지는 M3) |
| 이벤트 | 상태 변경과 함께 커밋되는 타입이 있는 이벤트와 구독 싱크마다 하나씩의 전달 행. 싱크: 구조화 로그, 웹훅은 *나중에*. `event_id`로 중복을 제거하는 최소 1회 전달. | M1(웹훅은 M5) |
| 인증 요소 | 2차 인증 요소를 위한 `Factor` 트레이트. TOTP, WebAuthn, 복구 코드는 *나중에*. 세션 스키마는 M1부터 충족한 요소를 기록합니다. | M5(스키마는 M1) |
| 저장소 | `Directory`, `Sessions`, `Events` 트레이트. SQLite 백엔드(M1), PostgreSQL 백엔드(M2). 내장 마이그레이션. | M1 |
| 캐시 | 세대 출처 정보를 담은, 권위 있는 읽기의 옵트인 제한 로컬 캐시. Redis/Valkey는 pub/sub 무효화와 제한 카운터 전용(세션 상태는 절대 아님)으로 *나중에*. | M2 |
| Lua | 게이트웨이의 모델을 복제한 샌드박스 워커 프로세스는 *나중에*. | M5 |
| 관리 | 관리 리스너의 콘솔 페이지와 `/v1` API: 자체 호스트의 Hopae 애플리케이션으로, 암묵적 애플리케이션 `admin`으로 등록되고 요청마다 verify 엔진을 통한 세션 핸들과 `admin_grants` 행으로 인증됩니다. 사용자, 세션, 로그인 기록과 감사, 읽기 전용 상태([관리](ADMIN.md), [ADR-0016](../adr/0016-management-console-minimum.md)). 제공자와 애플리케이션 관리는 *나중에*. | M4-min(나머지는 M4) |
| 업데이트 | 서명된 자가 업데이트는 *나중에*. | M6 |

## 신뢰 경계

| 경계 | 무엇이 넘어가는가 | Hopae가 신뢰하는 것 | Hopae가 절대 신뢰하지 않는 것 |
| --- | --- | --- | --- |
| 브라우저 ↔ 게이트웨이 | 쿠키가 담긴 HTTPS 요청, 리디렉션, 제공자 왕복 | 아무것도 없음. 모든 브라우저 입력을 검증합니다. | 브라우저가 보낸 `x-forwarded-*`, `x-original-*`, 신원 헤더, 핸드오프 매개변수. 게이트웨이가 제거하거나 다시 생성합니다([계약](GATEWAY_CONTRACT.md#수정하지-않은-hangang-026에서-동작하는-것)). |
| 게이트웨이 ↔ Hopae 게이트웨이 리스너 | 게이트웨이가 생성한 맥락 헤더, 나열된 클라이언트 헤더, 호출자 키를 가진 verify 요청 | 게이트웨이가 생성한 맥락(`x-original-url`, `x-forwarded-for`, `x-forwarded-host`, `x-forwarded-proto`)은 `x-hopae-gateway-key`가 `gateway.caller_key_env`와 상수 시간 비교로 일치한 **뒤에만** 신뢰합니다. 키가 없는 요청은 어떤 상태도 건드리지 않습니다. 네트워크 격리는 심층 방어일 뿐 경계가 아닙니다: 호스트 네트워크 게이트웨이에서는 어떤 로컬 프로세스든 루프백에 접근할 수 있습니다. | 복사된 클라이언트 헤더(`cookie`, `user-agent`, `sec-fetch-*`)는 검증할 입력이지 단언이 아닙니다. 호스트 중립 라우트에서는 `x-original-url`의 authority를 클라이언트가 고르므로 돌아갈 출처 허용 목록과 대조합니다. |
| 게이트웨이 ↔ Hopae 포털 리스너 | 포털 호스트로 일반 프록시된 요청 | 설정된 `trusted_proxies`에서 온 `x-forwarded-for`와 `x-forwarded-proto`만 | 그 외 모든 것은 브라우저 입력이며 모든 `x-original-*` 헤더도 포함됩니다. 게이트웨이는 `x-forwarded-*`는 다시 생성하지만 외부 인가가 없는 라우트에서는 `x-original-*`를 그대로 통과시킵니다. |
| Hopae ↔ ID 제공자 | 디스커버리, JWKS, 토큰 교환, 사용자 정보(아웃바운드 HTTPS만) | 완전한 검증을 거친 제공자의 서명된 ID 토큰. 제공자별 규칙에 따른 사용자 정보 필드([ADR-0010](../adr/0010-provider-abstraction.md)) | 서명되지 않은 클레임, 검증 플래그 없는 이메일 주소, 콜백 쿼리의 `code`와 `state` 이외의 모든 것. |
| Hopae ↔ 저장소 | 사설 네트워크의 SQL과 Redis 프로토콜 | 기본 저장소의 내용. 모든 verify가 이를 읽습니다 | Redis. 무효화 메시지와 카운터만 실어 나르고 세션이나 결정 상태는 절대 보관하지 않으므로, 오래된 Redis 응답이 접근을 넓힐 수 없습니다. 로컬 캐시는 권위 있는 읽기의 마감과 세대가 현재일 때만 항목을 제공합니다. |
| Hopae ↔ Lua 워커(M5) | 파이프를 통한 길이 프레임 JSON | 아무것도 없음. 출력은 네트워크에서 온 것처럼 검증합니다 | 스크립트. 네트워크, 비밀 정보, 파일 시스템이 없습니다. |
| 게이트웨이 ↔ Hopae 관리 리스너(M4-min) | 게이트웨이의 보호 라우트가 자체 verify 호출 뒤에 프록시한 콘솔 호스트 요청: 핸들 쿠키, 전달 헤더, 주입된 신원 헤더 | verify 엔진이 평가한 콘솔 호스트의 `__Host-hopae` 핸들과 사용자의 `admin_grants` 행(둘 다 요청마다 읽음). `x-forwarded-for`와 `x-forwarded-proto`는 `trusted_proxies`에서만, 그것도 클라이언트 바인딩에만 | 주입된 신원 헤더와 그 밖의 모든 게이트웨이 맥락 헤더(절대 읽지 않음). 요청의 출처: 게이트웨이를 우회한 연결은 유효한 콘솔 핸들 없이는 아무것도 얻지 못합니다([관리](ADMIN.md)). |

게이트웨이 리스너와 포털 리스너는 라우터가 서로 겹치지 않는 별도의 TCP
리스너입니다. 포털 리스너의 `GET /_hopae/verify`는 404로 답하고, 게이트웨이
리스너에는 포털 페이지가 존재하지 않습니다. 게이트웨이 리스너는 공개
인터넷에서 접근할 수 없어야 합니다. 기준 게이트웨이가 호스트 네트워크로
동작하므로 배포 템플릿은 Hopae를 같은 네트워크 네임스페이스(`network_mode:
host`)에서 `127.0.0.1:8701`에 바인딩하거나, 컨테이너 포트를 호스트 루프백에만
공개합니다(`127.0.0.1:8701:8701`). 컨테이너 내부 루프백에 바인딩하면
게이트웨이가 접근할 수 없습니다. 어떤 구성에서든 호출자 키는 필수입니다.
관리 리스너(M4-min)는 자체 라우터를 가진 세 번째 리스너로 `admin.public_url`이
설정된 때만 바인딩합니다. 게이트웨이의 보호 라우트 뒤에서 콘솔 호스트를 제공하고
자신의 요청을 핸들로 인증하므로 호출자 키가 필요 없고, 우회 연결이 덧붙일 수
있는 어떤 것도 신뢰하지 않습니다([관리](ADMIN.md)).

## 요청 흐름

표기 규칙: `GW`는 게이트웨이, `HP`는 Hopae, `IdP`는 ID 제공자입니다. `txn`은
로그인 트랜잭션 ID, `code`는 일회용 핸드오프 코드, `handle`은 한 호스트의
불투명 쿠키 값, `bind`는 로그인이 시작될 때 애플리케이션 호스트에 심는
브라우저 바인딩 쿠키입니다. 모든 verify 호출은 `x-hopae-gateway-key`도
함께 실어 보내지만 다이어그램에서는 생략합니다. 신원 헤더는 `[id-hdrs]`로
줄여 씁니다. 포털 호스트는 `auth.example.test`, 애플리케이션 호스트는
`app.example.test`와 `other.example.org`(다른 등록 도메인)입니다.

### 흐름 1 — 첫 방문, 미인증

```text
 브라우저                      GW                                 HP
   │ GET https://app.example.test/admin/x                         │
   ├────────────────────────────▶│ GET /_hopae/verify              │
   │                             │  cookie: (없음)                 │
   │                             │  x-original-url: https://app.example.test/admin/x
   │                             │  x-forwarded-for: 203.0.113.9   │
   │                             │  sec-fetch-dest: document       │
   │                             ├────────────────────────────────▶│ 핸들 없음 → txn 생성
   │                             │ 302 Location: https://auth.example.test/login?txn=T
   │                             │ Set-Cookie: __Host-hopae_bind=B (앱 호스트; 이미 있으면 유지)
   │                             │ Cache-Control: no-store         │ (txn: 대상, 호스트, ip, ua, H(B))
   │ 302 (중계됨, forward_response)◀────────────────────────────────┤
   │◀────────────────────────────┤                                 │
```

문서 탐색이 아닌 요청(`sec-fetch-dest`가 `document`가 아니거나 `accept`에
`text/html`이 없는 경우)은 `login` 필드가 애플리케이션 URL 자체인 JSON
본문과 함께 `401`을 받습니다. 그 URL을 문서 탐색으로 열면 바인딩 쿠키를 심고
트랜잭션을 시작하는 부트스트랩이 됩니다. `401`은 트랜잭션을 만들지도 쿠키를
설정하지도 않으며, `forward_response`가 켜져 있으므로 게이트웨이는 `401`을
중계합니다.

### 흐름 2 — 포털에서 로그인

```text
 브라우저                      GW                   HP(포털)                        IdP
   │ GET auth.example.test/login?txn=T                 │                              │
   ├───────────────────────────▶├─────────────────────▶│ txn 유효, 만료 아님           │
   │                            │                      │ Set-Cookie: __Host-hopae_portal=P (안정적; txn에 H(P) 저장)
   │ 200 선택 화면(제공자가 하나면 302)                  │ 활성화된 제공자 목록 표시      │
   │◀───────────────────────────┴──────────────────────┤                              │
   │ POST /login/google  (csrf 토큰, 포털 쿠키 P)       │                              │
   ├───────────────────────────▶├─────────────────────▶│ state,nonce,pkce를 txn에 저장 │
   │ 302 IdP authorize?client_id&redirect_uri=https://auth.example.test/callback/google
   │        &state=S&nonce=N&code_challenge=C&scope=openid email profile             │
   │◀───────────────────────────┴──────────────────────┤                              │
   ├──────────────────────────────── 인증, 동의 ───────────────────────────────────────▶│
```

### 흐름 3 — 제공자 콜백

```text
 브라우저                      GW                   HP(포털)                        IdP
   │ GET /callback/google?code=AC&state=S  (cookie: __Host-hopae_portal=P)           │
   ├───────────────────────────▶├─────────────────────▶│ state S → txn T; H(P) 일치; 제공자 일치
   │                            │                      ├─ POST token (code, verifier) ─▶│
   │                            │                      │◀─ id_token, access_token ──────┤
   │                            │                      │ iss/aud/exp/nonce/서명 검증    │
   │                            │                      │ 신원 → 사용자(생성/연결)        │
   │                            │                      │ 세션 생성(요소, 바인딩)         │
   │                            │                      │ 포털 핸들 H0; 핸드오프 코드    │
   │                            │                      │ K (app.example.test, H(B), aal 1, gen g)
   │ 302 Location: https://app.example.test/admin/x?_hopae_handoff=K                  │
   │ Set-Cookie: __Host-hopae=H0 (포털 호스트; 포털 바인딩 쿠키 P 유지)                │
   │◀───────────────────────────┴──────────────────────┤                              │
```

### 흐름 4 — 도메인 간 핸드오프

```text
 브라우저                      GW                                 HP(verify)
   │ GET https://app.example.test/admin/x?_hopae_handoff=K  (cookie: __Host-hopae_bind=B)
   ├────────────────────────────▶│ GET /_hopae/verify (문서 탐색; cookie; K가 담긴 x-original-url)
   │                             ├────────────────────────────────▶│ K: 1회용, ≤60초, 호스트+경로
   │                             │                                 │ +ip+H(B)에 바인딩; gen g가 현재;
   │                             │                                 │ 다른 사용자의 유효한 핸들 없음
   │                             │ 302 Location: https://app.example.test/admin/x
   │                             │ Set-Cookie: __Host-hopae=H1 (issued_aal = min(K.aal, session.aal) = 1); bind B 유지
   │                             │ Cache-Control: no-store          │ 핸들 H1 → 세션
   │◀────────────────────────────┤ (중계됨, 업스트림 미접촉)         │
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ → 흐름 5                         │
```

같은 흐름이 `other.example.org`의 두 번째 애플리케이션에도 적용됩니다. 첫
요청은 흐름 1을 거치며(그 호스트 전용 바인딩 쿠키를 심음), 포털은 유효한
포털 핸들 `H0`을 찾아 제공자를 건너뛰고(싱글 사인온) 곧바로 그 쿠키에
바인딩된 `other.example.org`용 새 코드와 함께 흐름 3의 리디렉션으로
답합니다. 따라서 코드는 그 호스트에서 로그인을 시작한 브라우저만, 그것도 문서
탐색으로만 소비할 수 있습니다. 매개변수를 실은 문서가 아닌 요청은 중계되는
`403`으로 중단되어 게이트웨이가 코드를 업스트림으로 전달하는 일이 없습니다.
같은 IP 뒤의 다른 브라우저는 거부되고, 이미 다른 사용자의 유효한 핸들을 가진
브라우저는 조용히 바꿔치기되는 대신 포털의 `/switch` 확인 페이지로 보내집니다.
이미 소비된 코드를 그 코드가 만든 핸들과 함께 다시 제시하면(프리페치가 먼저
소비한 경우) 쿠키를 바꾸지 않고 깨끗한 리디렉션으로 답합니다. 바인딩 쿠키는 그
호스트에서 그 브라우저의 모든 트랜잭션이 공유하므로 동시에 열린 탭들이 서로를
무효화하지 않으며, 어떤 응답도 이를 지우지 않습니다. 두 탭이 어느 쪽 쿠키도
도착하기 전에 시작한 경우, 진 탭은 그냥 포털로 되돌려 보내지고 포털이 싱글
사인온으로 다시 핸드오프하며, 이는 최대 `handoff.max_recoveries`번까지이고 그
뒤에는 브라우저가 중계되는 `403` 페이지를 받습니다. 게이트웨이 리스너에서는
인증된 허용만이 `2xx`입니다. 브라우저가 그 리스너에서 보는 모든 페이지는
중계되는 `403`인데, 수정하지 않은 게이트웨이는 어떤 `2xx`든 업스트림으로
전달하기 때문입니다.

### 흐름 5 — 정상 상태 verify

```text
 브라우저                      GW                                 HP(verify)
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ GET /_hopae/verify (cookie, x-original-url, x-forwarded-for, user-agent)
   │                             ├────────────────────────────────▶│ H1 → 세션 S
   │                             │                                 │ 핸들+세션 타이머 정상
   │                             │                                 │ 바인딩: ip/ua 정상
   │                             │                                 │ 사용자 활성, authz_version 정상
   │                             │                                 │ 앱 정책, 단계 상승: 정상
   │                             │ 200 [id-hdrs] Cache-Control: no-store (HC-1이면 max-age)
   │                             │◀────────────────────────────────┤ last_seen(병합 기록)
   │                             ├── 업스트림 요청 + [id-hdrs] ──▶ 애플리케이션
   │◀────────────────────────────┤ (클라이언트가 보낸 [id-hdrs] 복사본은 제거됨)
```

### 흐름 6 — 로그아웃(이 브라우저)

```text
 브라우저                      GW                   HP(포털)
   │ GET auth.example.test/logout  (cookie: __Host-hopae=H0)
   ├───────────────────────────▶├─────────────────────▶│ 200 확인 폼(csrf)
   │ POST /logout  (csrf, cookie H0)                   │
   ├───────────────────────────▶├─────────────────────▶│ 세션 S → 종료(reason=logout)
   │                            │                      │ S의 모든 핸들 무효. 이벤트
   │ 200 "로그아웃됨" + Set-Cookie: __Host-hopae=; Max-Age=0 (포털 호스트)
   │◀───────────────────────────┴──────────────────────┤ invalidate(S) 발행(M2)
   │ GET app.example.test/admin/x (오래된 쿠키 H1)      │
   ├───────────────────────────▶│ verify: H1 알 수 없음 → 302 로그인 + Set-Cookie 삭제(앱 호스트)
```

### 흐름 7 — 모든 기기에서 로그아웃(M2 표면, M1 의미론)

```text
   │ POST /logout  scope=all  (csrf, cookie H0)        │
   ├───────────────────────────▶├─────────────────────▶│ 사용자 U의 모든 세션 → 종료(reason=logout_all)
   │                            │                      │ invalidate(user U) 발행
   │ 200 "모든 기기에서 로그아웃됨"                      │ 세션마다 이벤트
```

관리자 취소(M4-min의 콘솔과 API)는 같은 종료 경로를 `reason=admin`으로
사용합니다. 사용자를 비활성화하면 그 세션들은 `reason=user_disabled`로
종료됩니다.

### 흐름 8 — 바인딩 불일치에 의한 취소(클라이언트 IP 변경)

```text
 브라우저(새 IP 198.51.100.7)    GW                              HP(verify)
   │ GET /admin/x  (cookie: __Host-hopae=H1)                        │
   ├────────────────────────────▶│ verify: x-forwarded-for: 198.51.100.7
   │                             ├────────────────────────────────▶│ session.ip=203.0.113.9 ≠
   │                             │                                 │ app.binding.ip=strict
   │                             │                                 │ → S 종료(reason=binding_ip)
   │                             │ 302 로그인 + Set-Cookie 삭제      │ 이벤트 session.terminated
   │◀────────────────────────────┤                                 │ invalidate(S) 발행
```

`on_mismatch: drop_handle`이면 `H1`만 무효화되고 포털 세션은 유지됩니다. 다음
포털 방문에서 제공자를 다시 거친 뒤 새 IP로 다시 바인딩합니다([ADR-0007](../adr/0007-context-binding-policy.md)).

### 흐름 9 — 단계 상승 2차 인증(M5 표면, M1 스키마)

```text
 브라우저                      GW                                 HP
   │ GET https://app.example.test/admin/x  (cookie H1, issued_aal=1)
   ├────────────────────────────▶│ verify ──────────────────────────▶│ 규칙: 정규 경로 /admin은 aal 2 필요
   │                             │ 302 Location: https://auth.example.test/stepup?txn=T2
   │◀────────────────────────────┤ (bind B가 있으면 유지, 없으면 심음); no-store
   │ GET /stepup?txn=T2 → TOTP 챌린지 → POST /stepup/totp (csrf, 포털 쿠키 P, code)
   ├───────────────────────────▶├─────────────────────▶│ 요소 확인, 한 트랜잭션에서: factors += totp@now; aal=2;
   │                            │                      │ cred_gen g→g+1; 모든 핸들 취소; 미소비
   │                            │                      │ 코드 전부 소비 처리; 새 포털 핸들
   │ 302 https://app.example.test/admin/x?_hopae_handoff=K2 (aal 2, gen g+1) + Set-Cookie (포털)
   │ GET …?_hopae_handoff=K2 (cookie bind=B; 오래된 H1은 취소됨, 같은 세션 → 교체)
   ├────────────────────────────▶│ verify → 302 + Set-Cookie: __Host-hopae=H1' (issued_aal=2)
   │ GET /admin/x (H1') → verify → 200 [id-hdrs: x-hopae-aal: 2, x-hopae-factors: oidc:google,totp 포함]
```

챌린지 전에 복사된 `H1`은 수준 1에 머물고 단계 상승으로 취소되므로, 2차
인증 요소를 절대 물려받지 않습니다. 챌린지 전에 만든 핸드오프 코드(예: 탈취한
포털 핸들로 싱글 사인온하여 얻은 코드)는 단계 상승이 소비 처리합니다. 그
코드의 소비가 먼저 커밋되더라도 수준 1 핸들만 만들고 이어지는 단계 상승이 그
핸들을 취소합니다. 소비는 `min(code.issued_aal, session.aal)`을 발급하고
세대를 검사하기 때문입니다.

## 데이터 모델

식별자는 무작위이고 URL에 안전하며 종류별 접두사(`u_`, `s_`, `a_`, `p_`,
`e_`)가 붙습니다. 베어러 값(핸들, 핸드오프 코드, 트랜잭션 ID, 매직 링크
토큰)은 SHA-256 다이제스트로만 저장합니다. 시각은 UTC 초입니다. *나중에*로
표시한 열은 M1부터 존재하므로 이후 마일스톤은 열이 아니라 행을 추가합니다.

| 테이블 | 키 | 열(요약) | 비고 |
| --- | --- | --- | --- |
| `users` | `user_id` | `primary_email`, `email_verified`, `email_authoritative`, `display_name`, `username`, `status`(active, disabled), `authz_version`, `groups`(JSON 배열, *나중에*), `created_at`, `updated_at`, `last_login_at` | 사람 한 명당 한 행. `username`과 `primary_email`은 각각 있을 때 고유합니다(동시에 두 번째 생성이 일어나면 ADR-0011의 충돌 결정을 다시 거칩니다). `authz_version`은 상태, 그룹, 역할이 바뀔 때마다 증가하며, verify는 호출마다 `status`와 `authz_version`을 읽습니다. |
| `identities` | (`provider_id`, `subject`) | `user_id`, `email`, `email_verified`, `email_authoritative`, `name`, `picture`, `raw_claims`(JSON, 8 KiB 제한), `first_seen_at`, `last_seen_at` | 제공자 subject를 사용자에 연결합니다([ADR-0011](../adr/0011-account-linking-policy.md)). [ADR-0010](../adr/0010-provider-abstraction.md)의 subject 일관성 검사를 통과한 뒤에만 생성됩니다. |
| `providers` | `provider_id` | `kind`(oidc, oauth2, email_link, password), `display_name`, `enabled`, `managed_by`(file, api), `deleted_at`, `sort_order`, `config`(JSON: issuer, 엔드포인트, 스코프, 특이 사항), `client_secret_env`, `allowed_email_domains`, `authoritative_domains`, `auto_link`, `trust_email`, `created_at`, `updated_at` | 파일 항목은 시작 시 행이 없거나 `managed_by = file`이면서 삭제되지 않은 경우에만 가져옵니다. 관리 API(M4)로 변경되거나 제거된 행은 파일이 절대 덮어쓰지 않는 묘비(tombstone)이므로, 실행 중 비활성화나 제거가 재시작 뒤에도 유지됩니다. 비밀은 환경 변수 이름으로만 참조하고 저장하지 않습니다. |
| `apps` | `app_id` | `display_name`, `hosts`(정확한 소문자 호스트 이름의 JSON 배열. 패턴 없음), `ports`(JSON 배열, 기본값 `[443]`), `enabled`, `session_policy`(idle, absolute), `binding_policy`(ip, ua, on_mismatch), `step_up`(JSON 규칙, *나중에*), `allowed_groups`(*나중에*), `on_authz_change`(refresh, terminate), `gateway_ref`(참고용 라우트 ID), `created_at`, `updated_at` | verify는 `x-forwarded-host`로 애플리케이션을 찾습니다. 모든 `hosts`와 `ports`의 합집합이 돌아갈 출처 허용 목록이며, 각 항목은 운영자가 보증하는 정확한 자격 증명 목적지입니다. 목록에 없는 호스트는 거부되며 "모든 호스트" 모드도 접미사 모드도 없습니다. 예약된 애플리케이션 `default`는 정책 기본값만 가집니다. |
| `sessions` | `session_id` | `user_id`, `provider_id`, `auth_time`, `factors`(`{kind, provider?, at}`의 JSON 배열), `aal`(1 또는 2), `authz_version`(스냅샷 시점의 사용자 값), `authz_version_at_auth`(인증 시점의 사용자 값으로 바뀌지 않으며 `terminate` 애플리케이션이 비교하는 기준), `cred_gen`, `bound_ip`, `bound_ua_sha256`, `bound_ua_prefix`(표시용 64바이트 정제 접두사, 마이그레이션 `0003`, M4-min), `bound_country`(*나중에*), `created_at`, `last_seen_at`, `absolute_expires_at`, `terminated_at`, `terminated_reason` | 브라우저 로그인 한 번당 한 행. 자체 완결적인 신원 스냅샷(`snapshot` JSON: email, name, username, groups)을 담으며 `users.authz_version`이 바뀌면 갱신합니다. `cred_gen`은 핸들 취소나 단계 상승과 같은 트랜잭션에서 증가하며, 그 트랜잭션은 세션의 미소비 핸드오프 코드도 함께 소비 처리합니다. 이 값은 `x-hopae-gen`과 무효화 메시지에 실립니다. |
| `session_handles` | `handle_sha256` | `session_id`, `host`, `issued_aal`, `created_at`, `last_seen_at`, `absolute_expires_at`, `revoked_at`, `revoked_reason` | (세션, 호스트)마다 하나. 쿠키는 핸들을 담으며, 서로 다른 호스트는 절대 핸들을 공유하지 않습니다. `issued_aal`은 핸들이 부여하는 수준이며, 단계 상승은 핸들을 취소하고 다시 발급합니다. 유휴·절대 타이머는 핸들 단위입니다([ADR-0007](../adr/0007-context-binding-policy.md)). |
| `login_txns` | `txn_sha256` | `created_at`, `expires_at`(10분), `app_id`, `return_target`(게이트웨이가 준 절대 URL, 돌아갈 출처 허용 목록의 정확한 항목), `bind_sha256`(애플리케이션 호스트에 있는 브라우저의 안정적인 바인딩 쿠키 다이제스트), `portal_bind_sha256`(첫 포털 방문 시 기록하는, 브라우저의 안정적인 포털 바인딩 쿠키 다이제스트), `client_ip`, `ua_sha256`, `provider_id`, `state_sha256`(콜백은 이 값으로 트랜잭션을 찾음), `nonce`, `pkce_verifier`, `portal_session_id`(SSO일 때, 또는 로그아웃 티켓이 가리키는 세션), `purpose`(login, stepup, link, switch, logout — 마지막은 애플리케이션 호스트 진입점의 로그아웃 티켓, [ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md)), `conflicting_handle_sha256`(`switch`용), `pending_identity`(JSON, `link_required`용), `recovery_depth`, `retry_bind_sha256`(콜백이 `portal_bind_mismatch`로 실패할 때 기록), `retry_used_at`(뒤따르는 단 한 번의 `POST /login/retry`가 기록), `consumed_at` | 로그인 시도 한 번의 서버 측 상태입니다. 브라우저마다 여러 개가 열려 있을 수 있으며, `recovery_depth`가 바인딩 경합 복구 횟수를 제한하고, `retry_bind_sha256`은 `POST /login/retry`가 일치시켜야 하는 값이고, `retry_used_at`은 그 재시도를 1회용으로 만듭니다. |
| `handoff_codes` | `code_sha256` | `session_id`, `host`, `return_target`, `client_ip`, `bind_sha256`, `issued_aal`, `cred_gen`, `recovery_depth`(발급한 트랜잭션에서 복사), `created_at`, `expires_at`(60초), `consumed_at`, `consumed_reason` | 1회용. 소비는 바인딩 쿠키, 세션의 현재 `cred_gen`, 다른 사용자의 유효한 핸들 부재까지 함께 검사하는 원자적 조건부 갱신이며, 만들어지는 핸들은 `min(issued_aal, session.aal)`을 받습니다. 복구 트랜잭션은 실패한 코드의 행에서 `recovery_depth + 1`을 가져오며 클라이언트에서는 절대 읽지 않습니다. |
| `events` | `event_id` | `at`, `kind`, `outcome`, `reason`, `user_id`, `session_id`, `app_id`, `provider_id`, `client_ip`, `ua_sha256`, `request_id`, `attrs`(JSON, 제한됨) | 추가 전용 로그인 기록이자 감사 원천([ADR-0009](../adr/0009-event-model.md)). 필수 종류와 그 전달 행은 상태 변경과 같은 트랜잭션에서 기록합니다(트랜잭션 아웃박스). 전달 상태와 무관하게 `events.prune_every`건 삽입마다 또는 60초마다 기간과 건수로 정리하므로 테이블은 `max_rows + prune_every`를 절대 넘지 않습니다. |
| `event_deliveries` | (`sink`, `event_id`) | `state`(pending, delivered, failed), `attempts`, `next_attempt_at`, `last_error`, `updated_at` | 필수 이벤트마다 구독 싱크당 한 행. 이벤트의 트랜잭션에서 삽입되고 전달 워커가 가져갑니다. 최소 1회 전달이며, 싱크별 적체 상한과 데드레터 처리를 갖습니다. 부모 이벤트와 함께 삭제되며(연쇄 삭제), 종결 상태 행은 `events.delivery_terminal_retention_days`가 지나면 별도로 만료됩니다. |
| `blocks`(*M2*) | `block_id` | `kind`(user, email, email_domain, ip_cidr), `value`, `reason`, `created_by`, `created_at`, `expires_at` | 로그인과 verify에서 검사합니다. |
| `attempts`(*M2*) | (`scope`, `key`) | `failures`, `window_started_at`, `locked_until` | 계정별·IP별 제한 카운터. 설정 시 Redis에 둡니다. |
| `factors`(*M5*) | `factor_id` | `user_id`, `kind`(totp, webauthn, recovery), `label`, `secret_env_or_encrypted`, `public_key`, `counter`, `created_at`, `last_used_at`, `disabled_at` | 등록 정보([ADR-0008](../adr/0008-second-factor-extension-point.md)). |
| `webhooks`(*M5*) | `webhook_id` | `url`, `event_kinds`, `secret_env`, `enabled`, `created_at`, `last_delivery_at`, `last_status` | 전송 대상. 전송 자체는 `kind=webhook.delivery` 이벤트입니다. |
| `admin_grants`(*M4-min*, 마이그레이션 `0003`) | `user_id` | `role`(admin, viewer), `granted_at`, `granted_by`(사용자 id 또는 `cli`), `revoked_at`, `revoked_by`, `note` | 관리자는 살아 있는 부여 행이 있는 사용자이며 콘솔 요청마다 읽습니다. 별도의 계정이나 비밀번호는 없습니다([ADR-0016](../adr/0016-management-console-minimum.md)). 취소된 행은 자리를 유지하며 다시 부여하면 취소가 해제됩니다. 이력은 `admin.grant` / `admin.revoke` 이벤트에 있습니다. |
| `meta` | `key` | `value` | 스키마 버전, 인스턴스 ID, 키 ID. |

인덱스: `identities(user_id)`, `identities(email)`(연결용),
`sessions(user_id, terminated_at)`, `session_handles(session_id)`,
`events(at)`, `events(user_id, at)`, `events(client_ip, at)`,
`event_deliveries(sink, state, next_attempt_at)`,
`handoff_codes(session_id, consumed_at)`, `handoff_codes(expires_at)`,
`login_txns(state_sha256)`, `login_txns(expires_at)`. 마이그레이션
`0003`(M4-min)은 콘솔의 필터와 목록을 위해 `events(kind, at)`,
`sessions(terminated_at, last_seen_at)`, `users(created_at)`를 추가합니다.
마이그레이션 `0002`는 동결되어 다시 편집하지 않습니다.

관계: 사용자는 여러 신원과 여러 세션을 가집니다. 세션은 호스트마다 핸들
하나와 로그인 시점의 사용자 스냅샷을 가집니다. 애플리케이션은 정책을 가집니다.
이벤트는 모든 것을 ID로 참조하며 삭제 뒤에도 남습니다.

## 저장소

결정은 [ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)에
기록되어 있습니다. 요약은 다음과 같습니다.

| 관심사 | SQLite(rusqlite, bundled) | PostgreSQL(tokio-postgres) | Redis/Valkey |
| --- | --- | --- | --- |
| 역할 | 기본 저장소, 기본값, 단일 인스턴스 | 활성-활성 배포의 기본 저장소(M2) | pub/sub 무효화 채널과 제한 카운터(M2) 전용. 세션이나 결정 상태를 절대 보관하지 않으며 절대 진실의 원천이 아닙니다 |
| 내구성 | WAL, `synchronous=NORMAL`, 쓰기 작업 하나. 필수 감사 이벤트와 그 전달 행은 상태 변경과 같은 트랜잭션에서 커밋. 체크포인트된 데이터베이스의 파일 복사로 백업(M7) | 운영자가 관리. 같은 트랜잭션 규칙 적용 | Redis를 잃어도 진행 중인 카운터와 조기 제거만 잃습니다. verify가 의존하는 것은 없습니다 |
| Verify 지연과 예산 | 루프백에서 조회당 수십 마이크로초. verify 예산은 총 400 ms(`gateway.verify_budget_ms`) | 사설 네트워크에서 1밀리초 미만. 앞에 권위 있는 읽기의 선택적 로컬 캐시 | verify는 Redis를 절대 기다리지 않습니다. 다른 곳의 카운터와 발행 작업은 50 ms(`cache.op_timeout_ms`)로 제한되고, 연속 세 번 시간 초과하면 5초 동안 차단기가 열리며, 시간 초과한 카운터는 그것이 지키는 로그인 시도를 거부 처리합니다 |
| 이유 | 게이트웨이가 검증한 내장 저장소 선택과 일치. 흔한 단일 게이트웨이 배포에 운영 의존성이 없음. 스키마 마이그레이션 내장 | 다중 인스턴스는 하나의 공유 디렉터리가 필요합니다. 사용자 ID, 신원, 차단은 인스턴스 간에 일치해야 하는데 SQLite는 네트워크로 안전하게 공유할 수 없습니다 | 게이트웨이의 `security_redis` 패턴(연결 관리자, 900 ms 시간 제한, 카운터의 거부 처리)을 재사용합니다 |

세 저장소 모두 같은 트레이트(`Directory`, `Sessions`, `Events`) 뒤에
있으므로, 배포는 키 하나 `store.kind = sqlite | postgres`로 선택합니다.

## 크레이트 구성

크레이트 하나 `hopae`에 라이브러리와 바이너리 하나를 둡니다. HTTP 계층은
hyper 1, tokio, rustls 위의 axum 0.8로, 게이트웨이와 같은 런타임 계열입니다.
[ADR-0003](../adr/0003-http-stack-axum-on-hyper.md)에서 axum과 순수 hyper를
비교합니다.

```text
src/
  main.rs            CLI: run, --check, hash-password, gateway render (M2), update (M6)
  lib.rs             통합 테스트용 재내보내기
  config/            스키마(serde, deny_unknown_fields), 로드, 환경 참조, 검증
  app.rs             배선: 저장소, 캐시, 리스너, 정상 종료
  http/              리스너별 라우터. 미들웨어: 요청 ID, 보안 헤더, 본문과 헤더 제한
  portal/            로그인, 콜백, 로그아웃, 단계 상승(M5) 핸들러. askama 템플릿. csrf
  admin/             콘솔 페이지와 /v1 API(M4-min): 엔진을 통한 핸들 인증, 부여, 사용자, 세션, 이벤트, 상태
  verify/            결정 엔진(VerifyInput → Decision 순수 함수)
  gateway/           Adapter 트레이트. hangang/ (계약 v1). 범용 포워드 인증(나중에)
  session/           세션, 핸들, 트랜잭션, 핸드오프 코드, 수명, 종료
  identity/          사용자, 신원, 연결 정책, 스냅샷
  policy/            애플리케이션, 바인딩, 단계 상승 규칙, 차단(M2), 경로 규칙(M2)
  provider/          Provider 트레이트. oidc/ (디스커버리, jwks, 토큰, idtoken). kakao/ naver/ email/ password/ (M3)
  factor/            Factor 트레이트. totp/ webauthn/ recovery/ (M5)
  event/             Event, EventKind, 버스(broadcast), 싱크: 로그, 저장소. webhook/ (M5)
  store/             트레이트. sqlite/ (M1). postgres/ (M2). migrations/
  cache/             제한된 로컬 캐시. redis/ (M2): write-through, pub/sub
  crypto/            ID, 다이제스트, 상수 시간 비교, 환경에서 읽는 키 자료
  lua/               워커 프로토콜과 샌드박스(M5). 게이트웨이의 모델에서 가져옴
  update/            서명된 업데이터(M6). 게이트웨이에서 가져옴
  telemetry/         tracing 설정, 지표(M7)
tests/
  support/           실행-탐침 하네스, mock_idp(오동작 프로필을 가진 OIDC)
  scenarios/         sNNN_*.rs, 시나리오당 파일 하나
```

의존성 정책: 게이트웨이 트리에 이미 있는 크레이트를 우선합니다(`hyper`,
`hyper-util`, `tokio`, `rustls`, `tokio-rustls`, rustls 기반 `reqwest`,
`redis`, `rusqlite`, `tokio-postgres`, `jsonwebtoken`, `argon2`, `sha2`,
`subtle`, `base64`, `serde`, `clap`, `tracing`, `arc-swap`, `semver`,
`ed25519-dalek`, `tempfile`). M1의 새 의존성: `axum`, `tower`, `askama`,
`cookie`, `url`. 새 의존성은 각각 추가하는 커밋에서 사유를 밝힙니다.

## 장애 시 동작

| 조건 | Verify(`/_hopae/verify`) | 포털 | 운영자가 보는 것 |
| --- | --- | --- | --- |
| Hopae 프로세스 다운 또는 접근 불가 | 게이트웨이가 시간 초과(`auth.timeout_ms`, 500 ms 권장)되어 클라이언트에 `503`으로 답합니다: 거부 처리. 제안된 마이크로 캐시(HC-1)가 있으면 캐시된 허용 결정은 TTL까지 유지되지만 새 로그인은 없습니다. | 사용 불가 | 게이트웨이 `503` 카운터. Hopae 상태 확인 실패. 완화: 게이트웨이 헤어핀 라우트 뒤의 인스턴스 두 개(M7)와 제한된 완충 역할의 마이크로 캐시 TTL. |
| 기본 저장소 사용 불가 | `reason=store_unavailable`과 함께 `503`. 절대 허용하지 않음 | `503` | 오류 수준 로그, 지표 `hopae_store_errors_total`. 게이트웨이는 `503`을 중계합니다. |
| Redis 사용 불가 또는 멈춤(M2) | 영향 없음: verify는 Redis를 읽지 않습니다. pub/sub 연결이 끊긴 동안 로컬 캐시가 비활성화되어 모든 verify가 기본 저장소를 읽습니다 | 제한 카운터가 시간 초과(50 ms)한 로그인 시도는 거부됩니다(거부 처리). 세 번 시간 초과하면 차단기가 5초 동안 거부합니다 | 경고 로그, 지표 `hopae_cache_degraded`. 무효화 메시지가 발행되지 않으므로 게이트웨이 마이크로 캐시는 절대 신선도 마감에 의존합니다(제한된 지연). |
| 호출자 키 없는 게이트웨이(잘못 설정된 라우트, 운영 환경의 수정하지 않은 게이트웨이) | 모든 verify에 `403 caller_unauthorized`, 게이트웨이가 중계. 어떤 상태도 읽거나 쓰지 않음 | 해당 없음 | `hopae --check`가 기대하는 정적 헤더를 보여 줍니다. 지표 `hopae_verify_unauthorized_total`. |
| ID 제공자 접근 불가 또는 느림 | 영향 없음(verify는 제공자를 호출하지 않음) | 로그인 시도가 `reason=provider_unavailable`로 실패. 재시도 페이지. 트랜잭션은 만료까지 유지 | 이벤트 `login.failed`. 제공자별 지표. 디스커버리와 JWKS 캐시에는 하드 데드라인이 있어, 만료된 키는 서명 검사를 건너뛰는 대신 토큰을 거부합니다. |
| 허용 오차(60초)를 넘는 시계 오차 | 세션이 만료되었거나 미래 시각으로 보임: 거부 | ID 토큰 검증 실패(`iat`/`exp`) | `reason=clock_skew`. 시스템 시계가 동기화되지 않으면 사전 점검이 경고합니다. |
| 게이트웨이가 예상 밖의 계약을 보냄(`x-original-url` 누락, 알 수 없는 계약 버전) | verify 호출에 `400`, 게이트웨이는 `503`으로 변환: 거부 처리 | 해당 없음 | 누락된 필드 이름을 담은 `reason=contract_violation`. 비밀 정보는 절대 없습니다. |
| Lua 워커 포화(M5) | 훅 결과 사용 불가 → 그 결과가 필요한 결정은 거부 | 훅이 필요한 로그인 단계 실패 | 게이트웨이와 동일: 포화는 거부 처리됩니다. |

모든 장애에 공통인 운영자 가시 효과: 로그의 사유 코드, 사유별 카운터, 어떤
메시지에도 비밀 정보 없음.

## 제한과 호환성

- M1에서 지원하는 게이트웨이 계열은 하나입니다(호출자 키를 위한 게이트웨이 변경 HC-3를 포함하여, 버전이 붙은 계약을 통한 Hangang). 다른 포워드 인증 게이트웨이는 핵심을 공유하지만 자체 어댑터와 자체 검증 실행이 필요합니다.
- 로그인은 같은 브라우저에서 같은 애플리케이션 호스트로 시작하고 끝내야 합니다(바인딩 쿠키). 애플리케이션 호스트의 쿠키를 차단하는 브라우저는 로그인할 수 없습니다.
- 보호되는 모든 호스트는 정확한 이름으로 등록합니다. 와일드카드나 접미사 호스트는 세션을 받을 수 없습니다. 문서 탐색을 수행할 수 없는 클라이언트는 API 클라이언트 모드(M7) 전까지 세션을 얻을 수 없습니다.
- 설정 파일은 JSON입니다. YAML이나 TOML 로더는 없으며, M6 전까지 다시 로드도 없습니다.
- 쿠키는 호스트 전용입니다. 형제 서브도메인에 걸친 쿠키(`Domain=`)는 쿠키 토싱 때문에 M1에서 의도적으로 제공하지 않으며, 핸드오프가 그 경우를 다룹니다([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)).
- Verify는 모든 요청마다 호출됩니다. 게이트웨이 마이크로 캐시(HC-1)가 생기기 전까지 Hopae의 요청당 예산이 전체 예산입니다: 제공자 호출 없음, 제한 없는 쿼리 없음, 제한된 로컬 캐시.
- 다중 인스턴스 배포에는 PostgreSQL(M2)과 무효화를 위한 Redis가 필요합니다. SQLite 배포는 빠른 재시작을 가진 단일 인스턴스입니다.

## 관련 페이지

- [게이트웨이 계약](GATEWAY_CONTRACT.md) — 전송 프로토콜, 라우트 조각, 제안된 게이트웨이 변경
- [위협 모델](THREAT_MODEL.md) — 자산, 행위자, 흐름별 STRIDE, 완화책
- [로드맵](ROADMAP.md) — 마일스톤과 M1 시나리오 목록
- [ADR 목록](../adr/) — ADR-0002부터 ADR-0013까지
