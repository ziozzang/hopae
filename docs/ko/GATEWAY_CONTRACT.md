# 게이트웨이 계약

<!-- translation-status: source=../GATEWAY_CONTRACT.md source-rev=2 status=current -->

[문서 목차](README.md) · [English](../GATEWAY_CONTRACT.md)

이 페이지는 게이트웨이의 포워드 인증 확인과 Hopae 사이의 정확한 와이어 계약을
정의합니다. 엔드포인트, 소비하는 요청 헤더, 응답 코드, 내보내는 신원 헤더, 캐시
의미론, 무효화 채널, 포털 진입점을 다룹니다. 이 계약은 **계약 v1**로 버전을
매기며, 버전 관리 목적상 Hopae 공개 API의 일부입니다([프로세스](PROCESS.md#변경-이력과-버전)).
Hangang 게이트웨이가 최우선(first-class) 통합 대상이며, 페이지 후반부는
수정하지 않은 Hangang 0.2.6에서 무엇이 동작하고 어떤 게이트웨이 변경을
제안하는지 밝힙니다. 결정은
[ADR-0005](../adr/0005-gateway-contract-and-versioning.md)와
[ADR-0006](../adr/0006-verify-caching-and-invalidation.md)에 기록되어 있습니다.

## 전제 조건과 설정

| 측 | 설정 | 값 |
| --- | --- | --- |
| Hopae | `listen.gateway` | 게이트웨이 리스너 주소. 기본값 `127.0.0.1:8701`. 공개 네트워크에서 도달할 수 없어야 합니다 |
| Hopae | `listen.portal` | 포털 리스너 주소. 기본값 `127.0.0.1:8700`. 게이트웨이가 포털 호스트를 이 주소로 프록시합니다 |
| Hopae | `portal.public_url` | `https://auth.example.test`. 계약이 내보내는 모든 `Location`에 사용합니다 |
| Hopae | `gateway.kind` | `hangang`(M1), `forward_auth`(이후) |
| Hopae | `gateway.caller_key_env` | `gateway.kind = hangang`이면 필수: 게이트웨이가 `x-hopae-gateway-key`로 보내는 공유 호출자 키를 담은 환경 변수(게이트웨이 변경 HC-3, M1과 함께 구현). `gateway.allow_unauthenticated_caller = true`는 개발 전용으로 이 검사를 끄며 사전 점검이 경고합니다. |
| Hopae | `gateway.verify_budget_ms` | verify 한 번에 Hopae가 스스로에게 허용하는 총 시간. 기본값 `400`. 게이트웨이의 `auth.timeout_ms`보다 작아야 합니다 |
| Hopae | `apps[]` | 애플리케이션 호스트(정확한 이름 또는 `*.suffix` 패턴), `ports`(기본값 `[443]`), 정책. 이들의 합집합이 돌아갈 출처 허용 목록입니다. 어떤 패턴에도 맞지 않는 호스트는 거부합니다(`unknown_app`) |
| 게이트웨이 | 라우트 `auth.url` | `http://127.0.0.1:8701/_hopae/verify` |
| 게이트웨이 | 라우트 `auth.static_request_headers` | `{"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}`(HC-3) |
| 게이트웨이 | 라우트 `auth.request_headers` | `cookie`, `user-agent`, `accept`, `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site` |
| 게이트웨이 | 라우트 `auth.response_headers` | 아래에 나열한 신원 헤더 집합 |
| 게이트웨이 | 라우트 `auth.forward_response` | `true`(필수: 로그인 리디렉션과 쿠키 심기가 이 경로로 전달됩니다) |
| 게이트웨이 | 라우트 `auth.timeout_ms` | `500` 권장(게이트웨이 기본값 `1000`, 최대 `5000`) |

### Hangang 라우트 조각

보호된 애플리케이션(호스트 전체):

```json
{
  "id": "app-example",
  "access_mode": "protected",
  "host": "app.example.test",
  "path_prefix": "/",
  "backends": ["http://127.0.0.1:3000"],
  "auth": {
    "url": "http://127.0.0.1:8701/_hopae/verify",
    "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
    "response_headers": [
      "x-forwarded-user", "x-forwarded-email", "x-forwarded-preferred-username", "x-forwarded-groups",
      "x-hopae-session", "x-hopae-provider", "x-hopae-auth-time", "x-hopae-expires",
      "x-hopae-aal", "x-hopae-factors"
    ],
    "static_request_headers": {
      "x-hopae-contract": "1",
      "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}
    },
    "timeout_ms": 500,
    "forward_response": true
  }
}
```

`static_request_headers`는 게이트웨이 변경 HC-3입니다. 수정하지 않은
게이트웨이는 이 키를 거부합니다(`deny_unknown_fields`). 그런 게이트웨이는 Hopae
쪽에서 `gateway.allow_unauthenticated_caller = true`를 설정한 개발 환경에서만
쓸 수 있습니다.

경로 범위 보호는 한 호스트에 두 라우트를 사용합니다. 호스트용 공개 라우트
하나와, 접두사용으로 우선순위가 더 높은 보호 라우트 하나입니다.

```json
[
  {"id": "site-public", "access_mode": "public", "host": "app.example.test",
   "path_prefix": "/", "priority": 0, "backends": ["http://127.0.0.1:3000"]},
  {"id": "site-admin", "access_mode": "protected", "host": "app.example.test",
   "path_prefix": "/admin", "path_match": "segment_prefix", "priority": 10,
   "backends": ["http://127.0.0.1:3000"],
   "auth": {"url": "http://127.0.0.1:8701/_hopae/verify",
            "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
            "response_headers": ["x-forwarded-user", "x-forwarded-email", "x-forwarded-preferred-username",
                                 "x-forwarded-groups", "x-hopae-session", "x-hopae-provider",
                                 "x-hopae-auth-time", "x-hopae-expires", "x-hopae-aal", "x-hopae-factors"],
            "static_request_headers": {"x-hopae-contract": "1",
                                       "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}},
            "timeout_ms": 500, "forward_response": true}}
]
```

포털 호스트(공개 라우트. Hopae가 자신의 페이지를 직접 인증합니다):

```json
{"id": "hopae-portal", "access_mode": "public", "host": "auth.example.test",
 "path_prefix": "/", "backends": ["http://127.0.0.1:8700"]}
```

신원 헤더 이름은 적어도 하나의 라우트 `response_headers`에 나타나야 합니다.
게이트웨이는 그런 이름을 모두 게이트웨이 전체의 모든 수신 요청에서 제거합니다.
위 조각들은 시나리오 008에서 게이트웨이 스키마(`deny_unknown_fields`)에 대해
검증합니다.

## 동작

### verify 엔드포인트

게이트웨이 리스너의 `GET /_hopae/verify`입니다. 본문은 없습니다. 응답 하나가
요청 하나를 결정합니다.

소비하는 요청 헤더를 Hopae가 평가하는 순서대로 나열합니다.

| 헤더 | 출처 | 필수 | 용도 |
| --- | --- | --- | --- |
| `x-hopae-gateway-key` | 게이트웨이(HC-3) | 예 | **다른 어떤 헤더보다 먼저** 호출자 키와 상수 시간으로 비교합니다. 불일치나 부재 → `403`(`caller_unauthorized`), 상태는 전혀 건드리지 않으며 횟수를 셉니다. `gateway.allow_unauthenticated_caller = true`(개발 전용)만 이 검사를 면제합니다. |
| `x-hopae-contract` | 게이트웨이(HC-3) 또는 없음 | 아니요 | 게이트웨이가 말하는 계약 메이저 버전. `1` 또는 없음은 v1을 뜻합니다. 더 높은 메이저는 `400`(`contract_unsupported`)으로 답합니다. |
| `x-original-url` | 게이트웨이 | 예 | 클라이언트 요청의 절대 URL(`proto://host[:port]/path?query`). 돌아갈 대상, 핸드오프 매개변수에 사용합니다. 2048바이트 이하, 스킴 `https`(`cookie.secure=false`일 때만 `http` 허용), userinfo 없음, fragment 없음. 호스트 중립 라우트에서는 이 URL의 호스트 부분을 클라이언트가 고르므로 돌아갈 출처 허용 목록에 대해 검사합니다. |
| `x-hangang-canonical-path` | 게이트웨이(HC-6) | 아니요 | 게이트웨이가 라우트 선택에 사용한 디코딩·정규화된 경로. 없으면 Hopae가 게이트웨이의 규칙으로 정규 경로를 직접 계산합니다([ADR-0013](../adr/0013-gateway-adapter-boundary.md)). 둘 다 있는데 서로 다르면 요청을 거부합니다(`canonical_path_mismatch`). 모든 경로 규칙은 원시 경로가 아니라 정규 경로에 대해 매칭합니다. |
| `x-hangang-route-id` | 게이트웨이(HC-6) | 아니요 | 선택된 라우트 ID. 로그에 남기고 애플리케이션 힌트로 사용합니다. |
| `x-forwarded-host` | 게이트웨이 | 예 | 애플리케이션 호스트. `x-original-url`의 호스트와 같아야 합니다. |
| `x-forwarded-proto` | 게이트웨이 | 예 | `__Host-` 쿠키를 심으려면 `https`여야 합니다. |
| `x-forwarded-for` 또는 `x-real-ip` | 게이트웨이(신뢰 프록시로 해석) | 예 | 바인딩, 제한, 이벤트에 쓰는 클라이언트 IP. Hangang은 둘 다 해석된 단일 클라이언트 IP로 설정합니다. |
| `x-original-method` | 게이트웨이 | 아니요 | 로그에 남깁니다. 메서드에 따른 규칙은 이후 작업입니다. |
| `cookie` | 클라이언트(나열됨) | 아니요 | Hopae 쿠키(`__Host-hopae`, `__Host-hopae_bind`)만 사용하고 다른 쿠키는 무시합니다. 전체 8 KiB 이하. |
| `user-agent` | 클라이언트(나열됨) | 아니요 | UA 바인딩(`sha256`), 이벤트. 1 KiB 이하, 저장 시 잘라냅니다. |
| `sec-fetch-dest`, `sec-fetch-mode`, `sec-fetch-site`, `accept` | 클라이언트(나열됨) | 아니요 | 인증되지 않은 요청에 `302`와 `401` 중 무엇으로 답할지 결정합니다. |

필수 헤더가 빠지면 계약 위반입니다. `400`과 `x-hopae-reason: contract_violation`으로
답하며, Hangang은 이를 `503`으로 바꿉니다(거부 처리). 클라이언트가 보낸
`x-forwarded-*`/`x-original-*`는 게이트웨이가 이미 교체합니다. Hopae는 추가로
게이트웨이 리스너에서 `x-forwarded-host`와 `x-original-url`의 호스트가 다른
요청을 거부합니다.

응답 코드:

| 상태 | 의미 | 헤더 | 게이트웨이 동작(Hangang) |
| --- | --- | --- | --- |
| `200` | 허용 | 신원 헤더, `cache-control: no-store`(HC-1이 적용되면 `private, max-age=N`), `x-hopae-reason: ok` | 나열된 헤더를 업스트림 요청에 주입합니다. |
| `302` | 문서 탐색에 대한 로그인, 단계 상승, 핸드오프 리디렉션 | `location`(포털 URL 또는 핸드오프 대상), `set-cookie`(바인딩 쿠키나 핸들을 심거나 지움), `cache-control: no-store`, `x-hopae-reason` | `referrer-policy: no-referrer`와 함께 클라이언트로 중계합니다. 업스트림에는 접속하지 않습니다. |
| `401` | 인증 필요, 문서가 아닌 요청 | `content-type: application/json`, 본문 `{"error":"login_required","login":"https://auth.example.test/login?txn=…"}`, `www-authenticate: Hopae realm="auth.example.test"`, `cache-control: no-store` | 클라이언트로 중계합니다. |
| `403` | 거부: 호출자 키 누락이나 불일치(`caller_unauthorized`), 허용 목록 밖의 호스트(`unknown_app`), 차단된 사용자나 IP, 비활성화된 애플리케이션, 그룹 규칙, 단계 상승 불가, **또는 속도 제한**(`{"error":"rate_limited","retry_after":30}`) | `error`를 담은 JSON 본문, `x-hopae-reason` | 본문과 함께 클라이언트로 중계합니다. 수정하지 않은 게이트웨이는 `429`를 `503`으로 바꾸고 `retry-after`를 버리므로 속도 제한에 `403`을 사용합니다. 게이트웨이 변경 HC-8이 있으면 Hopae는 대신 `retry-after`를 실은 `429`로 답합니다(`gateway.rate_limit_status`). |
| `400` | 계약 위반 | `x-hopae-reason` | 클라이언트에 `503`(거부 처리). |
| `503` | Hopae가 결정할 수 없음(저장소 사용 불가, 과부하, verify 예산 초과) | `retry-after`, `x-hopae-reason` | 클라이언트에 `503`(거부 처리). |

`x-hopae-reason`은 게이트웨이 로그를 위한 진단 헤더입니다. `response_headers`에
들어가지 않으며 업스트림이나 클라이언트에 절대 도달하지 않습니다.

Hopae 내부의 결정 순서는 다음과 같습니다. 호출자 키 → 계약 검사 → 정규 경로 →
핸드오프 매개변수(새 핸들을 심을 수 있음, 바인딩 쿠키 필요) → 쿠키 핸들 → 세션
조회 → 핸들과 세션 타이머 → 바인딩 정책 → 사용자 상태와 `authz_version` →
애플리케이션 정책(활성화, 차단, 그룹) → 단계 상승 규칙 → 신원 헤더. 이 모든
과정은 verify 예산(`gateway.verify_budget_ms`, 기본값 400 ms) 안에서 실행되며,
예산을 다 쓰면 `503`으로 답합니다.

### 신원 헤더

`200`에서만 내보냅니다. 값은 보이는 ASCII이며, ASCII가 아닌 문자는 UTF-8로
퍼센트 인코딩합니다(RFC 3986 비예약 집합은 유지). 값이 없는 헤더는 빈 값으로
보내지 않고 생략합니다.

| 헤더 | 값 | 제한 |
| --- | --- | --- |
| `x-forwarded-user` | 사용자의 수명 동안 안정적인 Hopae 사용자 ID(`u_` + base32 26자) | 64 B |
| `x-forwarded-email` | 기본 이메일. 없으면 생략 | 254 B |
| `x-forwarded-preferred-username` | 사용자 이름 또는 표시 이름 | 256 B |
| `x-forwarded-groups` | 쉼표로 구분한 그룹 이름(M2). 없으면 생략 | 4 KiB |
| `x-hopae-session` | 세션 ID(`s_` + 26자). 쿠키 핸들이 아닙니다 | 64 B |
| `x-hopae-provider` | 첫 번째 요소의 제공자 ID(`google`) | 64 B |
| `x-hopae-auth-time` | 첫 번째 요소 인증 시각의 Unix 초 | 20 B |
| `x-hopae-expires` | 유휴 만료와 절대 만료 중 이른 쪽의 Unix 초 | 20 B |
| `x-hopae-aal` | `1` 또는 `2`: 제시된 핸들이 발급될 때의 수준([ADR-0008](../adr/0008-second-factor-extension-point.md)). 단계 상승은 핸들을 다시 발급합니다 | 1 B |
| `x-hopae-factors` | 충족한 요소의 쉼표 목록 `kind[:provider]`, 예: `oidc:google,totp` | 256 B |

신원 헤더의 총 바이트는 8 KiB 이하입니다(게이트웨이는 16 KiB를 넘으면
거부합니다). 이 집합이 계약 v1의 전부입니다. 헤더 추가는 마이너 변경, 이름 변경이나
제거는 메이저 변경입니다.

### 쿠키

| 쿠키 | 호스트 | 속성 | 내용 |
| --- | --- | --- | --- |
| `__Host-hopae` | 각 애플리케이션 호스트와 포털 호스트 | `Path=/; Secure; HttpOnly; SameSite=Lax`, `Domain` 없음, `Max-Age`는 핸들의 남은 절대 수명과 같음 | `v1.` + 무작위 32바이트의 base64url. 세션 하나, 호스트 하나, 발급 수준 하나에 묶인 핸들 |
| `__Host-hopae_bind` | 애플리케이션 호스트. 로그인이나 단계 상승을 시작하는 미인증 `302`가 심음 | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | 무작위 16바이트의 base64url. 핸드오프 코드가 묶이는 브라우저 비밀. 소비 응답이 지움 |
| `__Host-hopae_txn` | 포털 호스트 | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | 로그인 트랜잭션 ID. 완료 시 지움 |

지울 때는 같은 이름과 속성에 `Max-Age=0`을 사용합니다. `SameSite`는 항상
`Lax`입니다. 포털 → 애플리케이션 리디렉션은 교차 사이트 최상위 탐색이므로
`Strict`는 싱글 사인온과 콜백을 깨뜨리며, 이를 바꾸는 설정 키는 없습니다.
`cookie.secure=false`(개발 전용)에서는 `__Host-` 접두사를 떼고 `Secure`를
생략합니다. 사전 점검이 경고를 출력하며 위협 모델 항목 TM-02가 적용됩니다.

### 도메인 간 핸드오프

로그인 후(또는 포털에 이미 유효한 세션이 있을 때) Hopae는 저장된 돌아갈 대상에
쿼리 매개변수 하나를 덧붙여 브라우저를 리디렉션합니다.

```text
https://app.example.test/admin/x?_hopae_handoff=<code>
```

그 요청에 대한 게이트웨이의 포워드 인증 호출은 매개변수를 `x-original-url`에
담고 그 호스트의 쿠키를 함께 보냅니다. Hopae는 다음이 모두 성립할 때만 코드를
소비합니다. 1회용이며 60초 이내일 것, 호스트와 경로가 일치할 것, 클라이언트 IP가
일치할 것, 요청에 코드와 함께 저장된 다이제스트와 SHA-256이 같은
`__Host-hopae_bind`가 실려 있을 것(이 쿠키는 이 로그인을 시작한 `302`가 이
호스트에 심은 것이므로 그 브라우저만 갖고 있습니다), 그리고 요청에 **다른**
사용자의 유효한 `__Host-hopae`가 없을 것(같은 사용자의 유효한 핸들은 교체되며,
단계 상승이 핸들을 다시 발급하는 방식이 바로 이것입니다). 그러면 매개변수를 뺀
같은 URL로 `302`를 답하고, 그 호스트용 `__Host-hopae`를 심으며,
`__Host-hopae_bind`를 지웁니다. 업스트림은 매개변수를 절대 보지 못합니다.
`302`는 게이트웨이가 업스트림에 접속하지 않고 중계하며, 이 매개변수를 실은
요청에는 어떤 결정 캐시도 우회합니다. 어떤 실패든 코드를 태워 버리고, 포털로
가는 인증되지 않은 `302`(새 바인딩 쿠키를 심음)로 답하며, 사유(`code_consumed`,
`code_expired`, `code_host_mismatch`, `code_path_mismatch`, `bind_mismatch`,
`session_conflict`)와 함께 `handoff.rejected`를 발생시킵니다.

매개변수 이름 `_hopae_handoff`는 예약되어 있습니다. 같은 이름을 사용하는
애플리케이션은 지원하지 않습니다.

### 포털 진입점

모두 포털 호스트에 있으며 포털 리스너가 제공합니다.

| 메서드와 경로 | 목적 | 보호 |
| --- | --- | --- |
| `GET /login?txn=<id>` | 제공자 선택. 제공자가 하나만 활성화되어 있으면 즉시 리디렉션 | `txn`이 존재하고, 만료되지 않았으며, 클라이언트 IP 정책에 맞아야 함. `__Host-hopae_txn` 설정 |
| `POST /login/<provider>` | 제공자 흐름 시작 | `txn` 쿠키에 묶인 CSRF 토큰. `Origin`은 포털 출처여야 함 |
| `GET /callback/<provider>` | 제공자 리디렉션 URI | `state` ↔ `txn` 쿠키 ↔ 제공자, PKCE, nonce, 발급자 |
| `GET /logout` | 확인 페이지 | 폼만 표시. 상태 변경 없음 |
| `POST /logout` | 이 세션 종료(`scope=this`, 기본값) 또는 사용자의 모든 세션 종료(`scope=all`, M2) | CSRF 토큰, `Origin` 검사, 유효한 포털 핸들 필요 |
| `GET /stepup?txn=<id>`(M5) | 2차 인증 요소 챌린지 | `/login`과 동일 |
| `GET /healthz` | 생존 확인(프로세스가 서비스 중이면 `200`, 본문에 저장소 상태) | 없음. 비밀 정보 없음 |
| `GET /_hopae/verify` | 여기서는 제공하지 않음 | `404` |

포털은 클라이언트로부터 돌아갈 URL을 절대 받지 않습니다. 돌아갈 대상은
트랜잭션을 만든 verify 호출의 `x-original-url`에서 옵니다. 포털 리스너에서는
모든 `x-original-*` 헤더가 브라우저 입력이며 절대 참조하지 않습니다. 게이트웨이는
프록시하는 요청에서 `x-forwarded-*`를 다시 생성하지만, 외부 인가가 없는
라우트에서는 `x-original-*`를 그대로 통과시키기 때문입니다.

### 캐시 의미론(HC-1)

캐시 가능 여부는 Hopae가 결정하고, 게이트웨이는 그것을 따르기만 합니다.

| 응답 | `cache-control`과 `x-hopae-fresh-until` | HC-1이 있는 게이트웨이 |
| --- | --- | --- |
| `200`, 이 애플리케이션에서 결정이 경로와 메서드에 무관한 경우 | `private, max-age=N`, 여기서 `N = min(app.verify_cache_seconds, 30)`. `x-hopae-fresh-until` = `min(now + N, 핸들 만료, 세션 만료)`를 Unix 밀리초로. 기본값 `N = 0`이며 이때는 `no-store`를 내보내고 마감은 없음 | **(게이트웨이 설정 세대, 라우트 ID, 해석된 클라이언트 IP, 정규화한 외부 스킴과 호스트(authority), 나열된 요청 헤더와 정적 요청 헤더의 SHA-256)**을 키로 신원 헤더를 캐시하고 `x-hopae-session`과 `x-forwarded-user`로 태그를 붙여 `min(N, 라우트 decision_cache_ms, fresh-until − now)` 동안 보관. 응답에 `set-cookie`가 있으면 절대 캐시하지 않음 |
| `200`, 경로나 메서드에 따라 달라지는 경우(단계 상승 규칙, 경로 규칙) | `no-store` | 절대 캐시하지 않음 |
| 경로나 쿼리에 `_hopae_handoff`가 들어 있는 모든 요청 | `no-store` | 조회도 저장도 하지 않음. 핸드오프는 항상 Hopae에 도달해야 함 |
| `302`, `401`, `403`, `400`, `503` | `no-store` | 절대 캐시하지 않음 |

제로 트러스트 기본값은 양쪽 모두 `N = 0`입니다. 모든 요청이 Hopae에 도달합니다.
운영자는 애플리케이션별, 라우트별로 제한된 지연(staleness)을 선택적으로 켭니다.
취소 후 허용이 살아남을 수 있는 최대 시간은 **합**
`decision_cache_ms + cache.local_ttl_ms + stale_if_error_ms`이며, 각 항의
기본값은 `0`이고, `x-hopae-fresh-until`을 절대 넘지 않습니다. 어느 항이든 0이
아니면 `hopae --check`가 이 한계를 출력합니다. 무효화 채널(HC-2)은 보통 훨씬
일찍 제거하지만 보장은 아닙니다.

### 무효화 채널(HC-2)

Redis/Valkey pub/sub 채널 `hopae:<namespace>:invalidate`입니다. 메시지는 512바이트
이하의 JSON입니다.

```json
{"v": 1, "kind": "session", "id": "s_01hz…", "gen": 7, "at": 1760000000}
{"v": 1, "kind": "user", "id": "u_01hz…", "gen": 3, "at": 1760000000}
{"v": 1, "kind": "all", "gen": 42, "at": 1760000000}
```

Hopae는 세션 종료와 핸들 취소, 모든 기기에서 로그아웃, 사용자 비활성화나 차단,
모든 `authz_version` 변경(그룹이나 역할 제거), 모든 정책이나 설정 변경(`all`),
키 교체 시 발행합니다. `gen`은 변경 후 세션, 사용자 또는 설정의 세대 번호입니다.
구독자는 해당 태그에 대해 마지막으로 본 세대보다 먼저 읽기를 시작한 캐시 저장을
버리므로, 진행 중이던 오래된 응답이 제거된 항목을 다시 채우지 못합니다.
구독자(다른 Hopae 인스턴스, HC-2가 있는 게이트웨이)는 해당 ID로 태그된 항목을
제거합니다. 전달은 최선 노력이며, 신선도 마감이 보장입니다. 연결이 끊긴
구독자는 다시 연결할 때 캐시 전체를 비웁니다.

### 버전 관리

| 변경 | 계약 버전 | 비고 |
| --- | --- | --- |
| 신원 헤더, 사유 코드, 선택적 요청 헤더 추가 | 마이너(`1.x`) | 게이트웨이는 알 수 없는 헤더를 무시함 |
| 쿠키 이름이나 속성 변경, 헤더 이름 변경이나 제거, 상태 코드 의미 변경, 핸드오프 매개변수 변경 | 메이저(`2.0`) | Hopae는 `x-hopae-contract: 2`로 답함. v1로 설정된 게이트웨이는 HC-3의 요청 헤더나 운영자의 호환성 매트릭스로 탐지함 |

호환성 매트릭스(릴리스마다 갱신):

| Hopae | 계약 | Hangang 0.2.6(수정 없음) | HC-3이 적용된 Hangang |
| --- | --- | --- | --- |
| 0.1.x | 1.0 | 개발 전용(`gateway.allow_unauthenticated_caller = true`). 속도 제한은 `403`으로 나타남 | 운영: 호출자 키 검증. 모든 M1 시나리오 |

## 수정하지 않은 Hangang 0.2.6에서 동작하는 것

2026-10-09에 게이트웨이 소스(`src/proxy.rs`의 `authorize`,
`forward_auth_context`; `src/config.rs`의 `ExternalAuth` 검증과
`authentication_identity_headers`)에 대해 확인했습니다.

| 필요 | 수정 없는 Hangang | 메커니즘 |
| --- | --- | --- |
| 모든 요청마다 verify, 타임아웃이나 예상 밖 상태에서 거부 처리 | 예 | `GET auth.url`, `timeout_ms`, `2xx`/`3xx`/`401`/`403` 이외는 모두 `503` |
| 쿠키 심기를 동반한 로그인 리디렉션 | 예 | `forward_response: true`가 `3xx`/`401`/`403`을 `location`, `set-cookie`, `www-authenticate`, `content-type`, `cache-control`과 함께 중계하고 `referrer-policy: no-referrer`를 추가함 |
| 신원 헤더 주입과 게이트웨이 전체 제거 | 예 | `response_headers`를 업스트림 요청에 복사. 선언된 모든 이름의 합집합을 라우팅 전에 모든 수신 요청에서 제거 |
| 원래 URL, 클라이언트 IP, 호스트, 프로토콜 | 예 | `x-original-url`, `x-original-uri`, `x-original-method`, `x-forwarded-{method,uri,proto,port,for,host}`, `x-real-ip`, `x-original-client-ip`를 생성. 클라이언트 복사본은 교체 |
| 도메인 간 핸드오프 | 예 | Hopae가 verify 호출을 통해 `_hopae_handoff` 매개변수를 가로챔. `302` + `set-cookie`가 중계되고 업스트림에는 접속하지 않음 |
| HTTP/2에서 분할된 `cookie` 필드 | 예 | 인가 전에 RFC 9113에 따라 결합 |
| 경로 범위 지정 | 예, 라우트 단위 | `path_prefix`, `path_match`, `priority`. 제외 규칙 없음 |
| 바깥 계층의 로그인 제한 | 부분적 | 포털의 `/login`과 `/callback/*`에 클라이언트 IP별 `settings.path_failure_bans`. `settings.path_rate_limits`는 전역 예산 |
| `200`에서의 세션 갱신 쿠키 | 예 | `forward_response`로 최대 16개의 `set-cookie` 값을 중계 |
| 미인증 `302`에서의 브라우저 바인딩 쿠키 | 예 | 중계되는 `3xx` 응답의 `set-cookie` |
| verify 엔드포인트의 호출자 인증 | **아니요** | 정적 요청 헤더를 설정할 수 없음. 호스트 네트워크 게이트웨이에서는 루프백이 모든 로컬 프로세스를 받아들임. 그래서 HC-3은 M1의 일부임 |
| verify 호출의 정규 경로 | 아니요 | 라우트는 `resource_policy::canonical_path`(한 번 디코딩, 경로 역참조와 인코딩된 구분자 거부)로 선택되지만 `x-original-url`은 원시 경로를 실음. HC-6까지는 Hopae가 같은 규칙으로 정규화함 |
| `retry-after`를 동반한 `429` 중계 | 아니요 | `3xx`/`401`/`403`만 중계됨. `429`는 `503`이 되고 `retry-after`는 버려짐. HC-8까지 Hopae는 속도 제한을 `rate_limited` 본문을 담은 `403`으로 답함 |
| 외부 인가가 없는 라우트에서 `x-original-*` 제거 | 아니요 | `strip_forwarding_headers`는 `forwarded`, `x-real-ip`, `x-forwarded-*`만 제거함. Hopae의 포털은 `x-original-*`를 무시함(HC-9, 선택) |
| 결정 캐싱 | 아니요 | 모든 요청이 Hopae를 호출함(HC-1) |
| 푸시 무효화 | 캐싱이 없으면 불필요 | HC-1이 생기면 HC-2 |
| verify 호출 전 쿠키 필터링 | 아니요 | `cookie` 헤더 전체가 복사됨(HC-4) |
| 애플리케이션 호스트의 네이티브 로그인/로그아웃 진입점 | 아니요 | Lua에는 `header`, `method`, `path`, `select_backend`, `select_member`, `set_header`, `reject`만 있음. 리디렉션, 응답 헤더, `set-cookie` 없음(HC-5) |
| 설정 소유권 2단계를 위한 필드 범위 라우트 쓰기 | 아니요 | 리비전을 동반한 라우트 전체 `PUT`만 있음. HC-7이 2단계의 전제 조건 |

## 제안하는 게이트웨이 변경

각 변경은 작고, 게이트웨이 워크트리에서 독립적으로 출시할 수 있으며, 수락 기준을
갖습니다. 권장 순서는 **HC-3(M1 필수)**, HC-6, HC-8, HC-4, HC-1, HC-2, HC-9,
HC-5, HC-7입니다. 식별자는 고정이며, 순서는 권장 사항입니다.

| ID | 변경 | 게이트웨이 표면 | 수락 기준 |
| --- | --- | --- | --- |
| HC-3(M1) | 외부 인증 호출의 정적 요청 헤더: `auth.static_request_headers: {"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}` | `ExternalAuth`(설정 검증, `authorize`) | 값은 리터럴이거나 활성화 시 해석되는 환경 변수 참조여야 함. 이름은 생성된 맥락 헤더나 나열된 클라이언트 헤더와 충돌할 수 없음. 같은 이름의 클라이언트 헤더는 버림. 환경 변수 값은 설정 덤프, 로그, 관리 API에 절대 나타나지 않음. 충돌 거부 단위 테스트. verify 호출에 헤더가 실리는 것을 보여 주는 게이트웨이 계층 테스트. 빌드된 게이트웨이에 대해 Hopae 시나리오 004-A8과 013-A1이 통과함. |
| HC-6 | 정규 경로 맥락: 외부 인증 호출에 생성 헤더 `x-hangang-canonical-path`(라우트 선택에 사용한 `canonical_path` 결과. 라우트가 원시 경로로 선택되었으면 없음)와 `x-hangang-route-id`를 실음 | `forward_auth_context` | 게이트웨이가 정규 경로를 사용했을 때만 정확히 존재함. 라우트 선택에 쓴 값과 같음. 클라이언트가 보낸 복사본은 교체함. `/%61dmin/x` 단위 테스트. 이름은 `x-original-*`처럼 예약됨. |
| HC-8 | `forward_response`로 외부 인증 서비스의 `429`를 `retry-after`, `content-type`, `cache-control`, 제한된 본문과 함께 중계 | `authorize` 응답 처리 | `forward_response`가 켜져 있을 때만. `retry-after`는 `429`에서만 중계함. 그 밖의 예상 밖 상태는 여전히 `503`. `path_failure_bans`가 `429`를 셀 수 있음. 중계와 변하지 않은 `503` 매핑에 대한 테스트. |
| HC-4 | 쿠키 필터링: `auth.request_cookies: ["__Host-hopae", "__Host-hopae_bind"]`가 `cookie` 헤더 중 지정한 쿠키만 인증 서비스로 전달 | `authorize` 요청 구성 | 나열된 쿠키 이름만 전송됨. 업스트림은 여전히 모든 쿠키를 받음. HTTP/2로 분할된 쿠키는 먼저 결합함. 형식이 잘못된 쿠키 쌍은 전달하지 않고 버림. 순서와 부재를 다루는 테스트. |
| HC-1 | 라우트별 결정 마이크로캐시: `auth.decision_cache_ms`(기본값 `0` = 끔, 최대 `30000`). `2xx`만 캐시하며 **(설정 세대, 라우트 ID, 해석된 클라이언트 IP, 정규화한 외부 스킴과 호스트, 나열된 요청 헤더와 정적 요청 헤더의 SHA-256)**을 키로 사용. `cache-control: max-age`와 `x-hopae-fresh-until`을 상한으로, `no-store`를 거부권으로 존중. 요청 경로나 쿼리에 `_hopae_handoff`가 있으면 조회도 저장도 하지 않음. 항목은 `x-hopae-session`과 `x-forwarded-user`로 태그하고 그 태그에 대해 마지막으로 본 무효화 세대를 찍음. 라우트별 항목 수 제한. 선택적 `stale_if_error_ms`(기본값 `0`) | `authorize`, 새 캐시 모듈, 지표 | 기본적으로 꺼져 있음. 꺼져 있으면 동작 변화 없음. `no-store`는 절대 캐시하지 않음. 적중 시 동일한 신원 헤더를 재생하되 갱신 쿠키는 절대 재생하지 않음. `set-cookie` 응답은 절대 캐시하지 않음. 핸드오프 요청은 항상 인증 서비스에 도달함(테스트). 다른 클라이언트 IP나 다른 호스트에서 온 요청은 항목에 절대 적중하지 않음(테스트). 항목은 TTL과 `x-hopae-fresh-until` 중 작은 쪽으로 만료. 태그에 대한 나중 무효화보다 먼저 시작된 저장은 버림(테스트). 메모리 제한 강제. 지표 `auth_cache_hits`, `auth_cache_misses`, `auth_cache_evictions`, `auth_cache_stale_fills_rejected`. 설정 활성화 시 캐시를 비움. |
| HC-2 | 무효화 구독자: `auth.invalidation: {"redis_env": "HANGANG_HOPAE_REDIS_URL", "channel": "hopae:prod:invalidate"}`가 HC-1 항목을 태그로 제거하고 메시지의 `gen`을 태그별로 기록 | `security_redis` 연결 패턴을 쓰는 새 구독자 태스크 | `security_redis`와 동일한 TLS 규칙으로 구독. `session`/`user`/`all` 메시지가 루프백 테스트에서 100 ms 안에 해당 항목을 제거하고 태그의 세대를 올림. 다시 연결하면 모든 항목을 제거. 형식이 잘못된 메시지는 세고 무시. 구독자 장애는 조기 제거를 잃는 것 외에 요청 처리에 영향을 주지 않음. |
| HC-9 | `x-forwarded-*`처럼 모든 라우트에서 클라이언트 요청의 `x-original-*`를 제거 | 수신 헤더 처리 | 클라이언트가 보낸 `x-original-*`는 업스트림이나 인증 서비스에 절대 도달하지 않음. 생성된 값은 영향 없음. 외부 인가가 없는 라우트에 대한 테스트. |
| HC-5 | 애플리케이션 호스트의 네이티브 진입점: `auth.entrypoints: {"login": "/_hopae/login", "logout": "/_hopae/logout"}`. 게이트웨이가 `x-hopae-phase: login \| logout`을 실은 verify 호출을 거쳐, 원래 URL을 돌아갈 대상으로 담은 포털행 `302`로 답함 | `authorize` 호출 지점 | 선택 사항. 바인딩 쿠키를 포함해 Hopae 측 구현과 관찰 가능한 동작이 동일. 로그아웃 진입점의 verify 호출은 쿠키를 실음. 게이트웨이 측 상태 없음. 두 진입점과 애플리케이션 라우트와의 경로 충돌에 대한 테스트. |
| HC-7 | 필드 범위 라우트 쓰기: `auth` 블록만 받는 `PUT /v1/routes/http/<id>/auth`와, 그 엔드포인트와 라우트 ID 목록으로 범위가 제한된 API 자격 증명 범위 | 관리 API, 자격 증명 범위 | 범위가 제한된 자격 증명은 다른 어떤 쓰기 엔드포인트도 호출할 수 없고 다른 라우트나 필드를 건드릴 수 없음(테스트). 리비전 CAS 적용. 감사가 범위를 기록. 설정 소유권 2단계의 전제 조건([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md)). |

검토했으나 제안하지 않은 변경: Lua `redirect`/`set_cookie` API(HC-5 대비 이득은
적고 샌드박스의 출력 표면을 넓힘), 전체 URL을 키로 하는 인증 결정 캐싱(SPA에서는
목적을 잃음), 거부 결정 캐싱(로그인 완료를 지연시킴. 인증되지 않은 홍수가
관찰되면 재검토).

## 검증

- 시나리오 007은 실제 게이트웨이를 통해 신원 헤더 주입과 클라이언트 복사본 제거를 증명합니다.
- 시나리오 008은 위 라우트 조각을 게이트웨이 설정 스키마에 대해 검증하고, 경로 범위 지정을 증명하며, 퍼센트 인코딩된 접두사 사례(`/%61dmin/x`)를 다룹니다.
- 시나리오 003은 서로 다른 등록 도메인의 두 호스트에서 게이트웨이를 통한 핸드오프를 증명하며, 같은 IP의 두 브라우저 거부를 포함합니다.
- 시나리오 004는 호출자 키 검사와, 멈춘 의존성 아래에서의 verify 예산을 증명합니다.
- 각 HC는 자체 게이트웨이 테스트와 함께 들어가며, Hopae는 그것을 사용하는 첫 릴리스에서 HC마다 게이트웨이 계층 시나리오를 추가합니다.
