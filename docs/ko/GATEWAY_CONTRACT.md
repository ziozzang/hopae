# 게이트웨이 계약

<!-- translation-status: source=../GATEWAY_CONTRACT.md source-rev=19 status=current -->

[문서 목차](README.md) · [English](../GATEWAY_CONTRACT.md)

이 페이지는 게이트웨이의 포워드 인증 확인과 Hopae 사이의 정확한 와이어 계약을
정의합니다. 엔드포인트, 소비하는 요청 헤더, 응답 코드, 내보내는 신원 헤더, 캐시
의미론, 무효화 채널, 애플리케이션 호스트 진입점, 포털 진입점을 다룹니다. 이
계약은 **계약 v1**로 버전을 매기며(현재 1.1:
[ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md)가
애플리케이션 호스트 진입점과 게이트웨이 변경 HC-12를 추가), 버전 관리 목적상
Hopae 공개 API의 일부입니다([프로세스](PROCESS.md#변경-이력과-버전)).
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
| Hopae | `gateway.caller_key_next_env` | 교체 중에 함께 받아들이는 선택적 두 번째 키. 순서: 모든 Hopae에 설정하고 재시작 → 게이트웨이 헤더를 전환 → `caller_key_env`로 승격하고 해제. 7일이 지나면 사전 점검이 경고합니다 |
| Hopae | `gateway.verify_budget_ms` | verify 한 번에 Hopae가 스스로에게 허용하는 총 시간. 기본값 `400`. 게이트웨이의 `auth.timeout_ms`보다 작아야 합니다 |
| Hopae | `apps[]` | 애플리케이션 호스트(정확한 소문자 이름만, 패턴 없음), `ports`(기본값 `[443]`), 정책. 이들의 합집합이 돌아갈 출처 허용 목록이며, 각 항목은 운영자가 보증하는 자격 증명 목적지입니다. 나열되지 않은 호스트는 거부합니다(`unknown_app`) |
| Hopae | `portal.sso_confirm_new_host` | 기본값 `false`. `true`이면 세션이 각 호스트로 처음 싱글 사인온 핸드오프를 하기 전에 포털이 한 번의 클릭을 요구합니다 |
| Hopae | `handoff.max_recoveries` | 기본값 `3`. 바인딩 쿠키 경쟁에서 복구하기 위해 브라우저를 포털로 되돌려 보낼 수 있는 횟수. 이를 넘으면 중계된 `403` 페이지를 보여 줍니다 |
| Hopae | `apps[].logout_confirm` | 기본값 `true`: 애플리케이션 호스트의 `/_hopae/logout`은 포털의 확인 페이지를 거칩니다. `false`이면 유효한 핸들을 제시한 같은 출처의 문서 탐색에 대해 즉시 세션을 끝냅니다([애플리케이션 호스트 진입점](#애플리케이션-호스트-진입점)) |
| 게이트웨이 | 라우트 `auth.url` | `http://127.0.0.1:8701/_hopae/verify` |
| 게이트웨이 | 라우트 `auth.static_request_headers` | `{"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}`(HC-3) |
| 게이트웨이 | 라우트 `strip_request_cookies` | `["__Host-hopae", "__Host-hopae_bind"]`(HC-12): 설정된 핸들 쿠키와 바인딩 쿠키 이름. verify 호출과 그 밖의 모든 헤더 변경 뒤에, 업스트림이 받는 `cookie` 헤더에서 제거합니다. **라우트 수준** 필드이며 공개 라우트를 포함해 애플리케이션 업스트림에 닿는 모든 라우트에 설정합니다. 보호 라우트에서는 `auth.strip_request_cookies`도 별칭으로 받아들입니다 |
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
  },
  "strip_request_cookies": ["__Host-hopae", "__Host-hopae_bind"]
}
```

`static_request_headers`는 게이트웨이 변경 HC-3이고 `strip_request_cookies`는
HC-12입니다. `strip_request_cookies`는 라우트 수준 필드이며, 브라우저가
`Path=/` 쿠키를 공개 라우트에도 보내므로 **경로 범위 호스트의 공개 라우트를
포함해** 애플리케이션 업스트림에 닿는 모든 라우트에 둡니다.
`auth.strip_request_cookies`는 보호 라우트의 별칭으로 받아들입니다. 제거하면
**안 되는** 유일한 라우트는 관리 콘솔 호스트의 라우트(M4-min)입니다. 그 업스트림은
핸들을 스스로 검증하고 주입된 신원 헤더를 절대 읽지 않는 Hopae 자신의 관리
리스너이며, 조각은 [관리 페이지](ADMIN.md#전제-조건과-설정)에 있습니다. 수정하지 않은 게이트웨이는 두 키를 모두
거부합니다(`deny_unknown_fields`). 그런 게이트웨이는 Hopae 쪽에서
`gateway.allow_unauthenticated_caller = true`를 설정한 개발 환경에서만, 세션
핸들이 업스트림에 도달하는 것을 감수하고 쓸 수 있습니다(위협 TM-40).

경로 범위 보호는 한 호스트에 세 라우트를 사용합니다. 호스트용 공개 라우트
하나, 접두사용으로 우선순위가 더 높은 보호 라우트 하나, 그리고 예약된
`/_hopae` 이름 공간을 위한 보호 라우트 하나입니다. 마지막 라우트가 있어야
[애플리케이션 호스트 진입점](#애플리케이션-호스트-진입점)이 Hopae에
도달합니다(그 백엔드에는 절대 접속하지 않습니다. Hopae는 그 이름 공간에 대해
`2xx`로 답하지 않기 때문입니다). `site-hopae`가 없으면 그런 호스트의
`/_hopae/logout`은 평범한 공개 경로이며, 운영자는 포털 자체의 `/logout`에
의존합니다. **게이트웨이는 경로 접두사를 대소문자를 구분해 대조합니다**:
`/ADMIN/x`는 `site-admin`을 선택하지 않고 `site-public`으로 넘어가 세션 없이
업스트림에 도달하며, `/_HOPAE/logout`도 같은 방식으로 넘어갑니다. 이 패턴은
업스트림이 경로의 대소문자를 구분할 때만 사용하십시오. 대소문자를 구분하지
않는 업스트림(IIS, 일부 프레임워크, 대소문자를 구분하지 않는 파일 시스템)은
게이트웨이 변경 HC-10이 출시될 때까지 호스트 전체를 보호해야 합니다(위협
TM-39).

```json
[
  {"id": "site-public", "access_mode": "public", "host": "app.example.test",
   "path_prefix": "/", "priority": 0, "backends": ["http://127.0.0.1:3000"],
   "strip_request_cookies": ["__Host-hopae", "__Host-hopae_bind"]},
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
            "timeout_ms": 500, "forward_response": true},
   "strip_request_cookies": ["__Host-hopae", "__Host-hopae_bind"]},
  {"id": "site-hopae", "access_mode": "protected", "host": "app.example.test",
   "path_prefix": "/_hopae", "path_match": "segment_prefix", "priority": 20,
   "backends": ["http://127.0.0.1:3000"],
   "auth": {"url": "http://127.0.0.1:8701/_hopae/verify",
            "request_headers": ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"],
            "response_headers": ["x-forwarded-user", "x-forwarded-email", "x-forwarded-preferred-username",
                                 "x-forwarded-groups", "x-hopae-session", "x-hopae-provider",
                                 "x-hopae-auth-time", "x-hopae-expires", "x-hopae-aal", "x-hopae-factors"],
            "static_request_headers": {"x-hopae-contract": "1",
                                       "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}},
            "timeout_ms": 500, "forward_response": true},
   "strip_request_cookies": ["__Host-hopae", "__Host-hopae_bind"]}
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
검증하며, `site-hopae` 라우트와 `strip_request_cookies`는 시나리오 015에서
다룹니다.

사전 점검과 불일치: `hopae --check`는 `auth` 조각과 함께 `cookie.name`에서 유도한
라우트 수준 `strip_request_cookies`(`cookie.secure`가 `false`이면 `hopae`,
`hopae_bind`) 필드를 출력하며, 공개 라우트를 포함한 모든 애플리케이션 호스트
라우트에 설정하라고 안내합니다. 1단계 불일치
보고서([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md),
M2)는 이 필드가 없는 애플리케이션 호스트 라우트를 `strip_request_cookies_missing`으로, 보호
라우트가 접두사만 덮고 `/_hopae` 라우트가 없는 호스트를
`reserved_namespace_unrouted`로 표시합니다.

## 동작

### verify 엔드포인트

게이트웨이 리스너의 `GET /_hopae/verify`입니다. 본문은 없습니다. 응답 하나가
요청 하나를 결정합니다.

**상태 코드 불변식.** 이 리스너에서 Hopae는 신원 헤더를 실은 인증된 허용에
**대해서만** `2xx`로 답합니다. 그 밖의 모든 결과 — 로그인·단계 상승·핸드오프
리디렉션, 핸드오프 실패, 복구 소진, 계정 전환, 거부, 속도 제한, 모호성, 계약
위반, 과부하 — 는 `302`, `401`, `403`, `400`, `503` 중 하나이며, 이 리스너에서
브라우저에 보여 주는 모든 페이지는 중계된 `403` 본문입니다. 이유는 게이트웨이
자체의 규칙입니다. 수정하지 않은 게이트웨이는 `terminal_response`를 설정하지
않는 한 모든 `2xx`를 허용으로 취급해 요청을 업스트림으로 전달하는데, Hopae는 그
설정을 요구하지 않습니다. `x-hangang-auth-terminal`은 절대 내보내지 않습니다.
시나리오 004-11이 허용이 아닌 모든 경로에 걸쳐 이 불변식을 검증합니다.

소비하는 요청 헤더를 Hopae가 평가하는 순서대로 나열합니다.

| 헤더 | 출처 | 필수 | 용도 |
| --- | --- | --- | --- |
| `x-hopae-gateway-key` | 게이트웨이(HC-3) | 예 | **다른 어떤 헤더보다 먼저** 현재 키와, 설정되어 있으면 다음 키와도 상수 시간으로 비교합니다. 불일치나 부재 → `403`(`caller_unauthorized`), 상태는 전혀 건드리지 않으며 횟수를 셉니다. `gateway.allow_unauthenticated_caller = true`(개발 전용)만 이 검사를 면제합니다. |
| `x-hopae-contract` | 게이트웨이(HC-3) 또는 없음 | 아니요 | 게이트웨이가 말하는 계약 메이저 버전. `1` 또는 없음은 v1을 뜻합니다. 더 높은 메이저는 `400`(`contract_unsupported`)으로 답합니다. |
| `x-original-url` | 게이트웨이 | 예 | 클라이언트 요청의 절대 URL(`proto://host[:port]/path?query`). 돌아갈 대상, 핸드오프 매개변수에 사용합니다. 2048바이트 이하, 스킴 `https`(`cookie.secure=false`일 때만 `http` 허용), userinfo 없음, fragment 없음. 호스트 중립 라우트에서는 이 URL의 호스트 부분을 클라이언트가 고르므로 돌아갈 출처 허용 목록에 대해 검사합니다. |
| `x-hangang-canonical-path` | 게이트웨이(HC-6) | 아니요 | 게이트웨이가 라우트 선택에 사용한 디코딩·정규화된 경로. 없으면 Hopae가 게이트웨이의 규칙으로 정규 경로를 직접 계산합니다([ADR-0013](../adr/0013-gateway-adapter-boundary.md)). 둘 다 있는데 서로 다르면 요청을 거부합니다(`canonical_path_mismatch`). 모든 경로 규칙은 원시 경로가 아니라 정규 경로에 대해 매칭합니다. |
| `x-hangang-route-id` | 게이트웨이(HC-6) | 아니요 | 선택된 라우트 ID. 로그에 남기고 애플리케이션 힌트로 사용합니다. |
| `x-forwarded-host` | 게이트웨이 | 예 | 애플리케이션 호스트. `x-original-url`의 호스트와 같아야 합니다. |
| `x-forwarded-proto` | 게이트웨이 | 예 | `__Host-` 쿠키를 심으려면 `https`여야 합니다. |
| `x-forwarded-for` 또는 `x-real-ip` | 게이트웨이(신뢰 프록시로 해석) | 예 | 바인딩, 제한, 이벤트에 쓰는 클라이언트 IP. Hangang은 둘 다 해석된 단일 클라이언트 IP로 설정합니다. |
| `x-original-method` | 게이트웨이 | 아니요 | 로그에 남깁니다. 메서드에 따른 규칙은 이후 작업입니다. |
| `x-hopae-risk-context` | 게이트웨이(ADR-0023) | 아니요 | `risk`가 있을 때 요청의 서명된 네트워크 증거([위험 컨텍스트](#위험-컨텍스트)). 위험 규칙이 있는 애플리케이션에서만 읽음. 클라이언트 헤더가 아님 |
| `cookie` | 클라이언트(나열됨) | 아니요 | Hopae 쿠키(`__Host-hopae`, `__Host-hopae_bind`)만 사용하고 다른 쿠키는 무시합니다. 전체 8 KiB 이하. HC-12가 있으면 게이트웨이는 이 호출 뒤에 업스트림으로 보내는 `cookie` 헤더에서 이 두 이름을 제거합니다. |
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
| `302` | 문서 탐색에 대한 로그인, 재인증(`reauth_required`: 세션의 제공자 인증이 애플리케이션의 `max_auth_age`보다 오래되어 트랜잭션이 포털로 하여금 단일 로그인을 건너뛰고 브라우저를 제공자로 보내게 함. 제공자의 `reauth` 능력이 `max_age`이면 `max_age`와 `prompt=login`을 실어, 아니면 일반 로그인으로. [ADR-0016](../adr/0016-management-console-minimum.md)), 단계 상승, 핸드오프, 애플리케이션 호스트 진입점 리디렉션(`logout_entry`, `already_authenticated`, 직접 `logout`) | `location`(포털 URL, 핸드오프 대상 또는 진입점 대상), `set-cookie`(바인딩 쿠키나 핸들을 심거나 지움), `cache-control: no-store`, `x-hopae-reason` | `referrer-policy: no-referrer`와 함께 클라이언트로 중계합니다. 업스트림에는 접속하지 않습니다. |
| `401` | 인증, 재인증 또는 단계 상승 필요, 문서가 아닌 요청 | `content-type: application/json`, 본문 `{"error":"login_required","login":"https://app.example.test/admin/x"}`(또는 `"reauth_required"`, `"step_up_required"`): `login`은 **요청된 애플리케이션 URL 그대로**입니다. 애플리케이션 호스트의 문서 탐색만이 바인딩 쿠키를 심고 트랜잭션을 시작할 수 있기 때문입니다. `401`은 트랜잭션을 만들지 않고 쿠키도 설정하지 않습니다. `www-authenticate: Hopae realm="auth.example.test"`, `cache-control: no-store` | 클라이언트로 중계합니다. 이를 받은 페이지 스크립트는 창을 `login`으로 이동시킵니다. |
| `403` | 거부: 호출자 키 누락이나 불일치(`caller_unauthorized`), 허용 목록 밖의 호스트(`unknown_app`), 차단된 사용자나 IP, 비활성화된 애플리케이션, 그룹 규칙, 단계 상승 불가, 예약 핸드오프 매개변수를 실은 문서가 아닌 요청(`handoff_parameter_not_allowed`), 모호한 예약 매개변수(`handoff_ambiguous`), 바인딩 경쟁 복구 소진(`handoff_recovery_exhausted`, 브라우저용 작은 HTML 본문), 진입점이 아닌 예약 경로(`reserved_path`), 진입점에 대한 문서가 아닌 요청(`entry_point_not_document`), 요청 출처 밖을 가리키는 진입점 `return`(`return_not_allowed`), **또는 속도 제한**(`{"error":"rate_limited","retry_after":30}`) | `error`를 담은 JSON 본문(문서 탐색의 `handoff_recovery_exhausted`는 HTML), `x-hopae-reason` | 업스트림에 접속하지 않고 본문과 함께 클라이언트로 중계합니다. 수정하지 않은 게이트웨이는 `429`를 `503`으로 바꾸고 `retry-after`를 버리므로 속도 제한에 `403`을 사용합니다. 게이트웨이 변경 HC-8이 있으면 Hopae는 대신 `retry-after`를 실은 `429`로 답합니다(`gateway.rate_limit_status`). |
| `400` | 계약 위반 | `x-hopae-reason` | 클라이언트에 `503`(거부 처리). |
| `503` | Hopae가 결정할 수 없음(저장소 사용 불가, 과부하, verify 예산 초과) | `retry-after`, `x-hopae-reason` | 클라이언트에 `503`(거부 처리). |

`x-hopae-reason`은 게이트웨이 로그를 위한 진단 헤더입니다. `response_headers`에
들어가지 않으며 업스트림이나 클라이언트에 절대 도달하지 않습니다.

Hopae 내부의 결정 순서는 다음과 같습니다. 호출자 키 → 계약 검사 → 돌아갈
대상과 애플리케이션 → 정규 경로 → 예약 경로 인식(`/_hopae/` 이름 공간은
여기서 멈춥니다. 진입점이면 답하고, 그 밖의 예약 경로는 `403 reserved_path`)
→ 예약 매개변수 인식(매개변수를 실은 문서가 아닌 요청은 여기서
`403 handoff_parameter_not_allowed`로 멈춥니다) → 핸드오프 소비(문서 탐색만,
바인딩 쿠키 필요, 새 핸들을 심을 수 있음) → 쿠키 핸들 → 세션 조회 → 핸들과
세션 타이머 → 바인딩 정책 → 사용자 상태와 `authz_version` → 애플리케이션
정책(활성화, 차단, 그룹) → 단계 상승 규칙 → 신원 헤더. 이 모든 과정은 verify
예산(`gateway.verify_budget_ms`, 기본값 400 ms) 안에서 실행되며, 예산을 다
쓰면 `503`으로 답합니다.

### 위험 컨텍스트

`risk`가 설정되면([ADR-0023](../adr/0023-risk-based-step-up.md)) 게이트웨이는 요청에
대한 네트워크 증거를 verify 호출에 덧붙입니다. 아래는 게이트웨이 쪽 계약이며, Hangang은
Sumunjang의 `NetworkEvidence`로 이 값을 만듭니다.

**헤더.** 게이트웨이는 HTTP 또는 HOP1 verify 호출에 `x-hopae-risk-context`를 한 번
보냅니다. 이 헤더는 업스트림으로 보내지 않으며, 같은 이름의 클라이언트 헤더는 라우트에 닿기
전에 게이트웨이가 지웁니다. 값은 다음과 같습니다.

```text
v1.<P>.<T>
P = base64url-nopad(UTF-8 JSON 클레임)
T = base64url-nopad(HMAC-SHA256(K, "hopae-risk-context.v1\n" || P || "\n" || M || "\n" || IP || "\n" || U))
```

값 전체는 최대 2,048바이트입니다.

| 입력 | 값 |
| --- | --- |
| `K` | Hopae의 `risk.context_key_env`(키 교체 중에는 `risk.context_key_next_env`). 32–4,096바이트, 전용 키이며 호출자 키가 아님 |
| `M` | 같은 verify 호출의 `x-original-method`. 게이트웨이가 보내지 않으면 `GET` |
| `IP` | 같은 호출이 `x-forwarded-for`/`x-real-ip`로 전하는 클라이언트 주소의 표준 텍스트 형식(Rust `IpAddr` 표시: `192.0.2.10`, `2001:db8::1`) |
| `U` | 같은 호출의 `x-original-url` 바이트 그대로(핸드오프 매개변수 포함) |

**클레임.** JSON 객체이며 알 수 없는 멤버는 거부합니다.

| 클레임 | 필수 | 값 |
| --- | --- | --- |
| `iat` | 예 | 증거를 얻은 유닉스 초. Hopae는 `|now − iat| ≤ risk.max_skew_secs`(기본 30)만 받음 |
| `level` | 예 | `low`, `elevated`, `high`(아래 대응표) |
| `source` | 예 | `sumunjang` |
| `mode` | 예 | 이 요청에 대한 Sumunjang 모드 `enforce` 또는 `observe` |
| `reason` | 예 | Sumunjang 사유 코드 `[a-z0-9._-]{1,64}`(예: `sumunjang.allowed`, `sumunjang.asn_reputation`) |
| `score` | 아니요 | 0–100, 10 단위로 묶은 증거 점수 |
| `asn` | 아니요 | 클라이언트 ASN(u32) |
| `country` | 아니요 | ISO 3166-1 alpha-2 대문자, 모르면 `XX` |
| `zones` | 아니요 | 일치한 영역 ID 최대 8개. Sumunjang(Pumgye) 존 ID 문자 집합 `[A-Za-z0-9_.:-]{1,128}` 그대로이며 대소문자 구분 |
| `rev` | 아니요 | Sumunjang 정책 리비전(u64) |

**수준 대응(게이트웨이).**

| 증거 | `level` |
| --- | --- |
| 허용, 평판·챌린지 사유 없음, 점수가 게이트웨이 임계값 미만 | `low` |
| 챌린지, 평판·이상 사유, 또는 임계값 이상 점수(`enforce`에서 통과된 요청) | `elevated` |
| `observe` 모드에서 평가했을 때 `enforce`라면 거부되었을 요청, 또는 최고 점수 구간 | `high` |

`enforce`에서 실제로 거부된 요청은 게이트웨이가 먼저 거부하므로 Hopae에 오지 않습니다.

**Hopae의 검사.**

- `apps[].risk`가 있는 애플리케이션에서는 컨텍스트가 있지만 잘못되었으면 `403`과
  `x-hopae-reason: risk_context_invalid`로 답합니다. 형식 오류, 크기 초과, 반복된 헤더,
  알 수 없는 클레임, 틀린 MAC, 다른 메서드·클라이언트·URL, 오래된 `iat`가 여기에 해당합니다.
- 컨텍스트가 없으면 애플리케이션의 `risk.missing`을 따릅니다. `ignore`(기본), `deny`
  (`403 risk_context_missing`), 또는 단계 상승입니다.
- 위험 규칙이 없는 애플리케이션은 헤더를 무시합니다. `risk`가 없으면 Hopae는 헤더를 읽지
  않습니다.

**게이트웨이 동작.**

- `risk_denied`, `risk_context_invalid`, `risk_context_missing`이 담긴 `403`은 다른 `403`과
  같이 전달합니다.
- 위험 규칙이 요구한 단계 상승은 일반 단계 상승 응답(`302` 또는 `401 step_up_required`)입니다.
- Sumunjang에 닿지 못하면 게이트웨이는 수준을 지어내지 않고 헤더를 생략하므로
  `risk.missing`이 적용됩니다.

**테스트 벡터.** 키 `risk-context-key-0123456789abcdef-current`, `M` = `GET`,
`IP` = `192.0.2.10`, `U` = `https://app.example.test/admin/x`, 클레임
`{"iat":1800000000,"level":"elevated","source":"sumunjang","mode":"enforce","reason":"sumunjang.asn_reputation","score":70,"asn":64500,"country":"KR","zones":["corp-vpn"],"rev":418}`(이 바이트열 그대로)이면 `iat` ± 30초 안에서 다음 값이 받아들여집니다.

```text
v1.eyJpYXQiOjE4MDAwMDAwMDAsImxldmVsIjoiZWxldmF0ZWQiLCJzb3VyY2UiOiJzdW11bmphbmciLCJtb2RlIjoiZW5mb3JjZSIsInJlYXNvbiI6InN1bXVuamFuZy5hc25fcmVwdXRhdGlvbiIsInNjb3JlIjo3MCwiYXNuIjo2NDUwMCwiY291bnRyeSI6IktSIiwiem9uZXMiOlsiY29ycC12cG4iXSwicmV2Ijo0MTh9.oIlJD45LbUbFg80GNO6g_delXTIQ_7m2lVOgtIPcDZQ
```

**존이 있는 테스트 벡터.** 키와 입력은 같고 클레임이 `{"iat":1800000000,"level":"low","source":"sumunjang","mode":"observe","reason":"sumunjang.observe.mode","score":20,"country":"KR","zones":["Corp:VPN","legacy.orders.1"],"rev":5}`이면 다음 값입니다.

```text
v1.eyJpYXQiOjE4MDAwMDAwMDAsImxldmVsIjoibG93Iiwic291cmNlIjoic3VtdW5qYW5nIiwibW9kZSI6Im9ic2VydmUiLCJyZWFzb24iOiJzdW11bmphbmcub2JzZXJ2ZS5tb2RlIiwic2NvcmUiOjIwLCJjb3VudHJ5IjoiS1IiLCJ6b25lcyI6WyJDb3JwOlZQTiIsImxlZ2FjeS5vcmRlcnMuMSJdLCJyZXYiOjV9.MOFgcPWLbPgy37fmi01OJnwX7tm6enJ1T5b2lxlLGWA
```

참조 서명 구현은 `hopae::policy::risk::Keys::sign`이며 `policy::risk::tests`가 두 벡터를
검사합니다.

### 신원 헤더

`200`에서만 내보냅니다. 값은 보이는 ASCII이며, ASCII가 아닌 문자는 UTF-8로
퍼센트 인코딩합니다(RFC 3986 비예약 집합은 유지). 값이 없는 헤더는 빈 값으로
보내지 않고 생략합니다.

| 헤더 | 값 | 제한 |
| --- | --- | --- |
| `x-forwarded-user` | 사용자의 수명 동안 안정적인 Hopae 사용자 ID(`u_` + base32 26자) | 64 B |
| `x-forwarded-email` | 기본 이메일. 없으면 생략 | 254 B |
| `x-forwarded-preferred-username` | 사용자 이름 또는 표시 이름 | 256 B |
| `x-forwarded-groups` | `groups.gateway_header`가 켜져 있을 때 쉼표로 구분한 그룹 참조(`grp1:…`, 최대 32개)([그룹](GROUPS.md)). 없으면 생략하며 기본값에서는 항상 생략 | 4 KiB |
| `x-hopae-session` | 세션 ID(`s_` + 26자). 쿠키 핸들이 아닙니다 | 64 B |
| `x-hopae-provider` | 첫 번째 요소의 제공자 ID(`google`). 비밀번호 없는 패스키 세션은 `hopae.passkey`([WebAuthn 패스키](WEBAUTHN.md#비밀번호-없는-로그인)). 설정된 제공자가 가질 수 없는 예약 값입니다 | 64 B |
| `x-hopae-auth-time` | 첫 번째 요소 인증 시각의 Unix 초 | 20 B |
| `x-hopae-expires` | 유휴 만료와 절대 만료 중 이른 쪽의 Unix 초 | 20 B |
| `x-hopae-aal` | `1` 또는 `2`: 제시된 핸들이 발급될 때의 수준([ADR-0008](../adr/0008-second-factor-extension-point.md)). 단계 상승은 핸들을 다시 발급합니다. `apps[].max_emitted_aal = 3`인 애플리케이션에 한해, 세션의 현재 상승이 고보증 패스키이면 `3`([ADR-0018](../adr/0018-aal3-emission.md)). 숫자로 비교하십시오 | 1 B |
| `x-hopae-factors` | 충족한 요소의 쉼표 목록 `kind[:provider]`, 예: `oidc:google,totp` | 256 B |

신원 헤더의 총 바이트는 8 KiB 이하입니다(게이트웨이는 16 KiB를 넘으면
거부합니다). 이 집합이 계약 v1의 전부입니다. 헤더 추가는 마이너 변경, 이름 변경이나
제거는 메이저 변경입니다. 모든 `200`은 추가로 신원 헤더가 아니며
`response_headers`에 절대 선언하지 않는 진단 헤더 두 개를 실어 보냅니다.
`x-hopae-fresh-until`(결정을 만든 권위 있는 읽기 시점 기준의 절대 마감, Unix
밀리초)과 `x-hopae-gen: s<세션 cred_gen>.u<사용자 authz_version>.c<설정
세대>`(그 읽기가 관찰한 세대)입니다.

### 쿠키

| 쿠키 | 호스트 | 속성 | 내용 |
| --- | --- | --- | --- |
| `__Host-hopae` | 각 애플리케이션 호스트와 포털 호스트 | `Path=/; Secure; HttpOnly; SameSite=Lax`, `Domain` 없음, `Max-Age`는 핸들의 남은 절대 수명과 같음 | `v1.` + 무작위 32바이트의 base64url. 세션 하나, 호스트 하나, 발급 수준 하나에 묶인 핸들 |
| `__Host-hopae_bind` | 애플리케이션 호스트. 로그인이나 단계 상승을 시작하는 미인증 `302`가 **요청에 올바른 형식의 값이 없을 때** 심음. 있으면 기존 값을 유지하고 `Max-Age`만 갱신 | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | 무작위 16바이트의 base64url. 이 호스트의 모든 핸드오프 코드가 묶이는 브라우저별 안정적 비밀. 동시 트랜잭션이 공유하며, 어떤 응답도 지우거나 교체하지 않고 `Max-Age`로 만료. 어느 응답도 도착하기 전에 시작한 두 탭은 서로 다른 값을 받고 마지막 응답이 이기며, 진 쪽은 통상의 미인증 `302`로 복구함(핸드오프 절 참조). 최대 `handoff.max_recoveries`회 |
| `__Host-hopae_portal` | 포털 호스트. 첫 포털 방문 시 심고 방문마다 갱신 | `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600` | 무작위 16바이트의 base64url. 브라우저별 안정적 포털 비밀. 각 트랜잭션은 제공자 리디렉션을 내보내는 순간 그 다이제스트를 기록하고 이후 절대 바꾸지 않으며, 콜백과 모든 포털 `POST`는 자신이 다루는 트랜잭션과의 일치를 요구함. 예외는 `POST /login/retry` 하나로, 중단 페이지가 기록한 `retry_bind_sha256`(교체된 쿠키)과 일치해야 함. 트랜잭션별 쿠키는 없음. 올바른 형식이지만 다른 쿠키를 가진 콜백(첫 접촉 경쟁)은 트랜잭션을 소비하고, 제시된 쿠키의 다이제스트를 `retry_bind_sha256`으로 저장하며, CSRF로 보호된 재시도를 한 번 제공함 |

지울 때는 같은 이름과 속성에 `Max-Age=0`을 사용합니다. `SameSite`는 항상
`Lax`입니다. 포털 → 애플리케이션 리디렉션은 교차 사이트 최상위 탐색이므로
`Strict`는 싱글 사인온과 콜백을 깨뜨리며, 이를 바꾸는 설정 키는 없습니다.
`cookie.secure=false`(개발 전용)에서는 `__Host-` 접두사를 떼고 `Secure`를
생략합니다. 사전 점검이 경고를 출력하며 위협 모델 항목 TM-02가 적용됩니다.

### 도메인 간 핸드오프

로그인 후(또는 포털에 이미 유효한 세션이 있을 때) Hopae는 저장된 돌아갈 대상에
쿼리 매개변수 하나를 덧붙여 브라우저를 리디렉션합니다.

```text
https://app.example.test/_hopae/login?return=/admin/x&_hopae_handoff=<code>
```

전달 URL은 항상 애플리케이션 호스트의 로그인 진입점이며, 깨끗한 돌아갈 대상이
`return`의 값입니다(경로 절대 참조. 그 안에서는 `%`, `&`, `+`, `#`만 퍼센트
인코딩하므로 2048바이트까지의 대상이 들어가며, 전송되는 URL은 그 세 배까지
길어질 수 있음). 진입점은 모든 보호 호스트에서 Hopae가 답하므로(호스트 전체 라우트,
또는 경로 범위 호스트의 `site-hopae` 라우트) 대상 자체가 어느 라우트를 선택하든
코드는 교환되고 업스트림에 도달하지 않습니다. 교환은 핸들을 심고 깨끗하게 다시
검증한 대상으로 `302`합니다(ADR-0015 결정 10). 옛 형식 `<대상>?_hopae_handoff=K`는
보호 라우트에서 여전히 교환되지만 Hopae는 더 이상 발급하지 않습니다. 이 문서의
나머지에서 "핸드오프 요청"은 이 요청을 뜻하며, 코드에 기록된 경로는 `return` 대상의
경로입니다.

그 요청에 대한 게이트웨이의 포워드 인증 호출은 매개변수를 `x-original-url`에
담고 그 호스트의 쿠키를 함께 보냅니다. 문서 탐색만이 코드를 소비합니다.
매개변수를 실은 **문서가 아닌** 요청은 어떤 쿠키를 갖고 있든, 유효한 핸들이
있더라도 `403 {"error":"handoff_parameter_not_allowed"}`로 답합니다. 그러지
않으면 게이트웨이가 코드를 포함한 요청을 업스트림으로 전달하기 때문입니다.
코드와 모든 쿠키는 손대지 않으므로 사용자의 문서 탐색은 여전히 성공합니다.
Hopae는 다음이 모두 성립할 때만 코드를 소비합니다. 1회용이며 60초 이내일 것,
호스트와 경로가 일치할 것, 클라이언트 IP가 일치할 것, 요청에 코드와 함께 저장된
다이제스트와 SHA-256이 같은 `__Host-hopae_bind`가 실려 있을 것(이 쿠키는 이
브라우저가 로그인을 시작할 때 이 호스트에 심은 것이므로 그 브라우저만 갖고
있습니다), 코드의 `cred_gen`이 세션의 현재 세대와 같을 것(소비하는 갱신문
안에서 검사하므로 단계 상승이나 취소 전에 만든 코드는 죽습니다), 그리고 요청에
**다른** 사용자의 유효한 `__Host-hopae`가 없을 것. 새 핸들의 수준은
`min(code.issued_aal, session.aal)`이며 소비가 권한을 높이는 일은 결코
없습니다. 같은 세션의 유효한 핸들은 교체되며, 단계 상승이 핸들을 다시 발급하는
방식이 바로 이것입니다. 그러면 매개변수를 뺀 같은 URL로 `302`를 답하고 그
호스트용 `__Host-hopae`를 심으며, `__Host-hopae_bind`는 손대지 않습니다.
업스트림은 매개변수를 절대 보지 못합니다. 문서 탐색은 중계되는 `302`로, 문서가
아닌 요청은 중계되는 `403`으로 답하며 둘 다 업스트림에 접속하지 않고, 아래 인식
규칙에 맞는 요청에는 어떤 결정 캐시도 우회합니다. (바인딩 쿠키 값 자체는
인증된 요청의 통상적인 `cookie` 헤더로 업스트림에 도달합니다. 장악된
애플리케이션 호스트는 같은 호스트 안의 신뢰 문제입니다.)

성공이 아닌 결과는 네 가지로 구분됩니다. **소비된** 코드가 그 코드로 만든
유효한 핸들과 함께 제시되면(프리페치나 재시도된 탐색이 이미 소비한 경우)
쿠키를 전혀 바꾸지 않고 깨끗한 `302`로 답합니다(`code_already_redeemed`).
**다른 사용자**의 유효한 핸들이 있으면
`https://auth.example.test/switch?txn=…`(목적 `switch`)으로 `302`를 답하고,
코드를 태워 버리며, 모든 쿠키를 그대로 둡니다(`session_conflict`). 브라우저에
유효한 핸들이 **없는** 상태에서 **알려진 코드가 어떤 사유로든 거부되면**(탭
사이의 첫 사용 경쟁, 두 호스트가 다르게 본 IP, 오래된 세대, 만료되거나 재사용된
코드) 코드를 태워 버리고, 제시된 바인딩을 유지하며
`recovery_depth = code.recovery_depth + 1`을 갖는 새 트랜잭션으로 가는 통상의
미인증 `302`로 답하므로(깊이는 코드를 만든 트랜잭션에서 복사되어 코드의 행에
실려 다니며 클라이언트에서는 절대 읽지 않음. 알 수 없는 코드는 깊이 0에서
시작하고 IP별 실패 상한으로 제한됨) 포털이 싱글 사인온으로 다시
핸드오프합니다. 태워 버린 코드의 깊이가 이미 `handoff.max_recoveries`와 같으면
트랜잭션을 만들지 않고 작은 HTML 본문을 실은 중계된
**`403`**(`handoff_recovery_exhausted`)으로 답합니다. 위의 상태 코드 불변식에
따라 절대 `2xx`가 아닙니다([ADR-0014](../adr/0014-handoff-recovery-on-any-rejected-code.md)).
모든 거부는 사유(`code_consumed`, `code_expired`, `code_stale_generation`,
`code_host_mismatch`, `code_path_mismatch`, `code_ip_mismatch`, `bind_mismatch`,
`handoff_ambiguous`)와 함께 `handoff.rejected`를 발생시키며, 코드의 클라이언트
IP는 로그인을 시작한 애플리케이션 호스트 verify가 기록한 값이지 포털의 값이
아닙니다.

### 예약 매개변수 인식

Hopae의 소비와 게이트웨이의 캐시 우회(HC-1)가 공유하는 규칙 하나입니다. 쿼리
문자열을 `application/x-www-form-urlencoded` 쌍으로 파싱하고(`&`로 나누고,
이름과 값을 각각 퍼센트 디코딩하며 `+`는 공백으로), **디코딩된** 이름이 정확히
`_hopae_handoff`인 쌍이 핸드오프 매개변수입니다. 따라서
`?%5Fhopae%5Fhandoff=K`는 `?_hopae_handoff=K`와 같은 매개변수입니다. 그런
쌍이 둘 이상이거나 후보 이름에 잘못된 퍼센트 이스케이프가 있으면
**모호**합니다. Hopae는 아무것도 소비하지 않고 요청을
거부하며(`handoff_ambiguous`), 게이트웨이는 캐시를 우회합니다. 게이트웨이는
경로 어디에든 원시 이름이나 퍼센트 인코딩된 이름이 나타나면 추가로 우회합니다.
이 이름은 예약되어 있습니다. 같은 이름을 사용하는 애플리케이션은 지원하지
않습니다.

### 애플리케이션 호스트 진입점

보호된 모든 애플리케이션 호스트에서 두 경로를 Hopae가 verify 호출을 통해
직접 제공하므로([ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md)),
애플리케이션은 자체 코드 없이 링크만 걸면 됩니다.

```text
https://app.example.test/_hopae/login[?return=<같은 출처의 대상>]
https://app.example.test/_hopae/logout[?return=<같은 출처의 대상>]
```

`/_hopae/` 이름 공간 전체가 예약되어 있습니다. 정규 경로가 `/_hopae`와 같거나
`/_hopae/`로 시작하면(ASCII 대소문자 구분 없이 비교) 업스트림에 절대 도달하지
않습니다. 두 진입점은 같은 비교 방식으로 정확히 `/_hopae/login`과
`/_hopae/logout`입니다(`/_HOPAE/Logout`과 `/_hopae/%6Cogout`은 로그아웃
진입점입니다). 그 밖의 모든 예약 경로는 `403 {"error":"reserved_path"}`
(`x-hopae-reason: reserved_path`)이며 상태와 쿠키를 건드리지 않습니다.
`/_hopae/` 아래의 애플리케이션 라우트는 지원하지 않습니다. 예약 경로 인식은
돌아갈 대상과 애플리케이션 검사 뒤(나열되지 않은 호스트는 여전히
`unknown_app`), 예약 매개변수 인식 앞에 실행되며, `/_hopae/login`이 아닌 예약 경로에서는 핸드오프
매개변수를 소비하지도 참조하지도 않으며, `/_hopae/login`에서는 `return` 대상에 대해
교환합니다(아래). 포털 호스트에는 이 이름 공간이
없습니다(`404`).

| 요청 | 응답 |
| --- | --- |
| 어느 진입점이든 문서가 아닌 요청(`document`가 아닌 `sec-fetch-dest`, HTML `Accept`(`text/html` 또는 `application/xhtml+xml`)가 없는 경우, `GET`이 아닌 메서드) | `403 {"error":"reserved_path"}`, `x-hopae-reason: entry_point_not_document`. `set-cookie` 없음, 트랜잭션 없음 |
| `GET /_hopae/login?return=<대상>&_hopae_handoff=<코드>`([위](#도메인-간-핸드오프)의 핸드오프 전달) | 검증된 `return`을 대상으로 한 통상의 교환 규칙(1회용, `return`의 호스트와 경로 일치, 클라이언트 IP, 바인딩 쿠키 다이제스트, 복구 깊이): `set-cookie: __Host-hopae=…`와 함께 `302 Location: <깨끗한 대상>`. 다시 제시된 코드는 쿠키 없이 같은 `302`(`code_already_redeemed`). 거부된 코드는 같은 대상으로 복구 로그인을 시작합니다. 반복되거나 잘못된 `_hopae_handoff`는 `403 handoff_ambiguous`. 그 밖의 모든 예약 경로와 `/_hopae/logout`에서는 매개변수를 무시합니다 |
| 통상의 verify가 허용했을 핸들을 가진 `GET /_hopae/login` | `302 Location: <대상>`. 쿠키 변경 없음. `already_authenticated`. `200`과 마찬가지로 `last_seen_at` 갱신 |
| 그 밖의 `GET /_hopae/login` | 대상으로의 문서 탐색이 받았을 통상의 결과: 바인딩 쿠키를 심고 `return_target`이 대상인 트랜잭션을 만드는 미인증 `302`(핸드오프는 진입점이 아니라 대상에 착지), 단계 상승 `302`, 또는 거부 |
| `GET /_hopae/logout`(기본값 `apps[].logout_confirm = true`) | 제시된 핸들을 통상의 verify처럼 평가한 뒤(바인딩 불일치는 평소처럼 종료하고, 유효하지 않은 핸들은 모든 `302`에서처럼 지움), 목적이 `logout`인 트랜잭션 — **로그아웃 티켓** — 에 대상, 애플리케이션, 제시된 유효한 핸들의 세션(있으면)을 저장하고 `302 Location: https://auth.example.test/logout?txn=<id>`(`logout_entry`)로 답합니다. **쿠키를 지우지 않고 아무것도 취소하지 않습니다**: 유일한 상태 변경은 포털의 CSRF로 보호된 `POST`입니다([포털 진입점](#포털-진입점)). 티켓은 1회용이고 트랜잭션 수명(600초)으로 만료하며 로그인 트랜잭션처럼 `txn.per_ip_per_minute`과 `txn.max_rows`에 집계됩니다 |
| `apps[].logout_confirm = false`, `sec-fetch-site: same-origin`, 유효한 핸들을 가진 `GET /_hopae/logout` | 세션을 즉시 종료합니다(`reason=logout`, 이벤트 `session.terminated`). 같은 호출에서 로그아웃 티켓을 만들어 곧바로 소비하며 이를 대상에 대한 불투명한 참조로 쓰고, `set-cookie: __Host-hopae=; Max-Age=0; …`와 함께 `302 Location: https://auth.example.test/signed-out?txn=<티켓>`으로 답합니다(대상 자체로 보내지 않으며 쿼리에 URL을 싣지 않음). 바인딩 쿠키는 그대로 둡니다. `x-hopae-reason: logout`. 그 밖의 `sec-fetch-site`(없음, `none`, `same-site`, `cross-site`)나 유효한 핸들이 없으면 위 행을 따릅니다. 형제 서브도메인이 위협 모델의 행위자이므로 `same-site`는 제외합니다 |

**대상.** 요청 출처의 `/`, 또는 쿼리 매개변수 `return`(디코딩된 이름이
`return`인 쌍 하나. 예약 매개변수와 같은 방식으로 파싱하며 둘이면 모호함)입니다.
경로 절대 참조(`/path?q`)는 요청 출처에 대해 해석하고, 절대 URL도 받습니다.
결과는 verify 엔드포인트의 돌아갈 대상 검증을 통과하고 요청과 정확히 같은
스킴, 호스트, 포트를 가져야 하며(단지 등록된 출처가 아니라 같은 등록 출처),
예약 핸드오프 매개변수를 실으면 안 되고, 그 정규 경로가 예약되어 있으면 안
됩니다. 절대 `return`은 표준 `scheme://authority/…` 형식이어야 하며(`https:/h/x`,
`https:///h/x`, 역슬래시 권한부는 거부: URL 파서가 원문이 가리키는 것과 다른 목적지로
고쳐 버리기 때문), 예약 이름 공간 검사는 원문뿐 아니라 정규화된 목적지의 정규 경로에도
적용됩니다. 그 밖의 모든 것은 `403 {"error":"return_not_allowed"}`
(`return_not_allowed`)이며 아무것도 만들지 않습니다. 대상은 트랜잭션 안에서만
포털에 도달하며 URL이 그대로 오가는 일은 없습니다(TM-01).

**로그아웃 뒤.** 어느 모드도 보호된 돌아갈 대상으로 리디렉션하지 않습니다.
그러면 로그인이 시작되고, 살아 있는 세션을 가진 제공자는 사용자를 곧바로 다시
로그인시키기 때문입니다. 대신 포털이 로그아웃 완료 페이지를 렌더링합니다(포털
리스너의 `200`. 확인 `POST` 뒤에는 바로, 확인 없는 모드에서는
`/signed-out?txn=<티켓>`으로의 `302` 뒤에). 페이지에는 티켓의 돌아갈 대상으로 가는
"<애플리케이션 표시 이름>에 다시 로그인" 링크가 있으며, 이 대상은 페이지를 렌더링할 때
같은 돌아갈 대상 검증을 다시 통과해야 합니다(더 이상 검증되지 않으면 링크를 표시하지
않음). 리디렉션의 참조는 소비된 로그아웃 티켓(1회용, 600초, 살아 있는 동안만 읽을
수 있음)이며 쿼리에는 URL이 실리지 않습니다(TM-01).

**로그아웃 티켓은 넘길 수 있는 취소 권한입니다.** 티켓 id는 그것이 발급된 세션(만든 사람이 제시한
핸들의 세션이며, 만든 사람이 지정한 다른 세션이 아님)을 가리키는 베어러 값입니다. 포털에서
처음 연 사람의 브라우저에 묶이므로, 아무도 열지 않은 티켓은 다른 사람에게 넘길 수 있고, 그
사람이 확인하면 티켓이 가리키는 세션(만든 사람 자신의 세션)과 확인한 사람 자신의 포털 세션이
끝납니다. 이는 접근을 줄일 뿐이고 그 두 세션에 한정되며 `Origin`과 CSRF 검사를 거친 확인
클릭이 필요하므로 받아들입니다(시나리오 015-A9). 티켓은 1회용이며 600초 뒤 만료됩니다.

**직접 모드는 옵트인이며 탐색 가젯을 받아들입니다.** `sec-fetch-site: same-origin`은
애플리케이션 자신의 출처 문서가 탐색을 시작했음을 증명할 뿐 사용자가 로그아웃하려
했음을 증명하지 않습니다. 자신의 쿼리에서 가져온 URL을 `location`에 대입하는
애플리케이션 페이지(예: `/continue?next=/_hopae/logout`)는 거기로 사용자를 이끈 누구든
클릭 없이 세션을 끝낼 수 있게 합니다. `logout_confirm = false`는 이 잔여 위험을
받아들이는 설정이며, 어느 애플리케이션이든 이를 설정하면 `hopae --check`가 경고합니다.
기본값은 확인을 유지합니다(TM-41, 시나리오 015-A8).

**로그아웃 `302`가 아무것도 지우지 않는 이유.** 지운 핸들은 다음 문서 탐색에서
싱글 사인온이 다시 심으므로 지우는 것은 로그아웃이 아닙니다. 또한 부작용이 있는
`GET`은 모든 교차 사이트 최상위 탐색(`SameSite=Lax`는 그 경우 쿠키를 보냄)과
문서 탐색으로 보이는 프리렌더로 도달할 수 있습니다. 문서가 아닌 요청에 대한
`403`에는 `set-cookie`가 없으므로 교차 사이트 `<img>`는 아무것도 바꾸지
못합니다(TM-41). 포털의 `POST` 뒤에 애플리케이션 호스트의 오래된 쿠키는 그
호스트의 다음 verify가 지우며, 그때 다시 로그인이 필요합니다.

**경로 범위 호스트.** 보호 라우트가 접두사만 덮는 호스트는 `/_hopae/*`를
Hopae로 보내지 않습니다. [라우트 조각 페이지](#hangang-라우트-조각)의
`site-hopae` 라우트를 추가하거나 포털 자체의 `/logout`에 의존하십시오. HC-10
전까지는 그런 호스트에서 접두사의 대소문자 변형이 공개 라우트로
넘어갑니다(TM-39).

### 포털 진입점

모두 포털 호스트에 있으며 포털 리스너가 제공합니다.

| 메서드와 경로 | 목적 | 보호 |
| --- | --- | --- |
| `GET /login?txn=<id>` | 제공자 선택. 제공자가 하나만 활성화되어 있으면 즉시 리디렉션 | `txn`이 존재하고, 만료되지 않았으며, 클라이언트 IP 정책에 맞아야 함. `__Host-hopae_portal`을 심거나 갱신하고 첫 방문 시 그 다이제스트를 트랜잭션에 기록 |
| `POST /login/<provider>` | 제공자 흐름 시작 | 포털 바인딩 쿠키에 묶인 CSRF 토큰. `Origin`은 포털 출처여야 함 |
| `GET /callback/<provider>` | 제공자 리디렉션 URI | `state`로 트랜잭션을 찾음. 포털 바인딩 쿠키가 제공자 리디렉션을 내보낼 때 기록한 다이제스트와 일치해야 함. 제공자 일치, PKCE, nonce, 발급자. 올바른 형식이지만 다른 쿠키는 트랜잭션을 소비하고 재시도 페이지를 표시함 |
| `POST /login/retry` | 포털 바인딩 경쟁 뒤에 같은 돌아갈 대상으로 `recovery_depth + 1`의 새 트랜잭션을 시작 | 중단 페이지에서 발급한 CSRF 토큰, `Origin` 검사. 포털 바인딩 쿠키는 소비된 트랜잭션의 `retry_bind_sha256`(원래 다이제스트가 아님)과 일치해야 함. 소비된 트랜잭션이 `portal_bind_mismatch`로 실패했어야 함. `handoff.max_recoveries`로 제한 |
| `GET /switch?txn=<id>` | `session_conflict` 뒤의 계정 전환 확인. 호스트와 두 계정을 표시 | 폼만 표시. 상태 변경 없음 |
| `POST /switch` | 확인(브라우저가 그 호스트에서 제시한 핸들을 취소하고, 새 코드를 발급하고, 리디렉션) 또는 거절(기존 사용자로 깨끗한 URL로 리디렉션) | CSRF 토큰, `Origin` 검사, 포털 바인딩 쿠키. 트랜잭션의 목적이 `switch`여야 함 |
| `GET /logout[?txn=<id>]` | 확인 페이지. [애플리케이션 호스트 진입점](#애플리케이션-호스트-진입점)의 로그아웃 티켓이 있으면 애플리케이션 이름을 표시하고, `__Host-hopae_portal`을 심거나 갱신하며, 이 첫 방문 때 그 다이제스트를 티켓에 기록(이후 불변) | 폼만 표시. 상태 변경 없음. 알 수 없거나, 소비되었거나, 만료되었거나, 목적이 다르거나(`txn_purpose_mismatch`), 다른 브라우저에 기록된 티켓은 없는 것으로 취급 |
| `POST /logout` | 이 세션 종료(`scope=this`, 기본값) 또는 사용자의 모든 세션 종료(`scope=all`, M2). 유효한 티켓(`txn`)이 있으면 티켓이 가리키는 세션도 종료. 로그아웃 완료 페이지와 함께 `200`으로 답하며, 방금 소비한 티켓이면 이 페이지에 티켓의 검증된 돌아갈 대상으로 가는 "<애플리케이션>에 다시 로그인" 링크가 있음. 그 대상으로의 리디렉션은 없음 | 포털 핸들에, 핸들이 없으면 포털 바인딩 쿠키에 묶인 CSRF 토큰. `Origin` 검사. 유효한 포털 핸들, 또는 기록된 다이제스트가 제시된 포털 바인딩 쿠키와 일치하는 티켓. 티켓은 소비됨(1회용) |
| `GET /signed-out?txn=<id>` | 확인 없는 모드의 로그아웃 완료 페이지. verify `302`가 가리키는 소비된 로그아웃 티켓에서 만들며 같은 "다시 로그인" 링크를 표시 | 읽기 전용. 티켓은 목적이 `logout`이고, 로그아웃으로 소비되었으며, 만료되지 않아야 함. 아니면 만료된 링크 페이지(`400`). 티켓은 불투명한 참조이며 쿼리에 URL이 없음 |
| `GET /stepup?txn=<id>`(M5) | 2차 인증 요소 챌린지 | `/login`과 동일 |
| `GET /healthz` | 생존 확인(프로세스가 서비스 중이면 `200`, 본문에 저장소 상태) | 없음. 비밀 정보 없음 |
| `GET /_hopae/verify` | 여기서는 제공하지 않음 | `404` |

포털은 클라이언트로부터 돌아갈 URL을 절대 받지 않습니다. 돌아갈 대상은
트랜잭션을 만든 verify 호출의 `x-original-url`에서 오며, 로그아웃 티켓도 같은
방식으로 돌아갈 대상을 나릅니다. 포털 리스너에서는
모든 `x-original-*` 헤더가 브라우저 입력이며 절대 참조하지 않습니다. 게이트웨이는
프록시하는 요청에서 `x-forwarded-*`를 다시 생성하지만, 외부 인가가 없는
라우트에서는 `x-original-*`를 그대로 통과시키기 때문입니다.

### 캐시 의미론(HC-1)

캐시 가능 여부는 Hopae가 결정하고, 게이트웨이는 그것을 따르기만 합니다.

| 응답 | `cache-control`과 `x-hopae-fresh-until` | HC-1이 있는 게이트웨이 |
| --- | --- | --- |
| `200`, 이 애플리케이션에서 결정이 경로와 메서드에 무관한 경우 | `private, max-age=N`, 여기서 `N = min(app.verify_cache_seconds, 30)`. `x-hopae-fresh-until` = `min(authoritative_read_at + N, 핸들 만료, 세션 만료)`를 Unix 밀리초로. `x-hopae-gen`은 같은 읽기에서 가져옴. 기본값 `N = 0`이며 이때는 `no-store`를 내보내고 마감은 없음 | **(게이트웨이 설정 세대, 라우트 ID, 해석된 클라이언트 IP, 정규화한 외부 스킴과 호스트(authority), 나열된 요청 헤더와 정적 요청 헤더의 SHA-256)**을 키로 신원 헤더를 캐시하고 `x-hopae-session`과 `x-forwarded-user`로 태그를 붙이며 `x-hopae-gen`을 찍어 `min(N, 라우트 decision_cache_ms, fresh-until − now)` 동안 보관. 응답에 `set-cookie`가 있으면 절대 캐시하지 않음. 태그 중 하나에 대해 마지막으로 본 세대보다 `x-hopae-gen` 구성 요소가 오래된 저장은 버림 |
| `200`, 경로나 메서드에 따라 달라지는 경우(단계 상승 규칙, 경로 규칙) | `no-store` | 절대 캐시하지 않음 |
| 예약 매개변수 인식 규칙에 맞는 모든 요청(디코딩된 쿼리 이름, 모호한 형태, 경로 안의 원시 또는 인코딩된 이름) | `no-store` | 조회도 저장도 하지 않음. 핸드오프는 항상 Hopae에 도달해야 함 |
| 정규 경로가 예약 이름 공간에 있는 모든 요청: `/_hopae`와 같거나 `/_hopae/`로 시작(ASCII 대소문자 구분 없이 비교. 진입점, 그 대소문자·인코딩 변형, 그 밖의 모든 예약 경로, 문서 여부 불문) | `no-store` | 조회도 저장도 하지 않음. 캐시 키가 경로를 제외하므로 적중하면 Hopae가 답하지 않은 채 `/_hopae/logout`이 업스트림으로 전달됨 |
| `302`, `401`, `403`, `400`, `503` | `no-store` | 절대 캐시하지 않음 |

제로 트러스트 기본값은 양쪽 모두 `N = 0`입니다. 모든 요청이 Hopae와 기본
저장소에 도달합니다. 세션이나 결정 상태를 위한 Redis 계층은 없습니다(Redis는
무효화 메시지와 카운터만 나릅니다). Hopae의 로컬 캐시는 옵트인이며, 항목을
채운 권위 있는 읽기의 마감과 세대가 여전히 유효한 동안만 그 항목을 제공합니다.
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

Hopae는 세션 종료와 핸들 취소(둘 다 세션의 `cred_gen`을 올림), 모든 기기에서
로그아웃, 사용자 비활성화나 차단, 모든 `authz_version` 변경(그룹이나 역할
제거), 모든 정책이나 설정 변경(`all`), 키 교체 시 발행합니다. `gen`은 변경 후
세션의 `cred_gen`, 사용자의 `authz_version` 또는 설정 세대이며, `200`이
`x-hopae-gen`으로 보고하는 것과 같은 값입니다. 구독자는 태그별로 본 가장 높은
세대를 기억하고 `x-hopae-gen` 구성 요소가 그보다 낮은 캐시 저장을 버리므로,
진행 중이던 오래된 응답도, 변경을 아직 적용하지 않은 인스턴스도 제거된 항목을
다시 채우지 못합니다. 구독자(다른 Hopae 인스턴스, HC-2가 있는 게이트웨이)는
해당 ID로 태그된 항목을 제거합니다. 전달은 최선 노력이며, 신선도 마감이
보장입니다. 연결이 끊긴 구독자는 다시 연결할 때 캐시 전체를 비웁니다.

캐시를 출시하는 마일스톤부터 세대는 데이터베이스 **에포크**의 범위 안에
있습니다([ADR-0006](../adr/0006-verify-caching-and-invalidation.md)).
`x-hopae-gen`은 `e<16진수 8자리>.s<n>.u<n>.c<n>`이 되고, 모든 메시지는
`"epoch"`를 실으며, 구독자는 최고 세대 표시를 에포크별로 유지하고, 본 적 없는
에포크를 만나면 그 Hopae에서 온 모든 항목을 제거하고 표시를 재설정합니다.
운영자의 복원 절차는 에포크를 다시 생성하므로(`hopae store mark-restored`),
더 낮은 세대로 복원된 데이터베이스가 접근을 넓히지도, 캐싱을 억누르지도
않습니다.

### 버전 관리

| 변경 | 계약 버전 | 비고 |
| --- | --- | --- |
| 신원 헤더, 사유 코드, 선택적 요청 헤더 추가 | 마이너(`1.x`) | 게이트웨이는 알 수 없는 헤더를 무시함 |
| 쿠키 이름이나 속성 변경, 헤더 이름 변경이나 제거, 상태 코드 의미 변경, 핸드오프 매개변수 변경 | 메이저(`2.0`) | Hopae는 `x-hopae-contract: 2`로 답함. v1로 설정된 게이트웨이는 HC-3의 요청 헤더나 운영자의 호환성 매트릭스로 탐지함 |

계약 1.1(ADR-0015)은 애플리케이션 호스트 진입점, 애플리케이션 호스트의 예약된
`/_hopae/` 이름 공간, 사유 코드 `reserved_path`, `entry_point_not_document`,
`return_not_allowed`, `logout_entry`, `already_authenticated`, 그리고 HC-12의
선택적 라우트 필드를 추가합니다. v1.0 게이트웨이는 핸들이 업스트림에 도달하는
채로 계속 동작합니다.

호환성 매트릭스(릴리스마다 갱신):

| Hopae | 계약 | Hangang 0.2.6(수정 없음) | HC-3과 HC-12가 적용된 Hangang |
| --- | --- | --- | --- |
| 0.1.x | 1.1 | 개발 전용(`gateway.allow_unauthenticated_caller = true`). 속도 제한은 `403`으로 나타남. Hopae 쿠키가 업스트림에 도달함 | 운영: 호출자 키 검증, Hopae 쿠키를 업스트림에서 제거. 모든 M1 시나리오 |

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
| 경로 범위 지정 | 예, 라우트 단위, 대소문자 구분 | `path_prefix`, `path_match`, `priority`. 제외 규칙 없음. `resource_guard::path_matches`는 바이트를 비교하므로 보호된 접두사의 대소문자 변형은 공개 라우트를 선택함(HC-10). 인코딩된 구분자, 순회, 반복 슬래시는 라우팅 전에 `400`으로 거부됨 |
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
| 업스트림 요청에서 Hopae 쿠키 제거 | **아니요** | 세션 핸들을 포함한 `cookie` 헤더 전체가 업스트림으로 복사됨. 기준 배포에서 실제로 관찰됨. 따라서 HC-12는 HC-3처럼 운영 라우트의 일부임(위협 TM-40) |
| 애플리케이션 호스트의 로그인/로그아웃 진입점 | 예, Hopae를 통해 | Hopae가 verify 호출 안에서 `/_hopae/login`과 `/_hopae/logout`에 중계되는 `302`나 `403`으로 답함([애플리케이션 호스트 진입점](#애플리케이션-호스트-진입점)). 게이트웨이 변경은 불필요. Lua에는 `header`, `method`, `path`, `select_backend`, `select_member`, `set_header`, `reject`만 있고 리디렉션, 응답 헤더, `set-cookie`가 없으므로 네이티브 형태는 선택 사항으로 남음(HC-5) |
| 설정 소유권 2단계를 위한 필드 범위 라우트 쓰기 | 아니요 | 리비전을 동반한 라우트 전체 `PUT`만 있음. HC-7이 2단계의 전제 조건 |

## 제안하는 게이트웨이 변경

각 변경은 작고, 게이트웨이 워크트리에서 독립적으로 출시할 수 있으며, 수락 기준을
갖습니다. 권장 순서는 **HC-3(M1 필수)**, **HC-12(운영 라우트 필수)**, HC-10,
HC-6, HC-8, HC-4, HC-1, HC-2, HC-9, HC-5, HC-7입니다. 식별자는 고정이며,
순서는 권장 사항입니다.

| ID | 변경 | 게이트웨이 표면 | 수락 기준 |
| --- | --- | --- | --- |
| HC-3(M1) | 외부 인증 호출의 정적 요청 헤더: `auth.static_request_headers: {"x-hopae-contract": "1", "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"}}` | `ExternalAuth`(설정 검증, `authorize`) | 값은 리터럴이거나 활성화 시 해석되는 환경 변수 참조여야 함. 이름은 생성된 맥락 헤더나 나열된 클라이언트 헤더와 충돌할 수 없음. 같은 이름의 클라이언트 헤더는 버림. 환경 변수 값은 설정 덤프, 로그, 관리 API에 절대 나타나지 않음. 충돌 거부 단위 테스트. verify 호출에 헤더가 실리는 것을 보여 주는 게이트웨이 계층 테스트. 빌드된 게이트웨이에 대해 Hopae 시나리오 004-A8과 013-A1이 통과함. |
| HC-12(M1) | 업스트림 요청에서 Hopae 쿠키 제거: **라우트 수준** 필드 `strip_request_cookies: ["__Host-hopae", "__Host-hopae_bind"]`(설정된 핸들 쿠키와 바인딩 쿠키 이름). 백엔드에 닿는 모든 라우트에 허용되며 **공개 라우트도 포함**(`auth`가 있는 라우트에서는 `auth.strip_request_cookies`도 별칭으로 받아들이고, 둘 다 설정하면 검증 오류). `auth`가 있는 라우트에서 외부 인증 호출은 여전히 수정하지 않은 `cookie` 헤더를 받음. 게이트웨이가 업스트림 요청의 결합된 `cookie` 헤더에서 이름이 나열된 이름과 같은 모든 `name=value` 쌍을 제거함([ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md)) | `ExternalAuth`와 라우트 검증, 업스트림 요청 구성 | 선택 필드, 기본값 빈 목록, 없으면 동작 변화 없음. 이름은 비어 있지 않은 RFC 6265 쿠키 이름 토큰이며 중복 없음. HTTP/2로 분할된 필드를 결합한(RFC 9113) 뒤 헤더의 각 쌍에 대해 바이트 단위·대소문자 구분 대조. 나열된 이름의 쌍은 중복을 포함해 모두 제거. 다른 쌍은 바이트, 순서, `; ` 구분자를 유지. **제거는 마지막 단계**: 외부 인증 호출, 모든 요청 헤더 변환, 신원 재주장 뒤, 디스패치 직전과 재시도용 요청 캡처 전에 실행(`Cookie: __Host-hopae=…`를 설정하는 변환이 쿠키를 되살릴 수 없음). 제거하는 라우트에서 **`cookie`는 신원 출력으로 거부**(`response_headers`, 신원 재주장). 파싱은 따옴표 값을 인식(따옴표 안의 `;`는 나누지 않음)하며 공백만으로 구분된 쌍은 모호한 것으로 취급. **모호하면 해당 업스트림 요청의 `cookie` 헤더 전체를 제거**하고 절반만 제거한 채 전달하지 않음. 남는 쌍이 없으면 `cookie` 헤더는 빈 값이 아니라 부재. 인증 호출은 수정하지 않은 헤더를 봄(기록하는 인증 스텁과 에코 업스트림으로 테스트). HC-1 캐시 적중과 공개 라우트에도 제거가 적용됨(미리 채운 항목, 경로 범위 호스트의 공개 경로로 테스트). `set-cookie`와 응답은 건드리지 않음. 필드가 관리 API와 설정 덤프를 왕복함. 첫 번째, 중간, 마지막, 유일, 중복, 부재, 따옴표, 공백 구분, 형식 오류 쌍과 나열된 쿠키를 되살리는 변환에 대한 단위 테스트. 빌드된 게이트웨이에 대해 Hopae 시나리오 015-11이 통과함. |
| HC-6 | 정규 경로 맥락: 외부 인증 호출에 생성 헤더 `x-hangang-canonical-path`(라우트 선택에 사용한 `canonical_path` 결과. 라우트가 원시 경로로 선택되었으면 없음)와 `x-hangang-route-id`를 실음 | `forward_auth_context` | 게이트웨이가 정규 경로를 사용했을 때만 정확히 존재함. 라우트 선택에 쓴 값과 같음. 클라이언트가 보낸 복사본은 교체함. `/%61dmin/x` 단위 테스트. 이름은 `x-original-*`처럼 예약됨. |
| HC-8 | `forward_response`로 외부 인증 서비스의 `429`를 `retry-after`, `content-type`, `cache-control`, 제한된 본문과 함께 중계 | `authorize` 응답 처리 | `forward_response`가 켜져 있을 때만. `retry-after`는 `429`에서만 중계함. 그 밖의 예상 밖 상태는 여전히 `503`. `path_failure_bans`가 `429`를 셀 수 있음. 중계와 변하지 않은 `503` 매핑에 대한 테스트. |
| HC-4 | 쿠키 필터링: `auth.request_cookies: ["__Host-hopae", "__Host-hopae_bind"]`가 `cookie` 헤더 중 지정한 쿠키만 인증 서비스로 전달 | `authorize` 요청 구성 | 나열된 쿠키 이름만 전송됨. 업스트림은 여전히 모든 쿠키를 받음. HTTP/2로 분할된 쿠키는 먼저 결합함. 형식이 잘못된 쿠키 쌍은 전달하지 않고 버림. 순서와 부재를 다루는 테스트. |
| HC-1 | 라우트별 결정 마이크로캐시: `auth.decision_cache_ms`(기본값 `0` = 끔, 최대 `30000`). `2xx`만 캐시하며 **(설정 세대, 라우트 ID, 해석된 클라이언트 IP, 정규화한 외부 스킴과 호스트, 나열된 요청 헤더와 정적 요청 헤더의 SHA-256)**을 키로 사용. `cache-control: max-age`와 `x-hopae-fresh-until`을 상한으로, `no-store`를 거부권으로 존중. 요청이 예약 매개변수 인식 규칙(디코딩된 쿼리 이름, 모호한 형태, 경로 안의 원시 또는 인코딩된 이름)에 맞거나 **정규 경로가 예약 `/_hopae` 이름 공간에 있으면**(`/_hopae`와 같거나 `/_hopae/`로 시작, ASCII 대소문자 구분 없음. `/_HOPAE/Logout`, `/_hopae/%6Cogout` 포함) 조회도 저장도 하지 않음. 항목은 `x-hopae-session`과 `x-forwarded-user`로 태그하고 응답의 `x-hopae-gen`을 찍음. 라우트별 항목 수 제한. 선택적 `stale_if_error_ms`(기본값 `0`) | `authorize`, 새 캐시 모듈, 지표 | 기본적으로 꺼져 있음. 꺼져 있으면 동작 변화 없음. `no-store`는 절대 캐시하지 않음. 적중 시 동일한 신원 헤더를 재생하되 갱신 쿠키는 절대 재생하지 않음. `set-cookie` 응답은 절대 캐시하지 않음. 핸드오프 요청은 미리 채워진 항목이 있어도 `?%5Fhopae%5Fhandoff=K`와 중복 매개변수를 포함해 항상 인증 서비스에 도달함(회귀 테스트). 같은 키의 통상 허용이 미리 채워진 항목이 있어도 `/_hopae/login`과 `/_hopae/logout` 요청, 그 인코딩·대소문자 변형, 그 진입점에 대한 문서가 아닌 요청은 항상 인증 서비스에 도달함(두 진입점에 대한 회귀 테스트). 다른 클라이언트 IP나 다른 호스트에서 온 요청은 항목에 절대 적중하지 않음(테스트). 항목은 TTL과 `x-hopae-fresh-until` 중 작은 쪽으로 만료. 태그 중 하나에 대해 마지막으로 본 세대보다 `x-hopae-gen` 구성 요소가 오래된 저장은 버림(테스트). 최고 세대 표시는 에포크별로 유지하며, 본 적 없는 에포크의 응답은 그 인증 서비스에서 온 모든 항목을 제거하고 표시를 재설정함(복원 테스트). 메모리 제한 강제. 지표 `auth_cache_hits`, `auth_cache_misses`, `auth_cache_evictions`, `auth_cache_stale_fills_rejected`. 설정 활성화 시 캐시를 비움. |
| HC-2 | 무효화 구독자: `auth.invalidation: {"redis_env": "HANGANG_HOPAE_REDIS_URL", "channel": "hopae:prod:invalidate"}`가 HC-1 항목을 태그로 제거하고 메시지의 `gen`을 태그별, 에포크별로 기록 | `security_redis` 연결 패턴을 쓰는 새 구독자 태스크 | `security_redis`와 동일한 TLS 규칙으로 구독. `session`/`user`/`all` 메시지가 루프백 테스트에서 100 ms 안에 해당 항목을 제거하고 태그의 세대를 올림. 본 적 없는 에포크의 메시지는 모든 항목을 제거하고 표시를 재설정함. 다시 연결하면 모든 항목을 제거. 형식이 잘못된 메시지는 세고 무시. 구독자 장애는 조기 제거를 잃는 것 외에 요청 처리에 영향을 주지 않음. |
| HC-9 | `x-forwarded-*`처럼 모든 라우트에서 클라이언트 요청의 `x-original-*`를 제거 | 수신 헤더 처리 | 클라이언트가 보낸 `x-original-*`는 업스트림이나 인증 서비스에 절대 도달하지 않음. 생성된 값은 영향 없음. 외부 인가가 없는 라우트에 대한 테스트. |
| HC-5 | 애플리케이션 호스트의 네이티브 진입점: `auth.entrypoints: {"login": "/_hopae/login", "logout": "/_hopae/logout"}`. 게이트웨이가 `x-hopae-phase: login \| logout`을 실은 verify 호출을 거쳐, 원래 URL을 돌아갈 대상으로 담은 포털행 `302`로 답함 | `authorize` 호출 지점 | 선택 사항. 바인딩 쿠키를 포함해 [ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md)의 Hopae 측 구현(예약 이름 공간, 대소문자 구분 없는 대조, `return` 규칙, 로그아웃 티켓, `GET`에서 쿠키를 지우지 않음, `logout_confirm`)과 관찰 가능한 동작이 동일. 로그아웃 진입점의 verify 호출은 쿠키를 실음. 게이트웨이 측 상태 없음. 두 진입점과 애플리케이션 라우트와의 경로 충돌에 대한 테스트. |
| HC-7 | 필드 범위 라우트 쓰기: `auth` 블록만 받는 `PUT /v1/routes/http/<id>/auth`와, 그 엔드포인트와 라우트 ID 목록으로 범위가 제한된 API 자격 증명 범위 | 관리 API, 자격 증명 범위 | 범위가 제한된 자격 증명은 다른 어떤 쓰기 엔드포인트도 호출할 수 없고 다른 라우트나 필드를 건드릴 수 없음(테스트). 리비전 CAS 적용. 감사가 범위를 기록. 설정 소유권 2단계의 전제 조건([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md)). |
| HC-10 | 보호된 경로 범위 라우트의 대소문자 구분 없는 접두사 대조: 새 라우트 필드 `path_case: "sensitive" \| "insensitive"`. `auth`, `basic_auth`, `jwt_auth` 또는 `access_mode: protected`와 `path_prefix`를 함께 가진 라우트의 기본값은 `insensitive`, 그 밖에는 `sensitive`. 비교는 ASCII 문자만 접고(유니코드 케이스 폴딩 없음) 라우트 선택이 이미 쓰는 정규 경로에 적용하며, 요청 경로는 그대로 전달 | `resource_guard::path_matches`, 라우트 검증, 콘솔 라우트 편집기 | `/ADMIN/x`, `/Admin/x`, `/admin/X`가 보호된 `/admin` 라우트를 선택해 외부 확인이 답함(공개 형제 라우트가 있는 실제 게이트웨이 테스트). `/administrator`는 여전히 `segment_prefix` 라우트에 맞지 않음. 보호된 접두사 라우트에 명시한 `path_case: "sensitive"`는 노출을 명시한 검증 경고와 함께 허용. 공개 라우트는 `insensitive`를 지정하지 않는 한 바이트 단위 대조 유지. `canonical_path`는 변경 없음. Hopae 시나리오 008-A1의 `/ADMIN/x` 단언은 `302`가 됨. |

검토했으나 제안하지 않은 변경: Lua `redirect`/`set_cookie` API(HC-5 대비 이득은
적고 샌드박스의 출력 표면을 넓힘), 전체 URL을 키로 하는 인증 결정 캐싱(SPA에서는
목적을 잃음), 거부 결정 캐싱(로그인 완료를 지연시킴. 인증되지 않은 홍수가
관찰되면 재검토).

## 검증

- 시나리오 007은 실제 게이트웨이를 통해 신원 헤더 주입과 클라이언트 복사본 제거를 증명합니다.
- 시나리오 008은 위 라우트 조각을 게이트웨이 설정 스키마에 대해 검증하고, 경로 범위 지정을 증명하며, 퍼센트 인코딩된 접두사 사례(`/%61dmin/x`)를 다룹니다.
- 시나리오 003은 서로 다른 등록 도메인의 두 호스트에서 게이트웨이를 통한 핸드오프를 증명하며, 같은 IP의 두 브라우저 거부, 인코딩된 매개변수 별칭, 단계 상승 전 코드 경쟁, 계정 전환 확인, 첫 사용 탭 경쟁 복구, 매개변수를 실은 문서가 아닌 요청에 대한 `403`을 포함합니다.
- 시나리오 004는 호출자 키 검사(키 교체 중복 기간 포함)와, 멈춘 의존성 아래에서의 verify 예산을 증명합니다.
- 시나리오 014는 최소 1회 전달과 멈춘 싱크에서의 제한된 적체를 증명합니다.
- 시나리오 015는 실제 게이트웨이를 통해 애플리케이션 호스트 진입점(예약 이름 공간의 모든 변형에 대해 업스트림 요청 0건, 경로 범위 호스트의 `site-hopae` 라우트)과 HC-12(verify 호출은 Hopae 쿠키를 보지만 에코 업스트림은 보지 못함)를 증명합니다.
- 각 HC는 자체 게이트웨이 테스트와 함께 들어가며, Hopae는 그것을 사용하는 첫 릴리스에서 HC마다 게이트웨이 계층 시나리오를 추가합니다.
