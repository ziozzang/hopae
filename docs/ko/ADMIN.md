# 관리

<!-- translation-status: source=../ADMIN.md source-rev=8 status=current -->

[문서 목차](README.md) · [English](../ADMIN.md)

관리 콘솔과 JSON API로 운영자는 사용자를 목록·검색하고, 사용자의 신원·세션·최근
이벤트를 살펴보고, 사용자를 비활성화·활성화하고, 세션 하나 또는 사용자의 모든
세션을 끝내고, 로그인 기록과 감사 기록을 조회하고, 애플리케이션·제공자·저장소·
빌드의 상태를 읽습니다. 이 페이지는 마일스톤
**M4-min**([로드맵](ROADMAP.md#m4-min--관리-콘솔-최소020))의 운영자 안내서이자
참조이며, 결정은 [ADR-0016](../adr/0016-management-console-minimum.md)에 기록되어
있습니다. 콘솔은 Hopae 자신이 제공하는 Hopae 애플리케이션입니다. 관리자는 일반
로그인 흐름으로 로그인하고, Hopae는 모든 콘솔 요청을 자신의 세션 핸들로
인증합니다.

## 전제 조건과 설정

| 항목 | 요구 사항 |
| --- | --- |
| 콘솔 호스트 | 다른 애플리케이션 호스트처럼 게이트웨이에 DNS와 TLS가 있는 콘솔 전용 호스트 이름(예시에서는 `hopae-admin.example.test`) |
| 게이트웨이 라우트 | 백엔드가 관리 리스너이고 계약의 표준 `auth` 블록을 가지며 `strip_request_cookies`가 **없는** 콘솔 호스트의 보호 라우트(조각은 아래에 있으며 `hopae --check`가 출력함) |
| 설정 | `admin.public_url` 설정. 그때만 관리 리스너가 `listen.admin`에 바인딩함 |
| 첫 관리자 | 한 번 이상 로그인한 사용자를 `hopae admin grant`로 부여하거나 `admin.users[]`에 나열([부트스트랩](#부트스트랩과-복구)) |
| 제공자 | `oidc` 제공자. 그 `reauth` 능력이 콘솔 신선도의 의미를 정함: `max_age`면 제공자가 검증한 도전, `unsupported`(`google` 프리셋)면 Hopae 로그인 경과 시간([신선도](#신선도와-재인증)) |
| 제공자 2차 인증 | Hopae 자체 TOTP(다음 마일스톤으로 제안)가 생기기 전까지 콘솔 세션은 단일 요소이므로 관리자 계정에는 제공자 측 2차 인증을 요구 |

키(따로 적지 않으면 최상위 `admin` 객체 아래. 자세한 내용은
[설정 참조](CONFIG.md#관리-콘솔)):

| 키 | 타입 | 기본값 | 의미 |
| --- | --- | --- | --- |
| `listen.admin` | 문자열, 소켓 주소 | `127.0.0.1:8702` | 관리 리스너. `admin.public_url`이 설정된 때만 바인딩. 다른 리스너와 달라야 하며 루프백이 아닌 주소는 경고 |
| `admin.public_url` | 문자열, origin | 없음 | 콘솔의 외부 노출 origin, `https://hopae-admin.example.test`. `https://`(`http://`는 `cookie.secure`가 `false`일 때만)와 소문자 호스트 이름(IP 주소는 안 됨), 선택적 포트이며 경로, 쿼리, 프래그먼트, 자격 증명은 없음. 설정하면 암묵적 애플리케이션 `admin`이 등록됨 |
| `admin.session.idle`, `admin.session.absolute` | 기간 | `30m`, `12h` | 콘솔 호스트의 핸들 단위 타이머(`idle`은 `60s` 이상) |
| `admin.binding.ip`, `admin.binding.ip_prefix_v4`, `admin.binding.ip_prefix_v6`, `admin.binding.ua`, `admin.binding.on_mismatch` | `apps[].binding.*`와 같음 | `strict`, `24`, `64`, `off`, `terminate_session` | 콘솔 핸들의 클라이언트 바인딩 |
| `admin.max_auth_age` | 기간, `30m` 이상 | `12h` | 콘솔 세션의 신선도 한도. 어디서나 하나의 술어: `auth_time ≤ now + 60초` 그리고 `now − auth_time < N`. 최솟값은 600초의 콜백 여유를 지키며 더 작은 값은 설정 오류. `auth_time`이 무엇을 증명하는지는 제공자의 `reauth` 능력에 따름([신선도](#신선도와-재인증)) |
| `admin.require_aal` | `1` 또는 `2` | `1` | 제시된 핸들의 최소 보증 수준. `2`는 호스트 전체에 대한 암묵적 애플리케이션의 단계 상승 규칙도 설정. Hopae에 2차 인증 요소가 생기기 전까지 `2`는 모든 요청을 거부하며 `hopae --check`가 경고 |
| `admin.untrusted_peers` | `refuse`, `as_client` | `refuse` | `trusted_proxies` 밖의 TCP 피어를 리스너가 어떻게 다루는지: 요란하게 거부(`403 untrusted_peer`, 경고, 카운터)하거나 포털처럼 피어를 클라이언트로 취급 |
| `admin.query_budget_ms` | 정수, 100부터 30000 | `2000` | 콘솔 저장소 작업 하나(목록, 검색, 변경)의 마감. 저장소 작업이 마감에 SQLite 안에서 문장을 중단하고 롤백하며 요청은 `503`으로 답함 |
| `admin.users[]` | `{user_id?, email?, role?, note?}` 배열 | `[]` | 시작 시와 `hopae admin import`로 파일에서 심는 부여([파일 심기](#설정-파일의-부여)). `role`은 `admin`(기본) 또는 `viewer`. `user_id`와 `email` 중 적어도 하나 |
| `limits.admin_max_concurrent` | 정수, 1 이상 | `16` | 관리 리스너의 동시 요청 상한. 초과 요청은 즉시 `503` |

콘솔에 관련된 제공자 설정(저장된 제공자 설정, [설정 참조](CONFIG.md#제공자)):
`reauth`(`max_age` 또는 `unsupported`. `google` 프리셋은 `unsupported`)와
`reauth_prompt`(`login` 또는 `none`).

암묵적 애플리케이션 `admin`은 예약되어 있습니다. 그 id를 가진 `apps[]` 항목은
설정 오류이며 콘솔 호스트는 어떤 `apps[].hosts`에도 나타나면 안 됩니다.
`hosts = [admin.public_url의 호스트]`, `ports = [그 포트, 없으면 443]`, 위의
수명과 바인딩, `max_auth_age = admin.max_auth_age`,
`on_authz_change = terminate`, `verify_cache_seconds = 0`,
`logout_confirm = true`로 등록됩니다. 다른 애플리케이션처럼 `hopae --check`와
상태 페이지에 나타납니다.

콘솔 호스트의 게이트웨이 라우트 조각(Hangang. `auth` 블록은 계약의 표준 블록이며,
애플리케이션 라우트와의 유일한 차이는 업스트림이 Hopae라서 핸들이 필요하므로
`strip_request_cookies`가 없다는 점입니다. `hopae --check`는 실제 호스트와 관리 리스너 주소를
넣은 같은 조각을 출력하며, `deploy/`의 Hangang 라우트 파일은 이를 `hopae-admin` 라우트로
싣고 있습니다):

```json
{
  "id": "hopae-admin",
  "access_mode": "protected",
  "host": "hopae-admin.example.test",
  "path_prefix": "/",
  "backends": ["http://127.0.0.1:8702"],
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

게이트웨이 자체의 라우트 수준 제어(클라이언트 주소 정책, 국가 정책)를 콘솔
호스트 앞에 두 번째 계층으로 둘 수 있습니다. Hopae는 그것에 의존하지 않습니다.

### 명령줄 참조

`hopae admin` 명령은 저장소에 직접 실행하며 인스턴스가 실행 중이어도 안전합니다.
인스턴스 잠금을 잡지 않고, 실행 중인 인스턴스는 요청마다 부여를 읽으므로 재시작이
필요 없습니다. 모든 명령은 무엇이든 건드리기 전에 인스턴스가 시작할 때와 같은 읽기 전용
사전 점검을 실행합니다. 데이터베이스를 만들거나 마이그레이션하거나 백업하지 않습니다.
파일이 없거나 바이너리보다 오래된 데이터베이스는 거부되며(`error: database schema
version N is older than this binary (M): start the instance once to migrate`), 사전
점검이 거부하는 데이터베이스도 마찬가지입니다. 바쁜 데이터베이스는 최대 5초까지
기다립니다. 인자는 저장소를 열기 전에 검증합니다. 종료 상태: `0` 성공, `2` 거부된
명령 또는 쓸 수 없는 데이터베이스, `1` 저장소 실패(바쁨, 시간 초과, 읽을 수 없음).
컨테이너에서는 `docker compose run --rm hopae admin list --config
/etc/hopae/hopae.json`으로 실행합니다(이미지의 엔트리포인트가 `hopae`입니다).

| 호출 | 의미 |
| --- | --- |
| `hopae admin grant <user_id 또는 email> [--role admin\|viewer] [--note <text>] [--confirm <user_id>] --config <path>` | 기존 사용자에게 역할(기본 `admin`)을 부여하고 해결된 사용자를 출력합니다(아래의 해결 블록). 이메일은 사용자의 검증된 `primary_email`이어야 합니다. 한 번도 로그인하지 않은 사용자는 존재하지 않습니다(종료 코드 `2`, "먼저 한 번 로그인하십시오"). **권위적이지 않은** 이메일은 해결된 id를 가리키는 `--confirm <user_id>`가 있을 때만 부여합니다(없으면 해결 결과를 출력한 뒤 종료 코드 `2`). 사용자 id에는 확인이 필요 없습니다. 비활성화된 사용자는 거부합니다. `--note`는 최대 256자입니다. 부여는 해결된 `user_id`에 묶이며 다시 해결되지 않습니다. 두 번째 부여는 역할을 갱신하고 취소를 해제하며, 파일 관리 행은 `managed_by = api`가 됩니다. `attrs.actor = cli`인 `admin.grant`를 기록합니다. |
| `hopae admin revoke <user_id 또는 email> --config <path>` | 부여를 취소합니다. 사용자의 다음 콘솔 요청은 `403 not_admin`입니다. 행은 파일 가져오기가 절대 되살리지 않는 묘비(`managed_by = api`)가 됩니다. `admin.revoke`를 기록합니다. |
| `hopae admin list [--all] --config <path>` | 살아 있는 모든 부여를 출력합니다: 사용자 id, 이메일, 역할, `managed_by`, 부여 시각, 부여자, 메모. `--all`은 취소된 행을 취소 정보와 함께 더합니다. 부여가 없으면 아무것도 출력하지 않습니다. |
| `hopae admin import [--force <user_id 또는 email>] --config <path>` | 파일의 `admin.users[]`를 [심기 규칙](#설정-파일의-부여)으로 저장소에 적용하고(같은 가져오기가 시작 시에도 실행됨) 삽입·갱신·취소·변경 없음·강제·건너뜀을 사유와 함께 출력합니다. `--force`는 같은 키 규칙으로 기존 행을 고르고(이메일은 어떤 해결보다 먼저 `source_email`로 묶인 행을 고름) 파일 항목을 `api` 관리 행이나 취소된 행 위에 다시 적용합니다. `attrs.actor = file`인 `admin.grant` / `admin.revoke`를 기록합니다. |
| `hopae admin factors list <user_id 또는 email> --config <path>` | 사용자의 2차 인증 요소(인증 앱, 사용하지 않은 복구 코드, 해시 ID·이름·종류·등급·시각이 있는 패스키)를 출력합니다. 키 자료는 출력하지 않습니다. [WebAuthn 패스키](WEBAUTHN.md#관리)를 보십시오. |
| `hopae admin factors reset <user_id 또는 email> --config <path>` | 사용자의 모든 패스키, 인증 앱, 복구 코드를 폐기하고 모든 세션을 종료합니다. `attrs.actor = cli`인 `admin.factor_reset`을 기록합니다. |
| `hopae admin service-credentials create\|rotate\|promote\|revoke\|list …` | 기계 호출자(Pumgye 정책 v2)를 위한 경로 범위·읽기 전용·mTLS 바인딩 자격 증명입니다. 토큰은 한 번만 출력되고 digest만 저장됩니다. [서비스 자격 증명](SERVICE_CREDENTIALS.md)을 참고하십시오. |

출력은 따로 밝히지 않으면 stdout입니다(시각은 UTC, `-`는 없는 값, 제공자가 준 텍스트의
제어 문자는 `?`로 출력됨). `hopae admin grant`는 해결 블록을 먼저 출력하고 결과를 냅니다.

```text
user_id u_01hzexampleexampleexample0
display_name Example Person
created_at 2026-01-15T09:30:00Z
last_login_at 2026-03-02T11:04:10Z
primary_email person@example.test (verified, authoritative)
identities google:104000000000000000000
granted admin to u_01hzexampleexampleexample0
```

`primary_email`은 `(verified, authoritative)`, `(verified, not authoritative)`,
`(unverified)` 중 하나로 끝나며 주소가 없으면 `(none)`입니다. 같은 부여를 반복하면
마지막 줄 대신 `unchanged`를 출력합니다. 거부는 종료 코드 `2`와 함께 stderr로
나가며, 사용자를 찾았다면 해결 블록은 그래도 출력됩니다.

```text
error: refusing: person@example.test is verified but not authoritative; re-run with --confirm u_01hzexampleexampleexample0 if this is the intended person
error: no such user: sign in once first
error: email not verified
error: user is disabled: enable first
error: --confirm names u_other but the address resolves to u_01hzexampleexampleexample0
```

`hopae admin revoke`는 `revoked admin from <user_id>`(또는 `viewer`),
`no grant for <user_id>`, `already revoked` 중 하나를 출력하며, 두 행에 묶인 주소는
거부합니다(`error: ambiguous binding; use the user id`). `hopae admin list`는 머리글과
부여마다 한 줄을 출력하고 필드는 공백 두 칸으로 구분합니다. 취소된 행(`--all`)은
`  revoked <time> by <who>`로 끝나며 `granted_by`는 사용자 id, `cli`, `file` 중 하나입니다.

```text
USER_ID  EMAIL  ROLE  MANAGED_BY  GRANTED_AT  GRANTED_BY  NOTE
u_01hzexampleexampleexample0  person@example.test  admin  api  2026-03-02T11:06:00Z  cli  on-call
```

`hopae admin import`는 결과마다 한 줄(목록은 사용자 id이며 빈 목록은 콜론 뒤에 아무것도
출력하지 않음)과, 건너뜀 사유마다 영향받은 항목을 출력합니다. 이메일만 있는 항목 뒤에는
그 주소로 묶인 사용자가 붙습니다. 경고는 stderr로 `warning: admin.users[<index>]: <reason>`
형태로 나갑니다.

```text
admin grants imported
  inserted: u_01hzexampleexampleexample0
  updated:
  revoked:
  unchanged:
  forced:
  skipped (revoked at run time): former@example.test → u_01hzformerformerformer00
```

건너뜀 사유는 `changed_at_run_time`과 `revoked_at_run_time`(각각 `changed at run time`,
`revoked at run time`으로 출력됨. 결함이 아니라 기록된 결정), `email_binding_ambiguous`,
`user_email_mismatch`, `email_not_authoritative`, `email_unverified`, `no_such_user`,
`user_disabled`입니다. 어떤 파일 항목과도 맞지 않는 `--force`는 `--force matched no file entry`
경고를 냅니다.

### 부트스트랩과 복구

1. 게이트웨이에 콘솔 라우트(위의 `hopae-admin` 조각)를 등록하고 `admin.public_url`을 설정하고(기본값 `127.0.0.1:8702`가 맞지 않으면 `listen.admin`도), `hopae --check`를 실행한 뒤 Hopae를 재시작합니다. 시작하면 포털과 게이트웨이 줄 외에 `admin listening on <address>`가 출력됩니다.
2. 브라우저에서 `https://hopae-admin.example.test/`를 열고 제공자로 로그인합니다. 콘솔은 `403 not_admin`으로 답하며 로그인한 사용자의 사용자 id와 이메일을 보여 줍니다. 한 번도 로그인하지 않은 사용자는 아직 존재하지 않으므로, 이 단계가 부여에 필요한 사용자를 만듭니다.
3. `hopae admin grant <그 사용자 id>`를 실행합니다. 이메일로 부여할 수도 있습니다. `hopae admin grant person@example.test --confirm <그 사용자 id>`: Google 같은 제공자는 `providers[].authoritative_domains`에 그 도메인을 적지 않는 한 주소에 대해 권위적이지 않으므로, 첫 실행은 해결 블록을 출력하고 종료 코드 `2`로 거부하며, 신원을 확인한 뒤 해결된 id를 지정한 두 번째 실행이 부여합니다. 또는 `admin.users[]`에 사용자를 나열하고 재시작하거나 `hopae admin import`를 실행합니다. 출력된 신원이 의도한 사람의 것인지 확인합니다. 새로 고치면 콘솔이 열립니다.
4. 복구도 같은 명령입니다. 잃어버렸거나 침해된 관리자는 `hopae admin revoke`로 취소하고 다른 사용자에게 부여합니다. 비밀번호, 부트스트랩 토큰, 비상용 자격 증명은 없습니다.

### 설정 파일의 부여

`admin.users[]`는 시작 시와 `hopae admin import`로 하나의 저장소 트랜잭션에서
가져오며, 제공자 가져오기 규칙을 부여에 맞게 적용합니다.

- 모든 항목은 원래의 키(`user_id`, `email`, 또는 둘 다)를 유지하고 먼저 그 키로 기존 행과 **대조**됩니다: `user_id`가 있는 항목은 그 행과, 이메일만 있는 항목은 `source_email`(행을 만들 때 쓴 주소)이 같은 **모든** 행과 — 파일 관리든 명령줄 관리든, 살아 있든 취소되었든, 그 행이 어떤 사용자에 묶여 있든 — 대조됩니다. 그 주소로 묶인 행이 존재하는 동안 주소는 **절대 다시 해결하지 않으므로**, 실행 중 취소된 부여는 파일이 그 주소를 새 보유자에게 부여하는 것을 막습니다(`skipped (revoked at run time)`). 같은 주소로 묶인 행이 둘이면 모호한 바인딩입니다: 항목은 경고와 함께 건너뛰고 `--force`는 `user_id`를 지정해야 합니다.
- 대조된 살아 있는 파일 행은 `role`과 `note`가 갱신됩니다. 항목이 유효하지 않은(`user_id`와 `email`이 다른 사용자를 가리키거나 그 밖에 쓸 수 없는) 대조된 행은 건드리지 않고 경고가 항목을 밝히며, 그 행은 존재하는 것으로 셉니다.
- 대조되지 않은 항목은 같은 트랜잭션 안에서 한 번 해결됩니다: `user_id`로(사용자가 존재해야 함), `email`만으로는 그 검증된 주소를 정확히 한 사용자가 가지고 **그리고** 권위적일 때만, 둘 다로는 같은 사용자를 가리킬 때만. 그 밖의 경우는 항목과 사유(`no_such_user`, `user_disabled`, `email_unverified`, `email_not_authoritative`, `email_binding_ambiguous`, `user_email_mismatch`)를 밝히는 사전 점검 경고와 함께 건너뜁니다.
- 어떤 항목과도 대조되지 않은 살아 있는 파일 행은 취소됩니다(`revoked_by = file`). 파일에서 관리자를 지우면 다음 시작이나 가져오기에서 권한이 사라집니다. 항목이 여전히 가리키는 행은 — 건너뛴 항목이라도 — 부재를 이유로 취소되지 않습니다.
- 명령줄이 만들었거나 마지막으로 바꾼 행(`managed_by = api`)과 묘비(취소된 행)는 가져오기가 절대 건드리지 않으므로 실행 중 취소가 재시작 뒤에도 유지됩니다. `hopae admin import --force <user_id 또는 email>`은 파일 항목 하나를 그런 행 위에 다시 적용하고 기록합니다.
- 파일 항목의 이메일이 이제 행에 묶인 사용자와 다른 사용자의 것이면 사전 점검이 경고합니다. 부여는 묶인 채로 남습니다.

## 동작

### 로그인과 인가

```text
 브라우저                   GW (라우트 hopae-admin)              HP 게이트웨이 리스너         HP 관리 리스너
   │ GET https://hopae-admin.example.test/users                 │                            │
   ├──────────────────────────▶│ GET /_hopae/verify (cookie, …) │                            │
   │                           ├───────────────────────────────▶│ 핸들 없음 또는 세션이 신선하지 않음
   │                           │                                │ → 302 포털 (reauth_max_age 설정)
   │ … SSO 없는 포털 로그인(max_age 제공자면 max_age + prompt=login), auth_time 규칙, /_hopae/login으로 핸드오프 …
   │ GET /users (cookie: __Host-hopae=Ha)                       │                            │
   ├──────────────────────────▶│ verify → 200 [id-hdrs]          │                            │
   │                           ├── 프록시된 요청: cookie Ha, x-forwarded-*, [id-hdrs] ─────────▶│ 피어 신뢰? → 핸들 Ha → 엔진:
   │                           │                                │                            │ 세션, 타이머, 바인딩, 상태,
   │                           │                                │                            │ 신선도 → 부여(사용자) → 역할 → 페이지
   │ 200 페이지                │◀─────────────────────────────────────────────────────────────┤ ([id-hdrs]는 절대 읽지 않음)
```

관리 리스너는 모든 요청을 스스로 인증합니다.

1. TCP 피어를 `trusted_proxies`와 대조합니다. 밖에 있는 피어는 기본값 `admin.untrusted_peers = refuse`에서 거부되고(`403 untrusted_peer`), `as_client`에서는 클라이언트로 취급됩니다. 신뢰된 피어라면 클라이언트 주소와 스킴은 포털 리스너처럼 전달 헤더에서 가져옵니다. 전달된 호스트는 콘솔 호스트여야 합니다(아니면 `404`).
2. 설정된 핸들 쿠키(`__Host-hopae`)를 읽고 verify 엔진이 게이트웨이의 verify와 똑같이 콘솔 호스트의 핸들을 평가합니다: 세션, 핸들과 세션 타이머, 바인딩 정책, `users.status`와 `authz_version`, 신선도 술어를 포함한 암묵적 애플리케이션의 정책. 허용만 진행합니다. 신선도 거부는 콘솔 URL이 있는 `403 auth_too_old`(게이트웨이의 verify와 이 검사 사이에 세션이 늙은 경합)이고, 그 밖의 결과는 콘솔 URL을 `login` 링크로 담은 `403 login_required`입니다. 아무것도 만들지 않고 쿠키도 설정하지 않으며 로그인도 시작하지 않습니다(게이트웨이의 verify가 프록시 전에 이미 로그인, 재인증, 핸드오프를 처리했습니다). 거부는 게이트웨이 리스너와 같은 샘플링된 `verify.denied` 도우미로 집계·기록됩니다.
3. 사용자의 부여를 요청마다 저장소에서 읽습니다. 부여가 없거나 취소되었으면 `403 not_admin`이며 페이지에 사용자 id와 이메일이 표시됩니다. 그다음 역할과 `admin.require_aal`을 검사합니다.
4. 게이트웨이가 주입한 신원 헤더와 전달 헤더 이외의 모든 게이트웨이 맥락 헤더는 절대 읽지 않습니다. 따라서 게이트웨이를 거치지 않고 리스너에 도달한 요청은 유효한 콘솔 핸들 없이는 아무것도 얻지 못합니다.

### 역할

| 역할 | 할 수 있는 것 | 할 수 없는 것 |
| --- | --- | --- |
| `viewer`(읽기 전용 관리자) | 모든 페이지 열기. API의 모든 `GET`. 클라이언트 주소와 이메일을 포함해 관리자와 같은 데이터 보기 | 모든 변경(`403 role_insufficient`, 기록됨) |
| `admin` | viewer가 할 수 있는 모든 것과 사용자 비활성화·활성화, 세션 종료 | 자기 사용자 비활성화(`403 self_target`). 부여와 취소(M4-min에서는 명령줄과 파일만) |

### 신선도와 재인증

- **하나의 술어.** 세션은 `auth_time ≤ now + 60초`이고 `now − auth_time < admin.max_auth_age`일 때 콘솔에 신선합니다(한도와 같은 나이는 신선하지 않음. 60초는 Hopae보다 앞선 제공자 시계를 허용). verify 엔진이 콘솔 호스트의 **모든** verify에서 적용하고, 관리 리스너가 경합 대비책으로 적용하며, 행위자 울타리가 SQL로 적용합니다. 실패하면 문서 탐색은 재인증 요구를 담은 트랜잭션(`reason=reauth_required`)과 함께 포털로 보내지고, 문서가 아닌 요청은 `401 {"error":"reauth_required"}`를 받습니다. 최근에 인증한 세션은 새 도전 없이 들어가고, 오래전 다른 호스트에서 로그인한 세션은 첫 콘솔 진입에서 도전을 받으며, 콘솔 안에서 한도를 넘긴 세션은 다음 탐색에서 도전을 받습니다.
- **출처.** 모든 세션은 `auth_time_source`를 기록합니다: ID 토큰이 유효한 `auth_time`(`now + 60초`보다 늦지 않음)을 담았으면 `provider_claim`, 담지 않았으면 `hopae_completion`(이때 `auth_time`은 Hopae의 로그인이 완료된 순간). 있지만 잘못된 `auth_time` 클레임은 로그인을 실패시킵니다(`invalid_auth_time`). 절대 현재 시각으로 대체하지 않습니다. 마이그레이션 `0003` 이전에 만들어진 세션은 `hopae_completion`입니다. `x-hopae-auth-time`이 저장된 값을 보고합니다.
- **세션 자신의 제공자.** 재인증은 언제나 세션을 만든 제공자(`sessions.provider_id`)로 갑니다: 포털의 선택 화면은 그 제공자만 제공하고 재인증 트랜잭션에서 다른 제공자는 거부합니다. 그 제공자가 비활성화되거나 제거되었으면 포털은 관리자에게 로그아웃하고 다시 로그인하라고 알리며, 그러면 새 세션이(다른 제공자로도 가능) 만들어집니다. 세션의 증거 제공자는 절대 바뀌지 않습니다: 포털 세션이 있는 동안 같은 사용자가 다른 제공자로 하는 일반 로그인은 늘 그랬듯 그 세션을 바꾸지 않고 재사용하며, 다른 제공자의 증거는 오직 새 세션과 함께 옵니다.
- **`max_age` 제공자**(표준 매개변수를 존중하는 범용 OpenID 제공자)에서 콘솔은 `provider_claim` 출처를 요구합니다: 클레임 없이 인증된 세션, 이전 세션, 제공자가 검증된 시각 없이 자신의 단일 로그인으로 끝낸 세션은 신선하지 않으며 첫 콘솔 진입에서 도전을 받습니다. 재인증은 제공자가 검증한 도전입니다: 포털은 단일 로그인을 제공하지 않고(포털 핸들은 유지), authorize 요청은 `max_age=<초>`와 `prompt=login`(`reauth_prompt`가 `none`이 아니면)을 실으며, 돌아온 ID 토큰은 `auth_time`을 담아야 하고 그 시각은 600초의 여유(트랜잭션 수명이므로 핸드오프 뒤 첫 콘솔 verify도 신선함. `admin.max_auth_age`가 `30m` 이상인 이유)를 둔 술어를 만족해야 합니다. 아니면 로그인이 실패하고(`reauth_auth_time_missing`, `reauth_not_fresh`) 아무것도 만들어지지 않습니다.
- **`unsupported` 제공자**(`google` 프리셋: Google은 재인증 요청을 지원하지 않는다고 문서화함)에서 콘솔 신선도는 **Hopae 로그인 경과 시간**입니다: Hopae 자신의 로그인이 완료된 뒤 지난 시간. 재인증은 포털에서 단일 로그인 없이 하는 일반 제공자 로그인이며, 제공자는 자신의 세션으로 조용히 끝낼 수 있고 Hopae는 이를 알 수 없습니다. 이것이 문서화된 잔여 위험입니다: 관리자 계정에 제공자 측 2차 인증을 강제하고, 다음 마일스톤으로 제안된 Hopae 자체 TOTP를 기대하십시오. `hopae --check`는 활성 제공자마다 능력과 그에 따른 `admin.max_auth_age`의 의미를 출력합니다.
- **성공하면** 같은 사용자의 기존 세션이 재인증됩니다: `auth_time`과 `auth_time_source`가 갱신되고, 인증 요소 항목이 추가되며, 자격 증명 세대가 올라가고, 모든 핸들이 취소되었다가 일반 핸드오프로 다시 발급됩니다(다른 애플리케이션은 단일 로그인으로 조용히 다시 핸드오프됨. 회전 중에 진행 중이던 탐색이 아닌 요청은 한 번 실패할 수 있음). 다른 사용자이거나 살아 있는 세션이 없으면 일반 새 세션이 됩니다.
- `admin.require_aal = 2`는 수준 2로 발급된 핸들을 요구합니다([ADR-0008](../adr/0008-second-factor-extension-point.md)). Hopae에 2차 인증 요소가 생기기 전에는 모든 요청을 거부하므로 기본값은 `1`입니다.
- 콘솔 핸들은 자체 수명(기본 유휴 `30m`, 절대 `12h`)과 strict 클라이언트 주소 바인딩을 가지며, `on_authz_change = terminate`는 사용자의 인가 데이터가 바뀌면 콘솔 세션을 끝냅니다.

### 로그아웃

모든 페이지는 애플리케이션 호스트 로그아웃 진입점인
`https://hopae-admin.example.test/_hopae/logout`로
연결됩니다([게이트웨이 계약](GATEWAY_CONTRACT.md#애플리케이션-호스트-진입점)).
포털의 확인 페이지가 세션을 끝내며, 다른 모든 호스트의 접근도 함께 끝납니다.

### 거부

| 코드 | 상태 | 시점 | 이벤트 |
| --- | --- | --- | --- |
| `untrusted_peer` | `403` | TCP 피어가 `trusted_proxies` 밖에 있고 `admin.untrusted_peers = refuse`. 쿠키를 읽기 전에 답함 | 샘플링된 `verify.denied`(`reason=untrusted_peer`), 속도 제한된 경고 |
| `login_required` | `403` | 유효한 콘솔 핸들 없음(직접 연결, 잘못 설정된 라우트, 게이트웨이 검사와 이 검사 사이에 끝난 세션). JSON 본문의 `login`은 콘솔 URL | 엔진의 사유가 담긴 샘플링된 `verify.denied` |
| `not_admin` | `403` | 유효한 세션이지만 살아 있는 부여 없음 | `admin.denied`(`reason=not_admin`) |
| `role_insufficient` | `403` | 읽기 전용 관리자가 변경을 시도함 | `admin.denied` |
| `auth_too_old` | `403` | 리스너에서 신선도 술어가 실패함(경합. 보통은 게이트웨이의 verify가 먼저 재인증으로 보냄). 페이지는 콘솔 URL로 연결 | `admin.denied` |
| `aal_insufficient` | `403` | 핸들 수준이 `admin.require_aal`보다 낮음 | `admin.denied` |
| `self_target` | `403` | 관리자가 자기 사용자를 비활성화하려 함 | `admin.denied` |
| `csrf_rejected` | `403` | 폼 토큰 또는 `Origin` 검사 실패 | `csrf.rejected`(`purpose=admin`, `cause=token` 또는 `origin`) |
| `actor_revoked` | `403` | 쓰기가 실행될 때 행위자의 세션, 핸들, 사용자 상태, 인가 기준, 신선도, 수준, 부여가 더 이상 울타리를 만족하지 않음(트랜잭션 안에서 거부됨) | `admin.denied` |
| `invalid_cursor`, `invalid_filter`, `invalid_id` | `400` | 형식이 잘못된 페이지 커서, 필터 값, 식별자 | 없음 |
| `not_found` | `404` | 알 수 없는 사용자나 세션 id. 알 수 없는 경로. 콘솔 호스트가 아닌 전달 호스트 | 없음 |
| `payload_too_large` | `413` | 본문 64 KiB 초과 또는 쿼리 문자열 4 KiB 초과 | 없음 |
| `header_too_large` | `431` | `cookie` 헤더 줄의 합이 8 KiB 초과 | 없음 |
| `method_not_allowed` | `405` | 알려진 경로에 다른 메서드(`allow` 헤더가 올바른 메서드를 알려 줌). 사전 요청 `OPTIONS`는 CORS 헤더 없는 `404` | 없음 |
| `overloaded` | `503` | `limits.admin_max_concurrent` 도달 | 없음 |
| `store_unavailable` | `503` | 기본 저장소가 답하지 못하거나 저장소 작업이 `admin.query_budget_ms`에 닿아 중단되고 롤백됨: 거부 처리 | 없음 |

### 장애 시 동작

| 조건 | 콘솔 | 운영자가 보는 것 |
| --- | --- | --- |
| 기본 저장소 사용 불가 | 모든 요청 `503 store_unavailable`. 아무것도 캐시하지 않음 | error 로그, `hopae_store_errors_total` |
| 콘솔 라우트가 없거나 `auth`가 없음 | 브라우저가 핸들 없이 리스너에 도달: 콘솔 링크가 있는 `403 login_required`. 로그인은 시작되지 않음 | `hopae --check`가 조각을 출력. `gateway.admin_url`과 읽기 전용 토큰이 있으면 `console_route_without_auth` 경고 |
| 콘솔 라우트가 Hopae 쿠키를 제거함 | 리스너가 핸들을 보지 못함: 로그인 성공 뒤 모든 요청이 `403 login_required` | `gateway.admin_url`과 읽기 전용 토큰이 있으면 `hopae --check`가 `console_route_strips_cookies` 경고 |
| 게이트웨이가 아닌 피어가 연결함 | 기본값으로 `403 untrusted_peer`. 아무것도 읽지 않고 만들지 않음 | 피어 주소를 밝히는 속도 제한된 경고, `hopae_admin_denied_total{reason="untrusted_peer"}` |
| 신뢰된 주소로 관리 리스너에 직접 도달 | 유효한 핸들 외에는 요청의 어떤 것도 신뢰하지 않음. 핸들이 없으면 `403 login_required`이고 상태 변화 없음 | 카운터 `hopae_admin_denied_total{reason}` |
| `max_age`로 선언된 제공자가 그것을 존중하지 않음(`auth_time` 없음 또는 오래됨) | 재인증 실패(`reauth_auth_time_missing`, `reauth_not_fresh`). `reauth` 설정을 `unsupported`로 바로잡기 전까지 그 제공자로는 콘솔에 들어갈 수 없음 | 제공자를 밝히는 `login.failed` |
| 부여 취소, 사용자 비활성화, 세션 종료 | 다음 요청이 거부됨. 재시작이나 캐시 비우기 불필요 | `admin.denied` 또는 `verify.denied` |

## 관리 API, 콘솔, 관측

### 페이지

| 경로 | 내용 |
| --- | --- |
| `/` | 상태: 애플리케이션, 제공자, 저장소, 빌드, 설정 세대 |
| `/users?q=&status=&cursor=` | 검색이 있는 사용자 목록 |
| `/users/{user_id}` | 사용자 상세: 신원, 합계와 링크가 있는 살아 있는 세션과 최근 종료된 세션의 미리보기, 링크가 있는 최근 이벤트 50건, 부여. 비활성화·활성화·전체 종료 폼 |
| `/sessions?user_id=&cursor=` | 살아 있는 세션 |
| `/sessions/{session_id}` | 호스트별 핸들을 포함한 세션 상세. 종료 폼 |
| `/events?kind=&outcome=&user_id=&session_id=&client_ip=&since=&until=&cursor=` | 로그인 기록과 감사 기록 |
| `/assets/admin.css` | 스타일시트(유일한 정적 자산) |

페이지는 `Accept-Language`에 따라 영어 또는 한국어로 렌더링됩니다. 모든 응답은
`cache-control: no-store`, `x-content-type-options: nosniff`,
`referrer-policy: same-origin`, `x-frame-options: DENY`, `x-robots-tag:
noindex`, `content-security-policy: default-src 'none'; style-src 'self';
img-src 'self'; form-action 'self'; frame-ancestors 'none'`을 가집니다. 어떤
페이지도 스크립트를 담거나 불러오지 않습니다.

### API

모든 엔드포인트는 관리 리스너의 `/v1/` 아래에 있고 페이지와 똑같이 콘솔 핸들로
인증되며 JSON으로 답합니다. 시각은 유닉스 초이고 식별자는 `u_`, `s_`, `e_`
형식입니다.

| 메서드와 경로 | 역할 | 응답 |
| --- | --- | --- |
| `GET /v1/me` | viewer | `{user_id, email, display_name, role, session_id, auth_time, auth_time_source, aal}` |
| `GET /v1/users?q=&status=&limit=&cursor=` | viewer | `{items: [{user_id, primary_email, email_verified, email_authoritative, display_name, username, status, authz_version, created_at, last_login_at, live_sessions, role}], next_cursor}` |
| `GET /v1/users/{user_id}` | viewer | `{user, identities: [≤ 50개의 {provider_id, subject, email, email_verified, name, first_seen_at, last_seen_at}], sessions_live: [최근 생성순 ≤ 20개 요약], sessions_live_total, sessions_terminated: [최근 ≤ 20개], events: [최근 ≤ 50개], grant: {role, managed_by, granted_at, granted_by, note} 또는 null}`. `sessions_url`과 `events_url`이 필터된 목록을 가리킴 |
| `POST /v1/users/{user_id}/disable` | admin | `{changed, sessions_terminated}`. 비활성화하고 `authz_version`을 올리며 살아 있는 모든 세션을 종료 |
| `POST /v1/users/{user_id}/enable` | admin | `{changed}`. 어떤 세션도 되살리지 않음 |
| `POST /v1/users/{user_id}/sessions/terminate` | admin | `{terminated}` |
| `GET /v1/sessions?user_id=&limit=&cursor=` | viewer | `{items: [{session_id, user_id, primary_email, provider_id, aal, factors, hosts, created_at, last_seen_at, absolute_expires_at, auth_time, auth_time_source, bound_ip, ua_prefix}], next_cursor}`(살아 있는 세션만, 최근 생성순) |
| `GET /v1/sessions/{session_id}` | viewer | 요약과 `handles: [≤ 100개의 {host, issued_aal, created_at, last_seen_at, absolute_expires_at, revoked_at, revoked_reason}]`, `terminated_at`, `terminated_reason` |
| `POST /v1/sessions/{session_id}/terminate` | admin | `{changed}` |
| `GET /v1/events?kind=&outcome=&user_id=&session_id=&client_ip=&since=&until=&limit=&cursor=` | viewer | `{items: [로그 싱크가 쓰는 형식의 이벤트 JSON], next_cursor}` 최신순 |
| `GET /v1/status` | viewer | [상태](#상태) 참조 |
| `POST /v1/subjects/resolve` | viewer | 주체 참조 최대 100개를 표시 정보로 해석. [주체 디렉터리](SUBJECT_DIRECTORY.md) 참조 |
| `POST /v1/subjects/search` | viewer | 선택기를 위한 사람 또는 서비스 주체 검색. [주체 디렉터리](SUBJECT_DIRECTORY.md) 참조 |
| `POST /v1/subjects/lifecycle` | viewer | 지속 커서 이후의 주체 생성과 상태 변경. [주체 디렉터리](SUBJECT_DIRECTORY.md) 참조 |
| `POST /v1/subjects/lifecycle/snapshot` | viewer | 예약된 모든 주체와 상태, 피드 워터마크. [주체 디렉터리](SUBJECT_DIRECTORY.md) 참조 |
| `POST /v1/explain/authentication` | viewer | 인증 검사가 무엇을 왜 답할지. [인증 설명](AUTHENTICATION_EXPLAIN.md) 참조 |
| `POST /v1/groups/search`, `/v1/groups/get`, `/v1/subjects/groups` | viewer | 그룹, 그룹 구성원, 사람의 그룹. [그룹](GROUPS.md) 참조 |
| `POST /v1/groups/create`, `/update`, `/delete`, `/members/add`, `/members/remove` | admin | 사유와 `expected_revision`을 붙인 로컬 그룹 쓰기. [그룹](GROUPS.md) 참조 |
| `POST /v1/groups/projection/snapshot`, `/changes` | viewer | Pumgye를 위한 서명된 멤버십 투영. [그룹](GROUPS.md) 참조 |

오류 본문은 거부 표의 코드를 담은 `{"error": "<code>"}`입니다.

### 페이지 나누기와 필터

- `limit`은 1부터 200까지(기본 50)입니다. `next_cursor`는 불투명하고 변조가 드러나는 위치이며 이어서 조회하려면 `cursor`로 되돌려 줍니다. 위조되거나 오래된 커서는 `400 invalid_cursor`입니다. `next_cursor`가 없으면 순회가 끝난 것입니다.
- 모든 페이지는 최대 **후보 1만 행**만 살펴봅니다: 인덱스 하나의 범위 스캔 한 번 뒤에 그 창 안에서 나머지 필터를 적용합니다. 창의 크기와 마지막 후보는 무엇이 맞았든 알 수 있으므로, 창이 가득 찼으면 페이지가 항목을 하나도 돌려주지 않았더라도 `next_cursor`는 마지막으로 살펴본 후보 뒤를 가리킵니다. 따라서 큰 테이블의 희소한 필터는 짧은 페이지 여러 번이 되지 요청 하나에서 테이블 전체를 훑지 않습니다. 커서 페이지는 자기 위치로 바로 탐색하므로(인덱스에 대한 복합 행 값 비교) 깊은 페이지도 첫 페이지보다 비싸지 않습니다. 밀집한 순회는 약 `rows / limit`번, 희소한 순회는 거기에 최대 `rows / 10,000`번이 더 걸립니다. `admin.query_budget_ms`에 닿은 페이지는 저장소 안에서 중단되고 `503`으로 답합니다.
- 정렬은 고정이며 불변입니다: 사용자는 생성(최신순), 세션은 생성(최신순, `last_seen_at` 표시), 이벤트는 시각(최신순). 순회는 시작 시점에 존재한 행을 그 사이의 활동과 무관하게 건너뛰거나 반복하지 않으며, 순회 시작 뒤에 만들어진 행은 순회에 들지 않습니다.
- 사용자: `q`(최대 128자)는 창 안에서 `primary_email`과 `username`을 접두사로, `display_name`을 부분 문자열로 대조합니다. `status`는 `active` 또는 `disabled`입니다.
- 세션: `user_id`로 한 사용자로 좁힙니다. 살아 있는 세션만 나열합니다(종료된 세션은 사용자 상세에서 미리보기로 봅니다).
- 이벤트: `kind`는 정확한 이벤트 종류(`login.failed`, `admin.user_disable`, …), `outcome`은 `success`, `failure`, `info`, `client_ip`는 정확한 주소 하나(IPv4 매핑 IPv6는 정규화), `since`와 `until`은 유닉스 초(`since`는 `until`을 넘을 수 없음)입니다. 필터는 AND로 결합됩니다. 인덱스는 `session_id`, 없으면 `user_id`, 없으면 `client_ip`, 없으면 `kind`, 없으면 시각 순으로 고르고 나머지 필터는 창 안에서 적용합니다.

### 상태를 바꾸는 요청

- HTML 폼: `application/x-www-form-urlencoded`의 `POST`, 페이지에서 발급된 `csrf` 필드(제시된 핸들에 바인딩, 목적 `admin`, 10분 유효), `admin.public_url`의 origin과 같은 `Origin` 헤더. 핸들 쿠키는 `SameSite=Lax`이므로 교차 사이트 폼 전송에는 애초에 실리지 않습니다.
- JSON API: `content-type: application/json`의 `POST`, 헤더 `x-hopae-admin-request: 1`, 그리고 있을 때 콘솔 origin과 같은 `Origin`과 `same-origin` 또는 `none`인 `sec-fetch-site`. 교차 출처 브라우저는 아무도 답하지 않는 프리플라이트 없이는 이것들을 보낼 수 없습니다.
- 모든 변경은 저장소 트랜잭션의 첫 문장으로 verify 엔진 자신의 수명 의미론에 따라 행위자를 다시 평가합니다: 세션이 살아 있고 실효 절대(`min(저장값, created_at + session.absolute)`)·유휴 마감 안에 있는지, 콘솔 호스트의 핸들이 취소되지 않고 실효 마감 안에 있으며 요구 수준인지, 둘 다 60초를 넘어 미래에 만들어지지 않았는지, 사용자가 `active`이고 인가 기준이 바뀌지 않았는지, 신선도 술어를 만족하는지, 부여가 살아 있는 `admin`인지. 먼저 커밋된 변화는 쓰기를 거부하고(`403 actor_revoked`) 아무것도 바꾸지 않습니다.
- 변경도 `admin.query_budget_ms` 아래에서 실행됩니다. 자기 작업 때문이든 다른 연결이 쓰기 잠금을 쥐고 있기 때문이든 마감까지 끝나지 못하는 비활성화나 전체 종료는 중단되고 롤백되며 `503`으로 답합니다. 부분적으로 커밋되는 것은 없고 마감 뒤에 커밋되는 것도 없습니다.
- 아무것도 바꾸지 않는 변경(비활성화된 사용자 비활성화, 끝난 세션 종료)은 `changed: false`와 함께 `200`으로 답하고 이벤트를 쓰지 않습니다.

### 감사 이벤트

모든 상태 변경은 변경과 같은 트랜잭션에서 `admin.*` 이벤트를
씁니다([ADR-0009](../adr/0009-event-model.md)). 1급 열은 대상을 가리키고
`attrs.actor`는 행위 사용자(또는 `cli`, `file`)를, `attrs.actor_session`은 그
세션을 가리킵니다.

| 종류 | 열 | `attrs` | 함께 기록되는 것 |
| --- | --- | --- | --- |
| `admin.user_disable` | `user_id` = 대상 | `actor`, `actor_session`, `count`(종료된 세션 수) | `users.status`, `authz_version`, 세션마다 `session.terminated`(`reason=user_disabled`) 하나 |
| `admin.user_enable` | `user_id` = 대상 | `actor`, `actor_session` | `users.status`, `authz_version` |
| `admin.session_terminate` | `session_id`, `user_id` = 대상 | `actor`, `actor_session` | `session.terminated`(`reason=admin`) |
| `admin.sessions_terminate` | `user_id` = 대상 | `actor`, `actor_session`, `count` | 세션마다 `session.terminated`(`reason=admin`) 하나 |
| `admin.grant`, `admin.revoke` | `user_id` = 부여된 사용자 | `actor`(`cli` 또는 `file`), `role`, `previous_role`, `managed_by` | `admin_grants` 행 |
| `admin.denied` | `user_id`, `session_id` = 요청자 | `endpoint`(라우트 패턴), `method`. `reason` ∈ `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`, `actor_revoked` | 없음(단독 필수 이벤트) |
| `csrf.rejected` | `user_id`, `session_id` = 요청자 | `purpose=admin`, `cause` | 없음 |
| `admin.read` | `user_id`, `session_id` = 설명한 사용자와 세션(설명 API만) | `actor`, `actor_session`, `purpose`, `endpoint`, `query_sha256`, `requested`, `count`, `status`, `host`, `port`, `app`, `navigation` | 없음(응답 전에 쓰는 단독 필수 이벤트) |

읽기는 감사하지 않습니다. 다만 [주체 디렉터리](SUBJECT_DIRECTORY.md)와
[인증 설명](AUTHENTICATION_EXPLAIN.md) 읽기는 `admin.read`를 쓰며, 이를 쓸 수 없으면
거부합니다. 콘솔 로그인은 `app_id = admin`인 일반
`session.handoff` 이벤트로, 재인증은 `attrs.reauth = true`와
`attrs.auth_time_source`가 있는 `login.succeeded`로 보입니다.

### 상태

`GET /v1/status`와 첫 페이지는 읽기 전용으로 다음을 보여 줍니다.

| 구역 | 필드 |
| --- | --- |
| `apps` | `app_id`, `display_name`, `hosts`, `ports`, `enabled`, `session`, `binding`, `on_authz_change`, `verify_cache_seconds`, `logout_confirm`, `max_auth_age`, `step_up` 개수. 암묵적 `admin` 애플리케이션 포함 |
| `providers` | `provider_id`, `kind`, `display_name`, `enabled`, `managed_by`, `health`(`ok`, 사유 코드가 있는 `degraded`, `disabled`), `reauth`(`max_age` 또는 `unsupported`), `client_secret_env`(변수 **이름**)와 `secret_present`. 값은 절대 없음 |
| `store` | `kind`, `schema_version`, `users`, `live_sessions`, `events`, 싱크별 `deliveries`(`pending`, `failed`), `last_prune_at` |
| `build` | `version`, `contract`(`1.1`), `started_at` |
| `config` | `generation`, `digest`, `insecure_mode`, `unauthenticated_caller`, `listeners` |

제공자와 애플리케이션의 실행 중 변경은 M4-min에 포함되지 않습니다. 추가될 때
API로 바뀐 제공자는 `managed_by = api`가
되며([ADR-0010](../adr/0010-provider-abstraction.md)), 운영자는 이 페이지에서
설정 파일이 더 이상 그 행을 소유하지 않음을 봅니다.

### 카운터

| 카운터 | 레이블 | 세는 것 |
| --- | --- | --- |
| `hopae_admin_requests_total` | `role`(`admin`, `viewer`, 인증 전에는 `none`), `outcome`(`ok`, `denied`, `client_error`, `server_error`, 또는 인증 전에 거부된 요청의 거부 코드). `cookie.secure`가 `false`이면 `insecure_mode="true"`가 더해짐 | 관리 리스너가 답한 요청 |
| `hopae_admin_denied_total` | `reason` | 리스너와 핸들러의 거부를 사유별로(`untrusted_peer`, `login_required`, `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`, `actor_revoked`, `overloaded`) |
| `hopae_admin_mutations_total` | `kind`(`user_disable`, `user_enable`, `sessions_terminate`, `session_terminate`) | 무언가를 바꾼 변경 |
| `hopae_admin_rows_examined_total` | `list`(`users`, `sessions`, `events`) | 목록이 살펴본 후보 행 |
| `hopae_admin_grants_imported_total` | `outcome`(`inserted`, `updated`, `revoked`, `unchanged`, `skipped`) | 시작할 때의 가져오기가 적용한 부여 |
| `hopae_store_interrupts_total` | 없음 | 마감에서 SQLite 안에서 중단된 저장소 작업 |

노출은 M7이며 그동안은 `test-hooks` 빌드가 보여 줍니다([운영](OPERATIONS.md#카운터)).

## 제한과 호환성

- 콘솔은 자기 호스트의 게이트웨이 보호 라우트가 필요합니다. `auth`가 없거나 `strip_request_cookies`가 있는 라우트는 모든 요청을 `403 login_required`로 만듭니다.
- 관리자 세션은 Hopae에 자체 2차 인증 요소(관리자용 TOTP는 다음 마일스톤으로 제안)가 생기기 전까지 단일 요소입니다. Google 같은 `unsupported` 제공자에서는 `admin.max_auth_age`가 Hopae 로그인 경과 시간이며 조용한 제공자 로그인이 그것을 만족시킵니다. 완화책은 제공자 측 2차 인증, 암묵적 애플리케이션의 짧은 수명과 strict 바인딩입니다.
- 제공자가 검증한 재인증에는 `max_age`를 존중하고 `auth_time`을 돌려주는 제공자(`reauth = max_age`)가 필요합니다. 그런 제공자에서는 모든 이전 세션과 클레임 없이 인증된 모든 세션이 첫 콘솔 진입에서 도전을 받습니다.
- 브라우저가 아닌 API 클라이언트는 브라우저로 얻은 쿠키가 필요합니다. API 토큰은 나중 작업입니다.
- M4-min에서는 제공자, 애플리케이션, 블랙리스트를 콘솔에서 관리하지 않습니다. 부여는 명령줄과 설정 파일에서만 옵니다.
- 읽기는 감사하지 않고 내보내기는 없습니다. 세션의 user-agent 접두사는 마이그레이션 `0003` 이후 만들어진 세션에만 있습니다.
- 목록은 요청당 최대 1만 행을 살펴봅니다. 큰 디렉터리의 희소한 검색은 짧은 페이지를 돌려주며 여러 요청이 필요합니다. 각 페이지는 자기 창을 구체화합니다.
- 읽기 전용 관리자는 관리자와 같은 개인 정보를 봅니다.

## 예제, 검증, 관련 페이지

관리자 한 명을 심어 콘솔을 켜는 설정 조각:

```json
{
  "listen": {"portal": "127.0.0.1:8700", "gateway": "127.0.0.1:8701", "admin": "127.0.0.1:8702"},
  "admin": {
    "public_url": "https://hopae-admin.example.test",
    "session": {"idle": "30m", "absolute": "12h"},
    "max_auth_age": "12h",
    "untrusted_peers": "refuse",
    "users": [{"user_id": "u_01hzexampleexampleexample0", "role": "admin", "note": "on-call"}]
  }
}
```

브라우저로 얻은 쿠키로 스크립트에서 세션을 종료하기:

```sh
curl -sS -X POST https://hopae-admin.example.test/v1/sessions/s_<redacted>/terminate \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -H 'cookie: __Host-hopae=<redacted>' -d '{}'
```

검증: 시나리오 [300](../../scenarios/300-administrator-access-to-the-console.md)
(접근, 역할, 두 제공자 능력에서의 신선도, CSRF, 피어와 직접 연결),
[301](../../scenarios/301-console-users-list-search-disable-enable.md)
(사용자), [302](../../scenarios/302-console-sessions-list-and-terminate.md)
(세션), [303](../../scenarios/303-console-login-history-and-audit-browsing.md)
(기록과 감사), [304](../../scenarios/304-console-status-is-read-only.md)
(상태), [305](../../scenarios/305-administrator-grants-cli.md)(부여, 파일 심기,
부트스트랩, 마이그레이션 보호).

관련 페이지: [설정 참조](CONFIG.md), [아키텍처](ARCHITECTURE.md),
[위협 모델](THREAT_MODEL.md#위협-목록)(TM-15, TM-42부터 TM-46),
[게이트웨이 계약](GATEWAY_CONTRACT.md), [운영](OPERATIONS.md),
[ADR-0016](../adr/0016-management-console-minimum.md).
