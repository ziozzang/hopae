# 설정 참조

<!-- translation-status: source=../CONFIG.md source-rev=15 status=current -->

[문서 목차](README.md) · [English](../CONFIG.md)

이 페이지는 Hopae가 읽는 모든 설정 키를 타입, 기본값, 제약, 도입된 마일스톤과
함께 나열합니다. 아래 표들은 마일스톤 M1과 M4-min이 구현한 내용을 설명하고, 마지막 표는
ADR에서 결정되었지만 지금은 알 수 없는 키로 거부되는 키를 나열합니다. 그런 키는
구현하는 변경에서 본문 표로 옮깁니다.

## 전제 조건과 설정

- JSON 파일 하나를 `hopae run`과 `hopae --check`에 `--config <path>`(또는 `HOPAE_CONFIG` 환경 변수)로 전달합니다. YAML은 M1에서 지원하지 않습니다(나중 작업이며, 하지 않을 수도 있습니다).
- 파일 크기는 최대 1 MiB입니다. 알 수 없는 키는 모든 수준에서 거부됩니다(`deny_unknown_fields`). 메시지에는 키 경로가 들어가며, 가까운 키가 있으면 가장 비슷한 알려진 키도 알려 줍니다. 이름이 평문 비밀 값처럼 보이는 키(`_env` 접미사 없이 `secret`, `password`, `token`, `api_key`, `private_key`를 포함)는 값을 되풀이하지 않고 거부합니다.
- 비밀 값은 파일에 절대 적지 않습니다. `_env`로 끝나는 키는 값을 담은 환경 변수의 이름을 지정합니다. `hopae --check`는 빠진 변수를 이름으로만 보고하고 값은 절대 출력하지 않습니다.
- 설정은 시작할 때 한 번만 읽습니다. M6 이전에는 다시 로드를 지원하지 않으므로 파일을 바꾼 뒤 재시작합니다. `SIGHUP`은 기록만 하고 무시합니다.
- 기간(`session.idle`, `apps[].session.idle` 등)은 양의 정수와 단위 하나로 씁니다. `30s`, `10m`, `12h`, `7d`.

### 명령줄

| 호출 | 의미 |
| --- | --- |
| `hopae run --config <path>` | 두 리스너를 시작하고 서비스합니다. `run`이 기본 명령이므로(`hopae --config <path>`도 같습니다) `serve`는 별칭입니다. |
| `hopae --check --config <path>` | 파일과 참조된 환경을 검증하고, 운영자가 다른 곳에 등록해야 하는 파생 사실(리스너, 반환 origin, 제공자 redirect URI, 게이트웨이 라우트 `auth` 조각)을 `config ok`로 끝나도록 출력한 뒤 `0`으로 종료합니다. 경고는 stderr로 나갑니다. 아래의 선택적 읽기 전용 drift 조회 외에는 아무것도 바인딩, 기록, 접속하지 않습니다. |
| `hopae --check --strict --config <path>` | `--check`와 같지만 경고가 하나라도 있으면 오류입니다(종료 코드 `2`). `--strict`는 `--check`와 함께만 쓸 수 있습니다. |
| `hopae providers import --config <path>` | 파일의 `providers[]`를 ADR-0010 규칙으로 저장소에 가져오고(파일 항목은 `managed_by = file` 행을 삽입하거나 갱신하며, 데이터베이스가 관리하거나 제거된 제공자는 건드리지 않습니다) 삽입, 갱신, 건너뛴 항목을 출력합니다. 인스턴스가 실행 중이어도 안전합니다. 변경을 반영하려면 그 인스턴스를 재시작합니다. |
| `hopae providers import --force <provider_id> --config <path>` | 위와 같고, 지정한 파일 항목을 데이터베이스 위에 다시 덮어씁니다(비활성화, API 관리 또는 제거된 제공자). id는 파일에 있어야 합니다. `admin.providers_import` 이벤트를 기록합니다. |
| `hopae admin grant <user_id 또는 email> [--role admin\|viewer] [--note <text>] [--confirm <user_id>] --config <path>` | 기존 사용자에게 콘솔 역할(기본 `admin`)을 부여하고 해결된 사용자를 출력합니다. 이메일은 사용자의 검증된 기본 이메일이어야 하며, 권위적이지 않은 이메일은 해결된 사용자 id를 가리키는 `--confirm`이 필요합니다. `--note`는 최대 256자입니다. 부여는 그 사용자 id에 묶이며 다시 해결되지 않습니다. `admin.grant`를 기록합니다([관리](ADMIN.md#명령줄-참조)). |
| `hopae admin revoke <user_id 또는 email> --config <path>` | 부여를 철회합니다. 행은 묘비로 남습니다. `admin.revoke`를 기록합니다. |
| `hopae admin list [--all] --config <path>` | 유효한 부여를 출력합니다. `--all`은 철회된 행도 더합니다. |
| `hopae admin import [--force <user_id 또는 email>] --config <path>` | 파일의 `admin.users[]`를 저장소에 적용하고(시작할 때도 같은 가져오기가 실행됩니다) 삽입, 갱신, 철회, 변경 없음, 강제, 건너뛴 항목을 출력합니다. |
| `hopae --version` | 버전을 출력하고 `0`으로 종료합니다. 설정이 필요 없습니다. |

종료 상태: `0` 성공. `2` 유효하지 않거나 안전하지 않은 설정(호출자 키 변수가 없거나
빈 경우 포함), `--config` 누락, 다른 인스턴스가 상태 디렉터리 잠금을 쥐고 있어
시작이 거부됨, `--strict` 실패, 실패한 `providers import`, 거부된 `hopae admin`
명령(없거나 부적합한 사용자, 잘못된 인자, 사전 점검이 거부하는 데이터베이스:
바이너리보다 새롭거나 출시 전 스키마이거나 손상되었거나 바이너리보다 오래된
경우이며, 마지막 경우 메시지가 인스턴스를 한 번 시작해 마이그레이션하라고 안내함).
`1` 그 밖의 모든 런타임 실패(예: 열 수 없는 저장소, 바인딩할 수 없는 리스너).
`hopae admin` 명령은 데이터베이스를 만들거나 마이그레이션하거나 백업하지 않고
인스턴스 잠금도 잡지 않으며, 바쁜 데이터베이스를 최대 5초까지 기다립니다.

`gateway.admin_url`과 `gateway.readonly_token_env`가 모두 설정되고 변수가 비어 있지
않으면 `hopae --check`가 게이트웨이의 관리 API에 어떤 호스트에 라우트가 있는지
묻고, 라우트가 없는 애플리케이션 호스트를 경고합니다
([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md)의
0단계). 조회에 실패하면 경고일 뿐 오류가 아닙니다. `hopae run`은 두 키를 쓰지
않습니다.

### 키(M0, M1, M4-min)

아래 키는 모두 구현되어 있습니다. "선택"은 키를 생략할 수 있고 기본값이 적용된다는
뜻입니다. 관리 콘솔 키(마일스톤 M4-min)는 별도 표 [관리 콘솔](#관리-콘솔)에 있습니다.

#### 프로세스와 저장소

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `listen.portal` | 문자열, 소켓 주소 | `127.0.0.1:8700` | 포털 리스너(로그인, 콜백, 로그아웃, `/healthz`). 게이트웨이의 포털 라우트가 프록시합니다. |
| `listen.gateway` | 문자열, 소켓 주소 | `127.0.0.1:8701` | 게이트웨이 리스너(`/_hopae/verify`). `listen.portal`과 달라야 합니다. 루프백이 아닌 주소는 경고를 냅니다. 이 리스너는 공개적으로 접근할 수 있어서는 안 됩니다([게이트웨이 계약](GATEWAY_CONTRACT.md#전제-조건과-설정)). |
| `state_dir` | 문자열, 경로 | 필수 | 런타임 상태(데이터베이스, 인스턴스 잠금, 백업)를 위한 쓰기 가능한 디렉터리이며 모드 `0700`으로 생성됩니다. 비어 있으면 안 됩니다. |
| `store.kind` | `sqlite` | `sqlite` | 기본 저장소 백엔드([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)). `postgres`는 M2에서 제공합니다. |
| `store.path` | 문자열, 경로 | `<state_dir>/hopae.db` | SQLite 데이터베이스 파일. 지정했다면 비어 있으면 안 됩니다. |
| `log.level` | `error`, `warn`, `info`, `debug`, `trace` | `info` | stderr 프로세스 로그의 상세도. |
| `log.verify_allow` | 불리언 | `false` | 허용된 verify를 하나하나 기록합니다(거부는 항상 집계되고 샘플링됩니다). |
| `log.accept_client_request_id` | 불리언 | `false` | 클라이언트가 보낸 `x-request-id`를 잘라서 verify와 포털 요청 이벤트의 `attrs.client_request_id`에 기록합니다([ADR-0009](../adr/0009-event-model.md)). |
| `trusted_proxies` | IP 주소 또는 CIDR 문자열 배열 | `["127.0.0.1/32"]` | 포털 리스너가 `x-forwarded-for`와 `x-forwarded-proto`를 신뢰하는 피어. 각 항목은 주소 또는 CIDR이어야 합니다. 전달된 체인이 (모든 헤더 줄을 합쳐) 64홉을 넘으면 신뢰하지 않으며, 이때 피어 자신이 클라이언트 주소가 됩니다. |
| `listen.admin` | 문자열, 소켓 주소 | `127.0.0.1:8702` | 관리 콘솔의 관리 리스너. `admin.public_url`이 설정된 때만 바인딩합니다(`listen.admin`만 설정하고 `admin.public_url`이 없으면 리스너가 바인딩되지 않는다는 경고를 냅니다). `listen.portal`, `listen.gateway`와 달라야 합니다(키가 설정되면 항상 검사). 루프백이 아닌 주소는 경고를 냅니다. 이 리스너는 공개적으로 접근할 수 있어서는 안 됩니다. |
| `limits.gateway_max_concurrent` | 정수, 1 이상 | `64` | 게이트웨이 리스너의 동시 처리 요청 상한. 초과 요청은 즉시 `reason=overloaded`와 함께 `503`으로 답합니다([ADR-0003](../adr/0003-http-stack-axum-on-hyper.md)). 호출자 키는 허가를 얻기 전에 검사합니다. |
| `limits.portal_max_concurrent` | 정수, 1 이상 | `256` | 포털 리스너의 동시 처리 요청 상한. 초과 요청은 즉시 `503`으로 답합니다. |
| `limits.admin_max_concurrent` | 정수, 1 이상 | `16` | 관리 리스너의 동시 처리 요청 상한. 초과 요청은 피어 검사와 인증보다 먼저 즉시 `503`(`overloaded`)으로 답합니다. |
| `sessions.retention_days` | 정수, 1 이상 | `30` | 종료된 세션과 그 핸들을 세션 보존 정리 작업이 삭제하는 기간([ADR-0007](../adr/0007-context-binding-policy.md)). |

#### 포털, 쿠키, 세션

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `portal.public_url` | 문자열, origin | 필수 | 외부에서 보이는 포털 origin(`https://auth.example.test`). Hopae가 내보내는 모든 `Location`과 제공자 redirect URI(`<public_url>/callback/<provider_id>`)에 쓰입니다. 경로, 쿼리, 프래그먼트 없이 `https://` 또는 `http://`와 호스트여야 합니다. |
| `portal.sso_confirm_new_host` | 불리언 | `false` | 세션이 어떤 호스트로 처음 핸드오프되기 전에 한 번 클릭해 확인하게 합니다([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)). |
| `cookie.name` | 문자열 | `__Host-hopae`(`cookie.secure`가 `false`면 `hopae`) | 영문자, 숫자, `_`, `-` 1~64자. 바인딩 쿠키와 포털 쿠키는 `_bind`, `_portal`을 덧붙입니다. `cookie.secure`가 `true`이면 `__Host-`로 시작해야 하고 `false`이면 시작하면 안 됩니다. |
| `cookie.secure` | 불리언 | `true` | `false`는 개발 전용입니다. `--check`와 시작 시 큰 경고를 내고, 상태 확인 본문에 `insecure_mode`가 나타나며, 기본 애플리케이션 포트가 `80`이 됩니다. |
| `session.idle` | 기간 | `24h` | 세션 전체의 유휴 타임아웃. 핸들 중 어느 것으로도 이 기간 동안 쓰이지 않은 세션은 종료됩니다. 최소 `60s`입니다(활동은 초 단위로 기록됩니다). |
| `session.absolute` | 기간 | `30d` | 세션 전체의 절대 수명. 이 나이에 세션이 종료됩니다. |
| `linking.on_conflict` | `link_required`, `separate`, `deny` | `link_required` | 로그인의 검증된 이메일이 다른 제공자를 통한 기존 사용자와 일치할 때의 동작([ADR-0011](../adr/0011-account-linking-policy.md)). |
| `linking.mode` | `verified_email`, `off` | `verified_email` | 계정 연결 정책. |
| `txn.max_rows` | 정수, 1 이상 | `1000` | 살아 있는 로그인 트랜잭션 수 상한([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)). 트랜잭션 수명은 상수 600초이며 키가 없습니다. |
| `txn.per_ip_per_minute` | 정수, 1 이상 | `30` | 클라이언트 IP 하나가 분당 시작할 수 있는 로그인 트랜잭션 수. |
| `handoff.per_ip_failures_per_minute` | 정수, 1 이상 | `10` | 클라이언트 IP 하나가 분당 일으킬 수 있는 핸드오프 코드 실패 수. 넘으면 속도 제한됩니다. |
| `handoff.max_recoveries` | 정수 | `3` | 알려진 핸드오프 코드가 거부되었을 때(첫 사용 바인딩 쿠키 경쟁 등) 브라우저를 포털로 되돌려 보내 복구하는 횟수. 넘으면 중계된 `403` 페이지로 루프가 끝납니다([ADR-0014](../adr/0014-handoff-recovery-on-any-rejected-code.md)). 범위 검사는 하지 않습니다. |

#### 게이트웨이

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `gateway.kind` | `hangang` | 필수 | 게이트웨이 어댑터([ADR-0013](../adr/0013-gateway-adapter-boundary.md)). 다른 종류는 나중 작업입니다. |
| `gateway.caller_key_env` | 문자열, 환경 변수 이름 | 없음 | 게이트웨이가 `x-hopae-gateway-key`로 보내는 호출자 키를 담은 변수(게이트웨이 변경 HC-3). `gateway.allow_unauthenticated_caller`가 `true`가 아니면 필수이며, 변수는 시작 시 설정되어 있고 비어 있지 않아야 합니다(아니면 종료 코드 `2`). 이름 패턴 `[A-Za-z_][A-Za-z0-9_]*`. |
| `gateway.caller_key_next_env` | 문자열, 환경 변수 이름 | 없음 | 교체 중 두 번째로 허용하는 호출자 키([ADR-0005](../adr/0005-gateway-contract-and-versioning.md)). `caller_key_env`가 있어야 하고 그것과 달라야 하며, 변수는 시작 시 비어 있지 않아야 합니다. 7일 넘게 설정되어 있으면 `--check`가 경고합니다. |
| `gateway.allow_unauthenticated_caller` | 불리언 | `false` | 개발 전용: 호출자 키 인증을 건너뜁니다. `--check`와 시작 시 경고를 내며(상태 확인 본문에는 `unauthenticated_caller`), `--strict`는 이를 거부합니다. |
| `gateway.verify_budget_ms` | 정수 | `400` | verify 호출 하나가 쓸 수 있는 총 시간, 1~10000. 게이트웨이 라우트의 `auth.timeout_ms`보다 작게 유지하세요. `--check`는 `auth.timeout_ms`를 예산에 100을 더하고 5000으로 제한한 값으로 출력합니다. |
| `gateway.admin_url` | 문자열, URL | 없음 | 게이트웨이 관리 API의 기본 URL(`http` 또는 `https`, 호스트 필요, 자격 증명 없음). `gateway.readonly_token_env`와 함께 `hopae --check`만 사용합니다. |
| `gateway.readonly_token_env` | 문자열, 환경 변수 이름 | 없음 | 읽기 전용 게이트웨이 자격 증명을 담은 변수. 라우트가 없는 애플리케이션 호스트를 경고하기 위해 `hopae --check`만 사용합니다. 전체 drift 보고서는 M2입니다. |

#### 애플리케이션

`apps[]`는 애플리케이션 레지스트리입니다. 로그인 후 Hopae가 브라우저를 보낼 수
있는 정확한 호스트들입니다. 활성화된 모든 호스트와 포트의 합집합이 반환 origin
허용 목록이며, 각 항목은 운영자가 보증하는 자격 증명 목적지입니다. 목록에 없는
호스트는 거부됩니다(`unknown_app`).

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `apps[].app_id` | 문자열 | 필수 | `[a-z0-9][a-z0-9_-]{0,31}`, 유일. id `default`는 예약되어 있으며, 그 항목은 다른 모든 애플리케이션의 정책 기본값을 담고 호스트를 나열하면 안 됩니다. |
| `apps[].display_name` | 문자열 | `app_id` | 포털에 표시됩니다. |
| `apps[].hosts` | 문자열 배열 | 필수(`default` 제외) | 정확한 소문자 호스트 이름. 스킴, 와일드카드, 포트, 경로, 끝의 점은 안 됩니다. 호스트는 애플리케이션 하나에만 속할 수 있습니다. 대문자 입력은 경고와 함께 정규화됩니다. |
| `apps[].ports` | 정수 배열 | `[443]`(`cookie.secure`가 `false`면 `[80]`) | 지정했다면 비어 있으면 안 되며 `0`은 안 됩니다. |
| `apps[].enabled` | 불리언 | `true` | 비활성 애플리케이션은 거부됩니다(`app_disabled`). |
| `apps[].session.idle`, `apps[].session.absolute` | 기간 | `12h`, `7d`(`default` 애플리케이션이 설정했다면 그 값을 상속) | 핸들별 타이머. `idle` 동안 쓰이지 않았거나 `absolute`보다 오래된 핸들은 취소되며, 세션과 다른 핸들은 계속됩니다. `idle`은 최소 `60s`여야 합니다([ADR-0007](../adr/0007-context-binding-policy.md)). |
| `apps[].binding.ip` | `strict`, `prefix`, `off` | `strict` | 핸들의 클라이언트 IP 바인딩([ADR-0007](../adr/0007-context-binding-policy.md)). |
| `apps[].binding.ip_prefix_v4`, `apps[].binding.ip_prefix_v6` | 정수 | `24`, `64` | `prefix` 모드의 접두사 길이. 각각 1~32, 1~128. |
| `apps[].binding.ua` | `strict`, `off` | `off` | User-Agent 바인딩. |
| `apps[].binding.on_mismatch` | `terminate_session`, `drop_handle` | `terminate_session` | 바인딩 불일치 시 동작. |
| `apps[].on_authz_change` | `refresh`, `terminate` | `refresh` | 인가 데이터가 바뀔 때 살아 있는 세션에 일어나는 일. |
| `apps[].verify_cache_seconds` | 정수 | `0` | 게이트웨이가 허용을 캐시할 수 있는 최대 시간. 최대 `30`. `hopae --check`는 애플리케이션마다 값을 출력하고 **`false`이면 경고합니다**: `sec-fetch-site: same-origin`은 애플리케이션 자신의 출처 문서가 탐색을 시작했음을 증명할 뿐이므로, 애플리케이션 안의 탐색 가젯(자신의 쿼리에서 가져온 URL을 `location`에 대입하는 페이지, 예: `/continue?next=/_hopae/logout`)이 클릭 없이 사용자의 세션을 끝낼 수 있습니다. 이를 받아들이는 경우가 아니면 `true`를 유지하십시오. |
| `apps[].logout_confirm` | 불리언 | `true`(`default` 애플리케이션이 설정했다면 그 값을 상속) | `true`: 애플리케이션 호스트의 `/_hopae/logout`은 포털의 확인 페이지로 리디렉션합니다. `false`: 유효한 핸들을 제시한 `sec-fetch-site: same-origin` 문서 탐색은 즉시 세션을 끝내고 포털의 로그아웃 완료 페이지로 리디렉션되며, 그 밖의 모든 요청은 여전히 확인을 거칩니다. 어느 쪽이든 포털은 보호된 대상으로 리디렉션하는 대신 "다시 로그인" 링크를 표시합니다([ADR-0015](../adr/0015-app-host-entry-points-and-upstream-cookie-stripping.md), [게이트웨이 계약](GATEWAY_CONTRACT.md#애플리케이션-호스트-진입점)). `--check`가 보고합니다. |
| `apps[].step_up[]` | `{path_prefix, require: {aal, max_age}}` 배열 | 없음 | 스텝업 규칙. M1에서는 파싱과 검증만 하고(`aal`은 1 또는 2, `path_prefix`는 `/`로 시작, `max_age`는 양의 초) `no-store`를 강제합니다. 강제 적용은 M5에서 도착합니다. |

#### 제공자

`providers[]`는 로그인 제공자를 정의합니다. 항목은 시작할 때 ADR-0010 가져오기
규칙으로 저장소에 반영됩니다. 그 뒤에는 실행 중에 바뀐 제공자에 대해 데이터베이스가
권위를 가집니다. M1은 `kind = oidc`만 지원합니다(검증된 제공자는 Google).

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `providers[].provider_id` | 문자열 | 필수 | `[a-z0-9][a-z0-9_-]{0,31}`, 유일. redirect URI `<portal.public_url>/callback/<provider_id>`에 나타납니다. 프리셋 이름(`google`)과 같은 id는 `issuer`가 없을 때 그 프리셋을 선택합니다. |
| `providers[].kind` | `oidc` | 필수 | `oauth2`, `email_link`, `password`는 파싱되지만 M3 이전에는 거부됩니다. |
| `providers[].display_name` | 문자열 | `provider_id` | 선택 화면의 라벨. |
| `providers[].enabled` | 불리언 | `true` | 비활성 제공자는 제시되지 않습니다. |
| `providers[].client_id` | 문자열 | 필수 | 비어 있으면 안 됩니다. 비밀 값이 아닙니다. |
| `providers[].client_secret_env` | 문자열, 환경 변수 이름 | 없음 | 클라이언트 비밀 값을 담은 변수. 설정했는데 시작 시 변수가 없거나 비어 있으면 제공자가 비활성화됩니다(`--check`에는 경고로, `/healthz`에는 `disabled`로 나타남). Hopae는 그대로 시작합니다. |
| `providers[].issuer` | 문자열, URL | 프리셋의 issuer | `https://`(`http://`는 루프백 호스트이면서 `allow_private_endpoints: true`일 때만), 쿼리·프래그먼트·자격 증명 없음. 프리셋이 적용되지 않으면 필수입니다. |
| `providers[].scope` | 문자열 | `openid email profile` | 비어 있으면 안 됩니다. |
| `providers[].endpoint_hosts` | 호스트 배열 | `[]` | 발급자 자신의 호스트 외에 제공자의 디스커버리 문서가 가리킬 수 있는 호스트(인가, 토큰, 사용자 정보, 키 엔드포인트는 `https`여야 하고 발급자의 호스트이거나 여기 나열된 호스트여야 하며, 스킴과 포트 없는 호스트 이름 또는 IP 주소). `google` 프리셋은 자신의 목록을 가집니다. |
| `providers[].allow_private_endpoints` | 불리언 | 미설정(`false`) | 개발용 및 사설 인증 제공자 전용: 루프백, 사설, 링크 로컬, CGNAT, 멀티캐스트 주소에 대한 연결 시점 거부를 해제하고 루프백 발급자에 대한 `http://`를 허용합니다. 설정하지 않으면 그런 주소는 거부되며 연결은 검증된 주소로만 갑니다. 명시적 `false`는 `test-hooks` 빌드에서도 항상 우선합니다. 제공자 요청은 `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`를 사용하지 않습니다. |
| `providers[].allowed_email_domains` | 도메인 배열 | `[]` | 평범한 도메인 이름. 비어 있지 않으면 그 이메일 도메인으로만 로그인을 제한합니다. 신원 계층이 강제하며 검증된 이메일 주소만 고려합니다. |
| `providers[].authoritative_domains` | 도메인 배열 | `[]` | 이 제공자가 이메일에 대해 권위를 갖는 도메인([ADR-0011](../adr/0011-account-linking-policy.md)). |
| `providers[].auto_link` | 불리언 | `false` | 정책이 허용하면 확인 없이 로그인을 기존 사용자에 연결합니다. |
| `providers[].trust_email` | 불리언 | `false` | 제공자의 이메일 클레임을 검증된 것으로 취급합니다. |

제공자 설정 `preset`, `userinfo`, `id_token_typ`, `reauth`, `reauth_prompt`는 OIDC
제공자가 설정 파일이 아니라 제공자 행에 저장된 `config`에서 읽습니다. 파일 가져오기는
`client_id`, `issuer`, `scope`만 그 행에 쓰며, `hopae --check`는 이 다섯 이름을 알 수
없는 키로 거부합니다. 이를 가진 행이 데이터베이스에 있을 때만 효과가 있습니다.
`reauth`와 `reauth_prompt`는 저장된 값이 파일이 해석한 기본값보다 우선하며(시작할 때와
`hopae --check` 보고서 모두), 나열된 값이 아닌 저장 값은 무시합니다.

| 저장된 설정 | 타입 | 기본값 | 의미 |
| --- | --- | --- | --- |
| `preset` | 문자열 | `provider_id`와 같은 이름의 프리셋, 없으면 issuer가 일치하는 프리셋 | 잘 알려진 제공자의 내장 기본값. M1에는 `google`만 있습니다(issuer `https://accounts.google.com`, scope `openid email profile`, user-info 호출 없음). |
| `userinfo` | 불리언 | 프리셋의 값, 프리셋이 없으면 `true` | ID 토큰 검증 뒤 user-info 엔드포인트를 호출합니다. 주체(subject)는 ID 토큰과 일치해야 합니다. |
| `id_token_typ` | 문자열 | 없음 | 제공자가 설정하는 경우 ID 토큰의 필수 `typ` 헤더. |
| `reauth` | `max_age`, `unsupported` | 프리셋의 값. 프리셋이 없으면 `max_age` | 제공자가 OpenID Connect `max_age` 매개변수를 존중하고 `auth_time`을 돌려주어 콘솔 재인증이 제공자가 검증한 도전이 되는지 여부. `google` 프리셋은 `unsupported`이며(Google은 재인증 요청을 지원하지 않는다고 문서화함) 그런 제공자에서의 콘솔 신선도는 Hopae 로그인 경과 시간입니다([ADR-0016](../adr/0016-management-console-minimum.md) 결정 15, [관리](ADMIN.md#신선도와-재인증)). |
| `reauth_prompt` | `login`, `none` | `login` | `max_age` 제공자에 대한 재인증 authorize 요청에 `prompt=login`도 실을지 여부. `reauth`가 `unsupported`인 제공자는 `max_age`도 `prompt`도 없는 일반 authorize 요청을 받습니다. |

#### 관리 콘솔

콘솔은 `admin.public_url`로 켭니다. 없으면 관리 리스너가 바인딩되지 않으며 다른
`admin.*` 키는 검증만 되고 효과가 없습니다. 배경은 [관리](ADMIN.md)에 있습니다.

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `admin.public_url` | 문자열, origin | 없음 | 콘솔의 외부 노출 origin, `https://hopae-admin.example.test`. `https://`이며, `http://`는 `cookie.secure`가 `false`일 때만. 소문자 호스트 **이름**(IP 주소 아님)과 선택적 포트이며 경로, 쿼리, 프래그먼트, 자격 증명은 없음. 설정하면 암묵적 애플리케이션 `admin`(호스트 `[host]`, 포트 `[그 포트, 없으면 443(http는 80)]`, `on_authz_change = terminate`, `verify_cache_seconds = 0`, `logout_confirm = true`)을 등록하고 `listen.admin`을 바인딩함. id `admin`은 예약됨. 그 id를 가진 `apps[]` 항목이나 콘솔 호스트를 나열한 항목은 오류. |
| `admin.session.idle` | 기간 | `30m` | 콘솔 호스트의 핸들별 유휴 타이머. `60s` 이상. |
| `admin.session.absolute` | 기간 | `12h` | 콘솔 호스트의 핸들별 절대 수명. |
| `admin.binding.ip` | `strict`, `prefix`, `off` | `strict` | 콘솔 핸들의 클라이언트 IP 바인딩. `apps[].binding.ip`와 같음. |
| `admin.binding.ip_prefix_v4`, `admin.binding.ip_prefix_v6` | 정수 | `24`, `64` | `prefix` 모드의 접두사 길이: 1부터 32, 1부터 128. |
| `admin.binding.ua` | `strict`, `off` | `off` | User-Agent 바인딩. |
| `admin.binding.on_mismatch` | `terminate_session`, `drop_handle` | `terminate_session` | 바인딩 불일치 시 동작. |
| `admin.max_auth_age` | 기간 | `12h` | 콘솔 세션의 신선도 한도. `30m` 이상: 더 작은 값은 설정 오류(`admin.max_auth_age must be at least 30m`)이며, 한도가 재인증 콜백과 뒤따르는 콘솔 verify 사이에 600초의 여유를 지키기 때문입니다. 콘솔의 모든 verify에서 하나의 술어로 평가: `auth_time ≤ now + 60초` 그리고 `now − auth_time < N`. `reauth` 능력이 `max_age`인 제공자에서는 세션이 제공자가 검증한 `auth_time`을 가져야 하고 오래되면 세션 자신의 제공자가 수행하는 재인증으로 보내며, `unsupported` 제공자(`google` 프리셋)에서는 한도가 Hopae 로그인 경과 시간뿐임([ADR-0016](../adr/0016-management-console-minimum.md) 결정 15, [관리](ADMIN.md#신선도와-재인증)). |
| `admin.require_aal` | `1`, `2` | `1` | 콘솔 핸들의 최소 보증 수준. `2`는 호스트 전체에 대한 암묵적 애플리케이션의 단계 상승 규칙도 설정하며, 아직 두 번째 인증 요소가 없으므로 모든 콘솔 요청이 거부된다고 `--check`가 경고함. |
| `admin.untrusted_peers` | `refuse`, `as_client` | `refuse` | `trusted_proxies` 밖의 TCP 피어를 관리 리스너가 어떻게 다루는지: `refuse`는 쿠키를 읽기 전에 `403 untrusted_peer`로 답함(집계, 속도 제한된 경고). `as_client`는 포털처럼 피어를 클라이언트로 취급. |
| `admin.query_budget_ms` | 정수, 100부터 30000 | `2000` | 콘솔 저장소 작업 하나(목록, 검색, 변경)의 마감. 마감은 저장소 작업에 전달되어 SQLite 안에서 문장을 중단하고 롤백한 뒤 `503`으로 답함. |
| `admin.users[]` | `{user_id?, email?, role?, note?}` 배열 | `[]` | 시작 시와 `hopae admin import`로 파일에서 심는 관리자 부여. 각 항목은 `user_id`(`u_` 다음에 문자, 숫자, `_`, `-`, 최대 64자)와 `email`(유효한 주소) 중 적어도 하나가 필요하고, `role`은 `admin`(기본) 또는 `viewer`, `note`는 최대 256자이며 알 수 없는 키는 거부됨. 이메일만 있는 항목은 검증된 주소를 정확히 한 사용자가 가지고 권위적일 때만 적용됨. 결함 있는 항목은 시작할 때 경고(건너뜀, 시작 실패 아님)이고 `--check --strict`에서는 오류. `managed_by`와 묘비를 가진 제공자 규칙으로 가져옴([관리](ADMIN.md#설정-파일의-부여)). |

#### 이벤트

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `events.retention_days` | 정수, 1 이상 | `90` | 이벤트를 정리하는 기간([ADR-0009](../adr/0009-event-model.md)). |
| `events.max_rows` | 정수, 1 이상 | `1000000` | 저장 이벤트 수의 하드 상한. 오래된 것부터 정리됩니다. |
| `events.prune_every` | 정수, 1 이상 | `1000` | 정리 패스 사이에 삽입되는 행 수(패스는 최소 60초마다도 실행됩니다). |
| `events.max_pending_per_sink` | 정수, 1 이상 | `10000` | 싱크마다 보관하는 미전달 행 수. 넘으면 가장 오래된 대기 행이 `backlog_overflow`로 `failed`가 됩니다. |
| `events.delivery_terminal_retention_days` | 정수, 1 이상 | `7` | 전달 완료 또는 실패한 전달 행을 보관하는 기간. |

### 결정되어 예정된 키

이 키들은 ADR과 게이트웨이 계약에 있으며 표시한 마일스톤에서 구현됩니다. 그때까지
`hopae --check`는 알 수 없는 키로 거부합니다.

| 키 | 마일스톤 | 기본값 | 결정된 곳 |
| --- | --- | --- | --- |
| `gateway.rate_limit_status` | HC-8 이후 | `403` | 게이트웨이가 중계하면 `429`([ADR-0005](../adr/0005-gateway-contract-and-versioning.md)) |
| `oidc`가 아닌 `providers[].kind` | M3 | — | 카카오, 네이버, 이메일 링크, 비밀번호([ADR-0010](../adr/0010-provider-abstraction.md)) |
| `cache.local_ttl_ms`, `cache.op_timeout_ms`, `cache.redis_url_env`, `cache.namespace` | M2 | `0`, `50`, 없음, 없음 | 로컬 캐시와 Redis 버스([ADR-0006](../adr/0006-verify-caching-and-invalidation.md)) |
| `store.kind = postgres`, `store.url_env` | M2 | — | 공유 기본 저장소([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |

## 동작

- 검증은 `hopae --check`와 `hopae run` 시작 시 같은 규칙으로 실행됩니다. 파일이 유효하지 않으면 `run`은 어떤 리스너도 바인딩하지 않고 종료 코드 `2`로 끝납니다.
- 오류는 모아서 한꺼번에 보고하며, 각각 키 경로를 명시합니다.
- 환경 변수 참조는 존재 여부만 검사합니다. 값은 절대 로그, 출력, 오류 메시지에 나타나지 않습니다.
- 참조된 환경 변수: 호출자 키 변수가 없거나 비어 있으면 오류이고, 제공자 비밀 값이 없으면 해당 제공자를 비활성화하는 경고입니다.
- 경고(치명적이지 않음): `gateway.allow_unauthenticated_caller`가 설정됨, `cookie.secure`가 false, `listen.gateway`가 루프백 주소가 아님, 비밀 값 변수가 없어 제공자가 비활성화됨, `gateway.caller_key_next_env`가 7일 넘게 설정됨, 게이트웨이 라우트가 없는 애플리케이션 호스트(`gateway.admin_url`을 설정한 경우만), 소문자로 정규화된 대문자 호스트 이름, 루프백 주소가 아닌 `listen.admin`, `admin.public_url` 없이 설정된 `listen.admin`, `2`로 설정된 `admin.require_aal`, 적용할 수 없는 `admin.users[]` 항목(저장소가 있으면 그것을 기준으로 보고), 없거나 쿠키를 제거하는 콘솔 라우트(`gateway.admin_url`을 설정한 경우만: `console_route_without_auth`, `console_route_strips_cookies`).
- 데이터베이스 경로를 지정하지 않으면 `<state_dir>/hopae.db`로 파생됩니다.

## 제한과 호환성

- JSON만 지원하며 주석은 허용하지 않습니다.
- 1.0 이전에는 마이너 릴리스에서 키의 이름이 바뀌거나 삭제될 수 있습니다. 그런 변경은 각각 CHANGELOG의 `Changed` 아래에 이전 안내와 함께 기록합니다.
- M6 이전에는 다시 로드가 없습니다.
- `apps[].step_up`은 파싱만 하며 M5 이전에는 강제하지 않습니다. 따라서 `admin.require_aal = 2`는 모든 콘솔 요청을 거부합니다.
- 제공자 설정 `preset`, `userinfo`, `id_token_typ`, `reauth`, `reauth_prompt`는 파일로 지정할 수 없습니다(제공자 절 참고).
- `apps[].max_auth_age`는 키가 아닙니다. 신선도 한도를 가진 것은 암묵적 콘솔 애플리케이션뿐이며 그 한도는 `admin.max_auth_age`입니다.

## 예제, 검증, 관련 페이지

저장소의 예제(`examples/hopae.example.json`):

```json
{
  "listen": {
    "portal": "127.0.0.1:8700",
    "gateway": "127.0.0.1:8701"
  },
  "state_dir": "/var/lib/hopae",
  "store": {
    "kind": "sqlite"
  },
  "portal": {
    "public_url": "https://auth.example.test"
  },
  "gateway": {
    "kind": "hangang",
    "caller_key_env": "HOPAE_GATEWAY_KEY",
    "allow_unauthenticated_caller": false
  },
  "log": {
    "level": "info"
  }
}
```

애플리케이션 하나와 Google 제공자를 포함한 더 완전한 템플릿은
`deploy/hopae.example.json`입니다. [운영](OPERATIONS.md)을 참고하세요.

다음 명령으로 검증합니다.

```sh
HOPAE_GATEWAY_KEY=<redacted> hopae --check --config examples/hopae.example.json
```

관련 페이지: [운영](OPERATIONS.md), [아키텍처](ARCHITECTURE.md), [게이트웨이 계약](GATEWAY_CONTRACT.md), 시나리오 013(사전 점검과 시작).
