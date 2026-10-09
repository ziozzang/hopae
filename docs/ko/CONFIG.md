# 설정 참조

<!-- translation-status: source=../CONFIG.md source-rev=3 status=current -->

[문서 목차](README.md) · [English](../CONFIG.md)

이 페이지는 Hopae가 읽는 모든 설정 키를 타입, 기본값, 제약, 도입된 마일스톤과
함께 나열합니다. *나중*으로 표시된 키는 ADR에서 결정되었지만 아직 구현되지 않은
키입니다. 운영자와 구현자가 같은 용어를 쓰도록 미리 나열하며, 각 키는 그것을
구현하는 변경에서 본문 표로 옮깁니다.

## 전제 조건과 설정

- JSON 파일 하나를 `hopae run`과 `hopae --check`에 `--config <path>`로 전달합니다. YAML은 M0/M1에서 지원하지 않습니다(나중 작업이며, 하지 않을 수도 있습니다).
- 파일 크기는 최대 1 MiB입니다. 알 수 없는 키는 모든 수준에서 거부됩니다(`deny_unknown_fields`).
- 비밀 값은 파일에 절대 적지 않습니다. `_env`로 끝나는 키는 값을 담은 환경 변수의 이름을 지정합니다. `hopae --check`는 빠진 변수를 이름으로만 보고하고 값은 절대 출력하지 않습니다.
- `hopae --check --config <path>`는 파일과 참조된 환경을 검증하고, 운영자가 다른 곳에 등록해야 하는 파생 사실(리스너, 게이트웨이 라우트 `auth` 조각, redirect URI)을 출력한 뒤 `0`으로 종료하거나, 오류마다 메시지 하나를 내고 `2`로 종료합니다. 경고는 stderr에 출력되며 `--strict`는 경고를 오류로 바꿉니다.
- 설정은 시작할 때 한 번만 읽습니다. M6 이전에는 다시 로드를 지원하지 않으므로 파일을 바꾼 뒤 재시작합니다.

### 키(M0)

| 키 | 타입 | 기본값 | 제약과 의미 |
| --- | --- | --- | --- |
| `listen.portal` | 문자열, 소켓 주소 | `127.0.0.1:8700` | 포털 리스너(로그인, 콜백, 로그아웃, 상태 확인). 게이트웨이의 포털 라우트가 프록시합니다. |
| `listen.gateway` | 문자열, 소켓 주소 | `127.0.0.1:8701` | 게이트웨이 리스너(`/_hopae/verify`). `listen.portal`과 달라야 합니다. 루프백이 아닌 주소는 경고를 냅니다. 이 리스너는 절대 공개적으로 접근할 수 없어야 합니다([게이트웨이 계약](GATEWAY_CONTRACT.md#전제-조건과-설정)). |
| `state_dir` | 문자열, 경로 | 필수 | 런타임 상태를 위한 쓰기 가능한 디렉터리이며 모드 `0700`으로 만듭니다. 비어 있으면 안 됩니다. |
| `store.kind` | `sqlite` | `sqlite` | 기본 저장소 백엔드([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)). `postgres`는 M2에서 추가됩니다. |
| `store.path` | 문자열, 경로 | `<state_dir>/hopae.db` | SQLite 데이터베이스 파일. 지정할 때는 비어 있으면 안 됩니다. |
| `portal.public_url` | 문자열, 출처(origin) | 필수 | 외부에서 보이는 포털 출처, `https://auth.example.test`. Hopae가 내보내는 모든 `Location`에 사용합니다. `https://` 또는 `http://`와 호스트로만 이루어져야 하며 경로, 쿼리, fragment가 없어야 합니다. |
| `gateway.kind` | `hangang` | 필수 | 게이트웨이 어댑터([ADR-0013](../adr/0013-gateway-adapter-boundary.md)). 다른 종류는 나중 작업입니다. |
| `gateway.caller_key_env` | 문자열, 환경 변수 이름 | 없음 | 게이트웨이가 `x-hopae-gateway-key`로 보내는 호출자 키를 담은 변수(게이트웨이 변경 HC-3). `gateway.allow_unauthenticated_caller`가 `true`가 아니면 필수이며, 변수는 시작 시 설정되어 있고 비어 있지 않아야 합니다. 이름 패턴은 `[A-Za-z_][A-Za-z0-9_]*`입니다. |
| `gateway.allow_unauthenticated_caller` | 불리언 | `false` | 개발 전용: 호출자 키 인증을 건너뜁니다. `--check`와 시작 시 경고를 내며 `--strict`는 거부합니다. |
| `log.level` | `error`, `warn`, `info`, `debug`, `trace` | `info` | 로그 상세 수준. |

### 결정되어 예정된 키

이 키들은 ADR과 게이트웨이 계약에 존재하며 표시된 마일스톤에서 구현됩니다. 그
전까지 `hopae --check`는 알 수 없는 키로 거부합니다.

| 키 | 마일스톤 | 기본값 | 결정 문서 |
| --- | --- | --- | --- |
| `gateway.caller_key_next_env` | M1 | 없음 | 교체 중에 함께 받아들이는 두 번째 호출자 키([ADR-0005](../adr/0005-gateway-contract-and-versioning.md)) |
| `gateway.verify_budget_ms` | M1 | `400` | verify 전체 예산. 게이트웨이의 `auth.timeout_ms`보다 작아야 합니다([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |
| `gateway.rate_limit_status` | HC-8 이후 | `403` | 게이트웨이가 중계하게 되면 `429`([ADR-0005](../adr/0005-gateway-contract-and-versioning.md)) |
| `apps[]` (`app_id`, `display_name`, `hosts`, `ports`, `enabled`, `session.idle`, `session.absolute`, `binding.ip`, `binding.ua`, `binding.on_mismatch`, `on_authz_change`, `verify_cache_seconds`) | M1 | ADR 참조 | 애플리케이션 등록부. 정확한 호스트 이름만 허용합니다([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md), [ADR-0007](../adr/0007-context-binding-policy.md)) |
| `session.idle`, `session.absolute` | M1 | `24h`, `30d` | 세션 전체 타이머([ADR-0007](../adr/0007-context-binding-policy.md)) |
| `cookie.name`, `cookie.secure` | M1 | `__Host-hopae`, `true` | 쿠키 이름은 `cookie.name`에서 파생됩니다. `secure=false`는 개발 전용입니다([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)) |
| `providers[]` (`provider_id`, `kind`, `display_name`, `enabled`, `client_id`, `client_secret_env`, `issuer`, `scope`, `endpoint_hosts`, `allow_private_endpoints`, `allowed_email_domains`, `authoritative_domains`, `auto_link`, `trust_email`) | M1(Google), M3(그 외) | ADR 참조 | 저장소에 미러링되는 제공자 정의([ADR-0010](../adr/0010-provider-abstraction.md)) |
| `providers[].endpoint_hosts`, `providers[].allow_private_endpoints` | M1 | `[]`, 미설정(`false`) | 제공자의 디스커버리 문서가 클라이언트를 어디로 보낼 수 있는지(외부 요청 위조 방어, [ADR-0010](../adr/0010-provider-abstraction.md)). 문서가 게시하는 모든 엔드포인트(인가, 토큰, 사용자 정보, 키)는 `https`여야 하고 발급자의 호스트이거나 `endpoint_hosts`에 나열된 호스트(스킴과 포트 없는 호스트 이름 또는 IP 주소)여야 합니다. `google` 프리셋은 자신의 목록을 가집니다. 해석된 주소가 루프백, 사설, 링크 로컬, CGNAT, 멀티캐스트이면 연결 시점에 거부하며 연결은 검증된 주소로만 갑니다. `allow_private_endpoints: true`는 주소 규칙을 해제하고 루프백 발급자에 대한 `http`를 허용합니다. 개발용 및 사설 인증 제공자 전용입니다. 미설정은 `false`입니다(`test-hooks` 빌드는 `true`로 취급하며 명시적 `false`가 항상 우선합니다). |
| `linking.on_conflict`, `linking.mode` | M1 | `link_required`, `verified_email` | 계정 연결 정책([ADR-0011](../adr/0011-account-linking-policy.md)) |
| `txn.max_rows`, `txn.per_ip_per_minute`, `handoff.per_ip_failures_per_minute`, `handoff.max_recoveries` | M1 | `1000`, `30`, `10`, `3` | 트랜잭션과 핸드오프 상한([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)) |
| `portal.sso_confirm_new_host` | M1 | `false` | 세션을 어떤 호스트로 처음 핸드오프하기 전에 한 번 클릭하는 확인([ADR-0004](../adr/0004-session-model-and-cross-domain-handoff.md)) |
| `events.retention_days`, `events.max_rows`, `events.prune_every`, `events.max_pending_per_sink`, `events.delivery_terminal_retention_days` | M1 | `90`, `1000000`, `1000`, `10000`, `7` | 이벤트 보존과 전달 상한([ADR-0009](../adr/0009-event-model.md)) |
| `trusted_proxies` | M1 | `["127.0.0.1/32"]` | 포털 리스너가 `x-forwarded-for`/`x-forwarded-proto`를 신뢰하는 피어 |
| `limits.gateway_max_concurrent`, `limits.portal_max_concurrent` | M1 | `64`, `256` | 리스너별 동시 처리 요청 상한. 초과분은 즉시 `503`(게이트웨이) 또는 `503`(포털)으로 답합니다([ADR-0003](../adr/0003-http-stack-axum-on-hyper.md)) |
| `log.verify_allow`, `log.accept_client_request_id` | M1 | `false`, `false` | 허용된 verify를 개별적으로 로그에 남길지, 클라이언트가 보낸 `x-request-id`를(잘라서) `attrs.client_request_id`에 기록할지([ADR-0009](../adr/0009-event-model.md)) |
| `sessions.retention_days` | M1 | `30` | 종료된 세션과 그 핸들을 세션 보존 스윕이 삭제하는 기준 경과 일수([ADR-0007](../adr/0007-context-binding-policy.md)) |
| `gateway.admin_url` | M1(선택) | 없음 | 게이트웨이 관리 API의 기본 URL(`http(s)`, 자격 증명 없음). `gateway.readonly_token_env`와 함께 쓰면 `hopae --check`가 라우트 목록을 물어 라우트가 없는 애플리케이션 호스트를 경고합니다([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md)의 0단계). `run`은 사용하지 않습니다 |
| `gateway.readonly_token_env` | M1(선택) | 없음 | `hopae --check`에서만 사용하는 읽기 전용 게이트웨이 자격 증명. 라우트가 없는 애플리케이션 호스트를 경고합니다([ADR-0012](../adr/0012-service-registration-and-gateway-config-ownership.md)의 0단계). 전체 불일치 보고는 M2입니다 |
| `cache.local_ttl_ms`, `cache.op_timeout_ms`, `cache.redis_url_env`, `cache.namespace` | M2 | `0`, `50`, 없음, 없음 | 로컬 캐시와 Redis 버스([ADR-0006](../adr/0006-verify-caching-and-invalidation.md)) |
| `store.kind = postgres`, `store.url_env` | M2 | — | 공유 기본 저장소([ADR-0002](../adr/0002-primary-store-sqlite-with-postgres-for-shared-deployments.md)) |

## 동작

- 검증은 `hopae --check`와 `hopae run` 시작 시 같은 규칙으로 실행됩니다. 파일이 유효하지 않으면 `run`은 어떤 리스너도 바인딩하지 않습니다.
- 오류는 모아서 한꺼번에 보고하며, 각각 키 경로를 명시합니다.
- 환경 변수 참조는 존재 여부만 검사합니다. 값은 절대 로그, 출력, 오류 메시지에 나타나지 않습니다.
- 경고(치명적이지 않음): `gateway.allow_unauthenticated_caller`가 설정됨, `listen.gateway`가 루프백 주소가 아님.
- 데이터베이스 경로를 지정하지 않으면 `<state_dir>/hopae.db`로 파생됩니다.

## 제한과 호환성

- JSON만 지원하며 주석은 허용하지 않습니다.
- 1.0 이전에는 마이너 릴리스에서 키의 이름이 바뀌거나 삭제될 수 있습니다. 그런 변경은 각각 CHANGELOG의 `Changed` 아래에 이전 안내와 함께 기록합니다.
- M6 이전에는 다시 로드가 없습니다.

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

다음 명령으로 검증합니다.

```sh
HOPAE_GATEWAY_KEY=<redacted> hopae --check --config examples/hopae.example.json
```

관련 페이지: [아키텍처](ARCHITECTURE.md), [게이트웨이 계약](GATEWAY_CONTRACT.md), 시나리오 013(사전 점검과 시작).
