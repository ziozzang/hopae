# 운영

<!-- translation-status: source=../OPERATIONS.md source-rev=6 status=current -->

[문서 목차](README.md) · [English](../OPERATIONS.md)

마일스톤 M1과 M4-min에서 Hopae 인스턴스를 실행, 관찰, 유지, 복구하는 방법입니다. 여기서
언급하는 모든 설정은 [설정 참조](CONFIG.md)에 정의되어 있고, 게이트웨이와의
프로토콜은 [게이트웨이 계약](GATEWAY_CONTRACT.md)입니다. 운영용 Docker Compose
템플릿과 게이트웨이 라우트 예시는 저장소의 `deploy/` 디렉터리에 있습니다.

## 전제 조건과 설정

- Hopae가 답하는 포워드 인증 확인을 보낼 수 있는 게이트웨이(운영에는 게이트웨이 변경 HC-3가 적용된 Hangang. [호환성 표](GATEWAY_CONTRACT.md#버전-관리) 참고).
- JSON 설정 파일 하나([CONFIG.md](CONFIG.md))와 그 파일이 지정하는 환경 변수: 게이트웨이 호출자 키, 그리고 제공자마다 클라이언트 비밀 값. 비공개 env 파일에 두고 설정 파일이나 이미지에는 절대 넣지 마세요.
- POSIX 권고 잠금과 SQLite WAL을 지원하는 로컬 저장소의 쓰기 가능한 비공개 상태 디렉터리(`state_dir`). 로컬 디스크나 Docker 볼륨이어야 하며 네트워크 파일 시스템은 안 됩니다.
- 상태 디렉터리 하나에 인스턴스 하나. M1은 단일 인스턴스 제품이며 M2 이전에는 공유 저장소가 없습니다.
- 게이트웨이의 공개 라우트 둘: 포털 호스트(공개, `listen.portal`로 프록시)와 보호할 각 애플리케이션 호스트(`hopae --check`가 출력하는 `auth` 조각 포함).
- 두 리스너는 기본적으로 루프백에 바인딩합니다. 게이트웨이 리스너는 절대 공개적으로 접근할 수 있어서는 안 됩니다. 호출자 키는 첫 번째가 아니라 두 번째 방어선입니다.
- 관리 콘솔을 쓰려면(선택): 전용 콘솔 호스트를 위한 세 번째 공개 라우트. `listen.admin`으로 프록시하고 `strip_request_cookies`가 **없는** `auth` 조각을 가집니다(`deploy/hangang-routes.example.json`의 `hopae-admin` 라우트이며 `hopae --check`가 출력함). 게이트웨이의 주소가 `trusted_proxies`에 있어야 하고 `admin.public_url`이 설정되어야 합니다. [관리](ADMIN.md)와 [콘솔](#관리-콘솔)을 참고하세요.

## 동작

### Hopae 실행

```sh
hopae --check --config /etc/hopae/hopae.json     # 검증, 라우트 조각 출력, 종료 코드 0 또는 2
hopae run     --config /etc/hopae/hopae.json     # 서비스(별칭: serve, 기본 명령)
```

항상 `--check`를 먼저 실행하고, 설정을 바꿀 때마다 서비스가 가질 것과 같은 환경에서
다시 실행하세요. 성공하면 `run`은 stdout에 안정적인 줄을 출력하고(`admin` 줄은 `admin.public_url`이
설정된 때만) 서비스를 시작합니다.

```text
portal listening on 127.0.0.1:8700
gateway listening on 127.0.0.1:8701
admin listening on 127.0.0.1:8702
```

시작 순서는 고정입니다. 인스턴스 잠금, 기존 데이터베이스의 읽기 전용 사전 점검,
오래된 데이터베이스 백업, 저장소 열기와 마이그레이션, 제공자 가져오기(같은
트랜잭션에서 `config.loaded` 이벤트), `admin.users[]`의 관리자 부여 가져오기,
애플리케이션 반영, 포털 리스너 바인딩, 관리 리스너 바인딩(켜진 경우), 마지막으로
게이트웨이 리스너 바인딩, 준비 완료. 어느 단계에서든 실패하면 리스너가 요청에 답하기
전에 종료합니다.

`SIGTERM` 또는 `SIGINT`로 멈춥니다. Hopae는 수락을 멈추고, 진행 중인 요청에 5초를
주고, 백그라운드 작업자를 멈추고(나가면서 비웁니다), SQLite 선행 기록 로그를
체크포인트한 뒤 `0`으로 종료합니다. `SIGHUP`은 기록만 하고 무시합니다. 설정 변경은
재시작이 필요합니다(다시 로드는 M6에서 도착합니다).

종료 상태: `0` 정상 중지 또는 명령 성공. `2` 유효하지 않거나 안전하지 않은 설정,
호출자 키 변수 누락, `--config` 누락, 같은 상태 디렉터리의 두 번째 인스턴스.
`1` 그 밖의 모든 런타임 실패. 실패 시 재시작하는 감독자는 변경 없이 `2`에서
재시작하면 안 됩니다. 같은 시작이 같은 방식으로 실패합니다.

### 상태 디렉터리

`state_dir`은 모드 `0700`으로 생성되며 다음을 담습니다.

| 경로 | 내용 | 다루는 법 |
| --- | --- | --- |
| `hopae.db`(또는 `store.path`) | WAL 모드 SQLite 데이터베이스: 사용자, 신원, 세션, 핸들, 트랜잭션, 핸드오프 코드, 이벤트와 전달 행, 제공자, 애플리케이션 | 업그레이드 전에 항상 백업하세요. 해시된 자격 증명만 담습니다. 핸들, 코드, 키는 값이 아니라 SHA-256 다이제스트로 저장됩니다. 그래도 민감하게 다루세요(이메일 주소와 주체가 들어 있습니다). |
| `hopae.db-wal`, `hopae.db-shm` | SQLite 선행 기록 로그와 공유 메모리 | 프로세스가 실행 중일 때 직접 복사하거나 삭제하지 마세요. 정상 종료 시 데이터베이스에 합쳐집니다. |
| `hopae.lock` | 인스턴스 잠금 | 아래를 참고하세요. |
| `hopae.db.bak-v<N>` | 마이그레이션 전에 기록한 백업(0003을 적용할 때는 `hopae.db.bak-v2`) | 아래를 참고하세요. |

데이터베이스 파일은 SQLite가 쓰기 전에 제한적인 모드로 만들어집니다. 제공자 클라이언트
비밀 값과 호출자 키는 상태 디렉터리에 저장되지 않고 환경에만 존재합니다.

### 인스턴스 잠금

시작할 때 Hopae는 `<state_dir>/hopae.lock`에 배타적 권고 잠금을 걸고 프로세스가
사는 동안 유지합니다. 같은 상태 디렉터리에서 두 번째 `hopae run`은 데이터베이스를
건드리기 전에 즉시 `store locked by another instance`와 종료 코드 `2`로 실패합니다.
프로세스가 종료되거나 죽으면 운영체제가 잠금을 풀기 때문에 정리할 낡은 잠금이
없으며 파일 자체는 그대로 두어도 안전합니다. `hopae --check`, `hopae providers
import`, `hopae admin`은 잠금을 잡지 않습니다.

컨테이너에서는 두 인스턴스가 같은 상태 볼륨을 볼 때만 잠금이 효과가 있습니다. "새
이미지를 시험해 보려고" 운영 중인 볼륨에 두 번째 컨테이너를 띄우지 마세요. 먼저
기존 컨테이너를 멈추세요.

### 업그레이드와 마이그레이션 백업

스키마 마이그레이션은 바이너리에 내장되어 있고 시작할 때 앞으로만, 각각 자신의
트랜잭션에서 적용됩니다. 무언가를 쓰기 전에 Hopae는 기존 데이터베이스를 읽기 전용
**사전 점검**합니다. 기록된 버전을 읽고, 더 새로운 버전을 거부하고, 기록된 버전의
기반 구조를 검증합니다. 사전 점검을 통과한 데이터베이스만 백업하고 그 뒤에야
마이그레이션을 적용합니다. 거부된 데이터베이스는 바이트 하나도 바뀌지 않은 채
백업 없이 그대로 남습니다. 바이너리보다 오래된 기존 데이터베이스에 마이그레이션을
적용하기 전에, Hopae는 옆에 일관된 복사본을 `hopae.db.bak-v<N>`으로 기록합니다.
`<N>`은 발견된 스키마 버전이며 모드는 `0600`이고 `VACUUM INTO`로 임시 파일에 기록한 뒤 완성되었을 때만 제자리로
이름을 바꾸므로, WAL 내용이 포함되고 중단된 실행이 이전 백업을 교체하는 일이 없습니다. 새 데이터베이스, 빈 데이터베이스, 이미 최신인 데이터베이스는
백업하지 않습니다. 같은 버전의 기존 백업은 교체됩니다. 더 새 바이너리가 쓴
데이터베이스는 거부됩니다(시작이 실패합니다). 릴리스 이전 개발 빌드가 쓴 스키마 버전 2
데이터베이스도 마찬가지입니다. `sessions.authz_version_at_auth` 열,
`users_primary_email` 또는 `event_deliveries_event_id` 인덱스, `txn_admissions` 테이블이 없으면 알아볼 수 있으며, 종료 상태 2와 함께
"development database from a pre-release schema; delete it" 메시지로 시작이
실패합니다. 첫 릴리스 전에는 스키마 버전 2를 제자리에서 수정했으므로 그런
데이터베이스는 업그레이드할 수 없습니다. 삭제하십시오. 이것이 마이그레이션 `0002`의
마지막 제자리 수정이었습니다(`logout` 트랜잭션 목적이 추가되었으며 `login_txns`의 check
제약으로 알아볼 수 있음). 배포가 데이터베이스를 갖게 된 뒤로는 **모든 스키마 변경이 번호가
매겨진 새 마이그레이션**이며, 위의 백업 뒤에 앞으로만 적용되고, 적용된 마이그레이션 파일은
다시 수정하지 않습니다.

마이그레이션 `0003`(마일스톤 M4-min, 스키마 버전 3)은 관리자 부여 테이블, 신선도 출처를
위한 세션 열(`auth_time_source`, `bound_ua_prefix`), 로그인 트랜잭션의 재인증 열, 콘솔
목록을 위해 `events`, `users`, `sessions`를 대체하는 인덱스를 추가합니다. 기존 세션은
`auth_time_source = hopae_completion`이 됩니다. 새 이벤트 인덱스를 만들 때 이벤트
테이블을 한 번 읽으므로, 이벤트 기록이 큰 경우 업그레이드 뒤 첫 시작이 더 오래 걸립니다.
0003 이전의 바이너리는 마이그레이션된 데이터베이스를 거부하므로(그 바이너리가 지원하는
것보다 새롭기 때문) 0003 이전으로 롤백하려면 `.bak-v2` 파일이나 직접 만든 복사본(아래)을
복원해야 합니다.

업그레이드 절차:

1. 새 바이너리의 `hopae --check`를 현재 설정에 대해 실행합니다.
2. 데이터베이스가 체크포인트되도록 실행 중인 인스턴스를 멈춥니다(`SIGTERM`).
3. 상태 디렉터리(최소한 `hopae.db`)를 안전한 곳에 복사합니다. 자동 백업은 실패한 마이그레이션을 위한 것이며, 나쁜 릴리스에 대비하는 이 복사본을 대신하지 않습니다.
4. 새 바이너리를 시작합니다. 로그에서 `schema foundation validated (v2)`, `database backup written before migration`, `store ready: ... (schema vN)`을 확인합니다. 스키마 2에서 3으로 올라갈 때 백업은 `hopae.db.bak-v2`입니다.
5. 새 바이너리가 실제 트래픽을 처리할 때까지 이전 이미지나 바이너리를 보관합니다.

롤백: Hopae를 멈추고, 저장해 둔 복사본(또는 `.bak-v<N>` 파일)을 `hopae.db` 위에
복원하고, 옆에 남은 `hopae.db-wal`과 `hopae.db-shm`을 지운 뒤 이전 바이너리를
시작합니다. 백업 이후에 만들어진 세션은 사라지고, 백업 이후에 기록된 관리자 부여와 감사 이벤트도 사라지며, 사용자는 다시 로그인합니다.


### 저장소를 PostgreSQL로 이전

`hopae --config <file> store migrate-to-postgres [--from <path>]`는 SQLite 저장소를 `store.postgres`가 가리키는 빈 PostgreSQL 저장소로 복사합니다([ADR-0020](../adr/0020-postgresql-store-backend.md)). `postgres` feature로 빌드한 바이너리가 필요합니다. 명령이 인스턴스 잠금을 잡으므로 먼저 Hopae를 멈춥니다. SQLite 파일은 이 바이너리의 스키마여야 하며(업그레이드 후 SQLite로 한 번 시작), 읽기 전용으로 열리고 바뀌지 않아 롤백 자료로 남습니다. 행이 하나라도 있는 PostgreSQL 저장소와 복사할 수 없는 SQLite 테이블은 거부합니다. 복사는 하나의 트랜잭션이며, 커밋 전에 테이블마다 행 수와 SHA-256 다이제스트를 양쪽에서 비교하고, 테이블별 보고를 출력하며, `store.migrated` 이벤트(실행자, 스키마, 테이블 수, 행 수, 다이제스트)가 데이터와 함께 커밋됩니다. 생애주기 피드와 원장 소비자는 이전 뒤 새 스냅샷을 받습니다. PostgreSQL에서의 서비스는 아직 켜지지 않았습니다(슬라이스 5). `make qualify-postgres`는 로컬 컨테이너로 이전과 복제본 2개 저장소 검증을 실행합니다.

### 관리 콘솔

콘솔은 세 번째 리스너 `listen.admin`(기본값 `127.0.0.1:8702`)이며 `admin.public_url`이
설정된 때만 바인딩합니다. 상태 확인 엔드포인트는 없으며 `/healthz`는 포털에 그대로 있습니다.
다음 순서로 켭니다.

1. 콘솔 호스트(예시에서는 `hopae-admin.example.test`)를 정하고 게이트웨이에 DNS와 TLS를 준비한 뒤 `deploy/hangang-routes.example.json`의 `hopae-admin` 라우트를 등록합니다. 보호 라우트이며 백엔드는 `listen.admin`, 표준 `auth` 조각을 쓰고 `strip_request_cookies`는 **없습니다**. Hopae의 쿠키를 제거하는 라우트는 모든 콘솔 요청을 `403 login_required`로 만듭니다.
2. `admin.public_url`을 설정합니다(필요하면 `listen.admin`, `admin.max_auth_age`와 [설정 참조](CONFIG.md#관리-콘솔)의 다른 `admin.*` 키도). 게이트웨이의 주소가 `trusted_proxies`에 있어야 합니다. 리스너는 신뢰된 피어의 전달 헤더에서만 클라이언트 주소, 스킴, 호스트를 가져오며, 기본값 `admin.untrusted_peers = refuse`에서는 다른 피어에 쿠키를 읽기 전에 `403 untrusted_peer`로 답합니다. 루프백이 아닌 `listen.admin`은 경고를 냅니다. 절대 공개적으로 접근할 수 있어서는 안 됩니다.
3. `hopae --check`를 실행합니다. 콘솔을 암묵적 애플리케이션 `admin`으로 나열하고, 실제 호스트와 관리 주소를 넣은 라우트 조각, `admin.untrusted_peers`, 활성화된 제공자별 신선도 능력(`reauth max_age: ...` 또는 `reauth unsupported: console freshness is Hopae login age; ...`)을 출력합니다. `gateway.admin_url`과 읽기 전용 토큰이 있으면 `console_route_without_auth`나 `console_route_strips_cookies`도 경고합니다. `--strict`는 모든 경고를 오류로 만듭니다.
4. Hopae를 재시작하고 첫 관리자를 부트스트랩합니다. 콘솔 호스트에 한 번 로그인하고, `403 not_admin` 페이지에서 사용자 id를 읽고, `hopae admin grant <user_id> --config <path>`를 실행한 뒤 새로 고칩니다([부트스트랩](ADMIN.md#부트스트랩과-복구)). 컨테이너에서는 `docker compose run --rm hopae admin grant <user_id> --config /etc/hopae/hopae.json`이 인스턴스를 멈추지 않고 같은 상태 볼륨에 대해 실행됩니다.

`admin.users[]`는 시작할 때마다 제공자 가져오기 뒤에 가져옵니다. 결함 있는 항목은 로그의
경고이며(건너뜀, 시작 실패 아님), 어떤 항목도 더 이상 가리키지 않는 살아 있는 파일 부여는
취소됩니다. `hopae admin`으로 하거나 취소한 부여는 파일이 되돌리지 않습니다. 콘솔의 모든
변경, 거부, 부여는 `admin.*` 이벤트입니다([감사 이벤트](ADMIN.md#감사-이벤트)).
`admin.query_budget_ms`에 도달한 저장소 작업은 중단되고 롤백되며 `503`으로 답하고,
`hopae_store_interrupts_total`이 그것을 셉니다.

리스너가 유효한 핸들 외에는 아무것도 신뢰하지 않는지 호스트에서 확인합니다(`x-forwarded-host`에
콘솔 호스트가 없는 요청은 `404`입니다).

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'x-forwarded-host: hopae-admin.example.test' \
  http://127.0.0.1:8702/v1/me      # 403 login_required: 핸들 없음, 요청에서 신뢰하는 것 없음
```

### 호출자 키 교체

호출자 키는 게이트웨이가 `x-hopae-gateway-key`로 보내는 공유 비밀 값입니다. verify
호출이 실패하는 구간 없이 교체하세요.

1. 새 임의 값을 만듭니다. Hopae의 env 파일에 새 변수 이름(예: `HOPAE_GATEWAY_KEY_NEXT`)으로 넣고 `gateway.caller_key_next_env`를 그 이름으로 설정한 뒤 Hopae를 재시작합니다. 이제 두 키를 모두 허용하며, 새 키를 쓴 호출은 `hopae_verify_caller_key_total{slot="next"}`로 집계됩니다.
2. 게이트웨이를 바꿉니다. 라우트의 `static_request_headers`가 참조하는 변수(예: `HANGANG_HOPAE_KEY`)에 새 값을 넣고 게이트웨이를 다시 로드하거나 재시작합니다. 카운터를 보세요. `slot="current"`는 0으로 떨어지고 `slot="next"`가 모든 트래픽을 맡아야 합니다.
3. 승격: `HOPAE_GATEWAY_KEY`를 새 값으로 설정하고, `gateway.caller_key_next_env`(와 next 변수)를 제거한 뒤 Hopae를 재시작합니다. 이제 이전 키는 거부됩니다.

Hopae는 겹침이 시작된 시점을 기록합니다. `caller_key_next_env`가 7일 넘게 설정되어
있으면 `hopae --check`가 경고합니다(`--strict`는 이를 오류로 만듭니다). 키 불일치는
모든 verify의 `403 caller_unauthorized`, 증가하는 `hopae_verify_unauthorized_total`,
읽거나 쓴 상태가 없음으로 나타납니다.

### TLS 인증서 갱신

모든 상호 TLS 리스너(관리자 리스너, 네이티브와 gRPC 게이트웨이)와 투영 수신기의 나가는
mTLS 클라이언트는 자기 파일을 따라갑니다. Hopae는 `reload.tls_interval_secs`(기본
10초)마다 인증서·키·CA를 다시 읽고 내용 다이제스트를 비교합니다. 파일 시스템 알림을
쓰지 않으므로 Kubernetes 시크릿 볼륨의 심볼릭 링크 교체와 제자리 덮어쓰기를 모두
알아챕니다. cert-manager를 쓴다면 시크릿을 디렉터리째(`subPath` 아님) 마운트하고 설정이
`tls.crt`, `tls.key`, `ca.crt`를 가리키게 하세요. 갱신에 재시작이 필요 없습니다.

- 바뀐 자료는 먼저 전부 검사합니다. 인증서가 해석되고, 개인 키가 리프와 맞고, CA 파일에
  인증서가 있어야 합니다. 그다음에야 새 설정을 원자적으로 교체합니다. 새 핸드셰이크가
  그것을 쓰고, 이미 맺어진 연결은 닫힐 때까지 기존 자료를 씁니다. 나가는 클라이언트는
  이후 모든 호출에서 새 채널로 바꿉니다.
- 불러올 때마다 리프의 지문을 로그로 남깁니다(`TLS material reloaded name=…
  fingerprint=sha256:…`). `GET /v1/status`의 `reload.tls[]`는 항목별 `fingerprint`,
  `reloads`, `last_reload_at`, `failing`, `error`를 보여 줍니다.
- 잘못되었거나 반쯤 쓰인 자료(다음 인증서의 키, 빈 CA)는 아무것도 바꾸지 않습니다. 이전
  자료가 계속 쓰이고 `hopae_tls_reload_failing{name}`이 `1`이 되며 경고가 원인을
  밝힙니다. 유효한 자료가 오거나 파일이 사용 중인 자료로 돌아가면 해제됩니다. 이것과
  만료 전에 갱신되지 않는 인증서에 경보를 거세요.
- 교체한 클라이언트 CA는 다음 핸드셰이크부터 자신이 서명한 클라이언트를 받아들이고 이전
  클라이언트를 거부합니다. CA를 교체할 때는 두 인증서를 모두 담은 묶음을 먼저 게시하세요.

### 제공자 비밀 값 교체

제공자 클라이언트 비밀 값은 Hopae가 시작될 때, 그리고 제공자 레지스트리를 만들 때
환경에서 읽으며 다시 로드는 없습니다. 교체하려면 제공자에서 새 비밀 값을 만들고(둘을
허용하는 제공자라면 이전 값을 유효하게 유지), env 파일에서
`providers[].client_secret_env`가 가리키는 변수를 갱신한 뒤 Hopae를 재시작합니다.
재시작 순간 진행 중이던 로그인은 다시 해야 하며, 이미 성립된 세션은 영향이 없습니다.
변수가 없거나 비어 있으면 제공자는 `disabled`로 시작하고(선택 화면에서 빠지고
`/healthz`가 `disabled`로 보고) Hopae는 경고를 기록합니다. 다른 제공자와 기존 세션은
영향을 받지 않습니다.

파일의 제공자 정의 변경은 가져오기 규칙을 따릅니다. 파일은 시작할 때마다 제공자를
삽입하거나 갱신하지만, 실행 중에 바뀌거나 제거된 제공자는 데이터베이스가 권위를
가집니다. 파일 항목을 데이터베이스 위에 다시 덮어쓰려면 `hopae providers import
--force <provider_id> --config <path>`를 실행하고 재시작하세요.

### 로그와 이벤트

Hopae는 **stderr**에 기록하며 stdout에는 위의 시작 줄만 나갑니다.

- **프로세스 로그**: `log.level`의 사람이 읽는 `tracing` 줄(stderr가 터미널이 아니어도 ANSI 색 코드가 들어갑니다). 시작 단계, 경고(안전하지 않은 모드, 비활성 제공자, 가져오기에서 건너뛴 제공자), 백업과 종료 메시지, 오류를 담습니다. 제공자 실패는 응답 본문이 아니라 사유 코드를 기록합니다.
- **이벤트 스트림**: 한 줄에 JSON 객체 하나이며 `log` 싱크가 기록하고, 저장된 이벤트와 같은 필드를 가집니다. `event_id`, `at`(유닉스 초), `kind`, `outcome`(`success`, `failure`, `info`), `reason`, `user_id`, `session_id`, `app_id`, `provider_id`, `client_ip`, `ua_sha256`, `ua_prefix`, `request_id`, `attrs`. 줄에는 식별자와 사유 코드만 있으며 쿠키, 핸들, 코드, 토큰, 비밀 값, 전체 이메일 주소는 기록되지 않습니다. 두 스트림을 나누려면 `{"`로 시작하는 줄로 거르세요.

이벤트 종류: `login.started`, `login.succeeded`, `login.failed`,
`session.created`, `session.handoff`, `handoff.rejected`, `session.terminated`,
`handle.revoked`, `identity.linked`, `identity.conflict`, `csrf.rejected`,
`config.loaded`, `admin.providers_import`, `store.migrated`, `verify.denied`, `provider.error`,
`txn.evicted`, `events.dropped`, `sink.backlog_overflow`, 그리고 콘솔의
`admin.grant`, `admin.revoke`, `admin.user_disable`, `admin.user_enable`,
`admin.session_terminate`, `admin.sessions_terminate`, `admin.denied`. 상태를 바꾸는 종류는 그
변경과 같은 트랜잭션으로 데이터베이스에 기록된 뒤 로그 싱크에 최소 한 번 전달됩니다
(충돌 후 줄이 반복될 수 있으며 `event_id`로 식별합니다). `verify.denied`,
`provider.error`, `txn.evicted`, `events.dropped`, `sink.backlog_overflow`는
진단 이벤트입니다. 최선 노력이고, 부하 시 샘플링되며, 버려지면 `events.dropped`로
요약됩니다. 허용된 verify 호출은 `log.verify_allow`가 `true`가 아니면 기록하지
않습니다.

이벤트는 나이(`events.retention_days`)와 개수(`events.max_rows`)로 정리됩니다. 전달
행은 자체 보존 기간(`events.delivery_terminal_retention_days`)과 대기 백로그 상한
(`events.max_pending_per_sink`)이 있습니다. 종료된 세션과 그 핸들은
`sessions.retention_days`가 지난 뒤 매시간 정리됩니다.

모든 포털 응답에는 `x-request-id`가 붙습니다(그 요청의 이벤트에 같은 값이
`request_id`로 나타납니다). 사용자 제보를 로그와 대조할 때 인용하세요. verify 답변에는
대신 `x-hopae-reason`과 `x-hopae-contract`가 붙습니다.

### `/healthz`

포털 리스너의 `GET /healthz`(게이트웨이의 포털 라우트를 통해서는 포털 호스트)는
프로세스가 요청을 처리하는 동안 항상 JSON 본문과 함께 `200`을 반환합니다.

```json
{"status":"ok","ready":true,"store":"ok","providers":{"google":"ok"},"insecure_mode":false,"unauthenticated_caller":false}
```

- `ready`는 시작이 끝났고 기본 저장소가 방금 질의에 답한 경우에만 `true`입니다. `store`는 `ok` 또는 `unavailable`입니다. `ready`가 `false`여도 HTTP 상태는 `200`입니다. "프로세스가 살아 있고 서비스 중"이라는 뜻이므로, 저장소가 망가진 Hopae로 트래픽을 보내지 말아야 하는 감독자나 로드 밸런서는 상태 코드가 아니라 본문을 읽어야 합니다.
- `providers`는 각 제공자 id를 `ok`, `degraded`(디스커버리나 키 가져오기가 실패했고 백오프로 재시도 중), `disabled`(꺼짐, 삭제됨, 비밀 값 없음)로 매핑합니다.
- `insecure_mode`는 `cookie.secure`가 `false`일 때, `unauthenticated_caller`는 `gateway.allow_unauthenticated_caller`가 `true`일 때 `true`입니다. 운영에서 둘 중 하나라도 `true`이면 잘못된 설정입니다.
- 본문에는 비밀 값도 사용자 데이터도 없습니다. 엔드포인트는 포털 리스너에 있으므로 포털 라우트만큼 공개적입니다. 게이트웨이 리스너에는 상태 확인 엔드포인트가 없습니다.

설정 문제는 `hopae --check`로, 런타임 상태는 `/healthz`로 확인하세요. 둘 다 게이트웨이
라우트가 올바르게 등록되었는지는 증명하지 않습니다. 믿을 만한 종단 간 점검은 보호된
호스트에서의 브라우저 로그인입니다.

### 카운터

Hopae는 프로세스 내 카운터를 유지합니다. M7 이전에는 **운영용 노출이 없습니다**. 값은
`test-hooks` 빌드의 루프백 테스트 훅 리스너로만 읽을 수 있으며 그 빌드는 운영에서
절대 실행하면 안 됩니다. Prometheus 텍스트 노출은 M7입니다. 그때까지는 이벤트
스트림(`verify.denied` 줄에 사유가 있습니다)과 게이트웨이 자체의 카운터(보호된
라우트의 `503`, `403` 비율)를 보세요. 이후 노출을 위해 고정된 카운터 이름은 다음과
같습니다.

| 카운터 | 레이블 | 세는 것 |
| --- | --- | --- |
| `hopae_verify_decisions_total` | `decision`, `reason` | 결과별 모든 verify 결정 |
| `hopae_verify_denied_total` | `reason` | 샘플링 전에 센 모든 verify 거부 |
| `hopae_verify_unauthorized_total` | 없음 | 호출자 키가 없거나 틀린 verify 호출 |
| `hopae_verify_caller_key_total` | `slot`(`current`, `next`) | 설정된 각 키로 인증된 verify 호출 |
| `hopae_verify_overloaded_total` | 없음 | `limits.gateway_max_concurrent`가 소진되어 거부된 verify 호출 |
| `hopae_verify_canonical_mismatch_total` | 없음 | 정규 경로가 게이트웨이의 것과 달랐던 verify 호출 |
| `hopae_store_errors_total` | 없음 | verify 경로의 저장소 실패(`store_unavailable`) |
| `hopae_store_interrupts_total` | 없음 | 마감에서 SQLite 안에서 중단된 저장소 작업 |
| `hopae_admin_requests_total` | `role`, `outcome`(`cookie.secure`가 `false`이면 `insecure_mode="true"`가 더해짐) | 관리 리스너가 답한 요청 |
| `hopae_admin_denied_total` | `reason` | 콘솔의 거부(`untrusted_peer`, `login_required`, `not_admin`, `role_insufficient`, `auth_too_old`, `aal_insufficient`, `self_target`, `actor_revoked`, `overloaded`) |
| `hopae_admin_mutations_total` | `kind` | 무언가를 바꾼 콘솔 변경(`user_disable`, `user_enable`, `sessions_terminate`, `session_terminate`) |
| `hopae_admin_rows_examined_total` | `list`(`users`, `sessions`, `events`) | 콘솔 목록이 살펴본 후보 행 |
| `hopae_admin_grants_imported_total` | `outcome` | 시작할 때의 가져오기가 적용한 부여(`inserted`, `updated`, `revoked`, `unchanged`, `skipped`) |
| `hopae_events_total` | `kind`, `outcome` | 기록된 이벤트 |
| `hopae_events_dropped_total` | `kind` | 저장소에 닿기 전에 버려진 진단 이벤트 |
| `hopae_events_pruned_total` | 없음 | 정리로 삭제된 이벤트 행 |
| `hopae_event_deliveries_delivered_total` | `sink` | 완료된 전달 |
| `hopae_event_deliveries_failed_total` | `sink`, `reason` | 포기한 전달(`retries_exhausted`, `backlog_overflow`, `pruned`) |
| `hopae_build_info` | `version` | 게이지, 항상 `1` |
| `hopae_config_loaded_timestamp` | 없음 | 게이지, 마지막 설정 로드의 유닉스 초 |
| `hopae_tls_reloads_total` | `name`(`admin`, `native_gateway`, `grpc_gateway`, `projection_authority`), `result`(`reloaded`, `invalid`) | 확인 작업이 찾은 TLS 자료 변경 |
| `hopae_tls_reload_failing` | `name` | 게이지, `name`의 최신 자료가 잘못되어 이전 자료를 계속 쓰는 동안 `1` |
| `hopae_config_reloads_total` | `result`(`reconciled`, `invalid`, `restart_required`) | `authentication.source = config`에서 본 설정 파일 변경 |
| `hopae_config_reload_failing` | 없음 | 게이지, 최신 설정 파일이 잘못되어 이전 프로필이 유지되는 동안 `1` |

### 장애 동작

verify는 실패 시 차단합니다(fail closed). Hopae가 해결하지 못하는 조건은 허용이 아니라
거부이고, 게이트웨이는 이해하지 못하는 것을 `503`으로 바꿉니다. 아래 사유는
`verify.denied` 이벤트와 `x-hopae-reason`에 나타납니다.

| 조건 | 클라이언트가 보는 것 | 살필 곳 |
| --- | --- | --- |
| Hopae 중단 또는 접근 불가 | 게이트웨이가 타임아웃되고 `503`으로 답합니다 | 감독자, 프로세스 로그, 종료 상태. 고치고 재시작 |
| 저장소 사용 불가 또는 데이터베이스 오류 | verify `503`(`store_unavailable`), 포털 페이지 `503`, `/healthz`는 `ready:false`, `store:"unavailable"` | 디스크 가득 참, 권한, 손상된 파일. 프로세스 로그 오류, `hopae_store_errors_total` |
| verify 예산 초과(`gateway.verify_budget_ms`) | `budget_exceeded`로 거부 | 느린 디스크나 경합. 예산은 라우트의 `auth.timeout_ms`보다 작게만 올리세요 |
| 동시성 상한 도달 | 즉시 `503`(`overloaded`) | `limits.*_max_concurrent`. 폭주는 대기열이 아니라 상한으로 제한됩니다 |
| 호출자 키가 틀리거나 없음 | 모든 verify에 `403`(`caller_unauthorized`) | 라우트의 키와 `caller_key_env`, 교체 상태 |
| 게이트웨이가 잘못되었거나 지원되지 않는 계약을 보냄 | `400` 또는 `403`(`contract_violation`, `contract_unsupported`, `path_not_canonical`, `wrong_listener`)을 게이트웨이가 `503`으로 매핑 | 라우트의 `auth` 조각과 `hopae --check` 출력 비교 |
| ID 제공자 접근 불가 또는 느림 | 그 제공자의 로그인은 재시도 페이지로 실패(`provider_unavailable`). verify와 기존 세션은 영향 없음 | `provider.error` 이벤트, `/healthz`의 제공자 상태 |
| 알 수 없는 호스트 또는 비활성 애플리케이션 | 거부(`unknown_app`, `app_disabled`) | `apps[]`의 호스트와 포트, `hopae --check`의 반환 origin |
| 60초를 넘는 시계 오차 | 세션이 만료된 것처럼 보이거나 ID 토큰이 실패(`clock_skew`) | 호스트의 시간 동기화 |
| 한 상태 디렉터리의 두 번째 인스턴스 | 시작 거부, 종료 코드 `2` | 다른 인스턴스를 멈추세요 |
| 관리 리스너 주소가 이미 사용 중이거나 다른 리스너와 같음 | 어떤 리스너도 답하기 전에 시작 실패(바인딩 실패는 종료 코드 `1`, `listen.admin`이 포털이나 게이트웨이 주소와 같으면 `2`) | `listen.admin`, `hopae --check` |
| 콘솔 저장소 작업이 너무 느리거나 저장소가 바쁨 | 콘솔이 `503 store_unavailable`로 답하고 변경은 롤백됨. 게이트웨이 리스너의 verify는 영향 없음 | `admin.query_budget_ms`, `hopae_store_interrupts_total`, 프로세스 로그 |
| 사전 점검이 데이터베이스를 거부함(더 새롭거나, 출시 전 스키마이거나, 손상됨) | 시작(과 모든 `hopae admin` 명령)이 종료 코드 `2`로 거부됨. 백업도 마이그레이션도 없음 | 오류 메시지. 복사본을 복원하세요 |
| 이벤트 전달 실패 | 로그인에는 영향 없음. 행은 재시도 후 `failed`가 되고 백로그가 차면 가장 오래된 행이 `failed`(`backlog_overflow`) | `sink.backlog_overflow`, `hopae_event_deliveries_failed_total` |
| 쓰기 도중 충돌 또는 정전 | 다음 시작 때 WAL에서 데이터베이스가 복구됩니다. 진행 중이던 마지막 트랜잭션만 잃을 수 있고, 진행 중인 로그인은 다시 해야 합니다 | 시작 시 프로세스 로그 |

모든 장애에 공통으로 운영자에게 보이는 효과는 로그의 사유 코드, 카운터가 있는 곳의
사유별 카운터, 어떤 메시지에도 비밀 값이 없다는 것입니다.

## 제한과 호환성

- 상태 디렉터리당 인스턴스 하나이며 페일오버가 없습니다. 재시작은 빠르고 세션은 재시작을 넘어 유지됩니다. 다중 인스턴스 배포에는 M2 저장소가 필요합니다.
- M6 이전에는 설정, 제공자 비밀 값, 호출자 키의 핫 리로드가 없습니다. 모든 변경은 재시작이며, 재시작하는 동안 verify는 실패 시 차단합니다(게이트웨이가 `503`으로 답합니다).
- M7 이전에는 메트릭 엔드포인트가 없고 카운터는 프로세스 내에만 있습니다. 관리 콘솔(M4-min)은 사용자와 세션을 읽고 끝낼 수 있으며, 제공자, 애플리케이션, 블랙리스트는 설정 파일, `hopae providers import`, `hopae admin`으로 관리합니다.
- 백업은 멈춘(또는 체크포인트된) 데이터베이스의 파일 복사입니다. 온라인 백업 도구는 M7입니다.
- Hopae는 TLS를 종료하지 않으며 설정된 ID 제공자(디스커버리, 키, 토큰, user-info 엔드포인트) 외에는 인터넷과 통신하지 않습니다. M6 이전에는 텔레메트리도 자가 업데이트도 없습니다. 제공자 트래픽은 `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`를 무시합니다. 프록시가 목적지를 직접 해석하므로 연결 시점 주소 검사를 우회하게 되기 때문입니다. 프록시 옵션은 없습니다.

## 예제, 검증, 관련 페이지

배포 템플릿(`deploy/compose.yaml`, `deploy/hopae.example.json`,
`deploy/env.example`, `deploy/hangang-routes.example.json`이며 마지막 파일에는
`hopae-admin` 콘솔 라우트가 있습니다)은 강화된 컨테이너를
보여 줍니다. 읽기 전용 루트 파일 시스템, 모든 capability 제거, `no-new-privileges`,
메모리와 프로세스 한도, 순환하는 JSON 로그, 비공개 상태 볼륨, 그리고 루프백
리스너를 게이트웨이와만 공유하도록 하는 호스트 네트워킹입니다. 절차는
`deploy/README.md`를 참고하세요.

배포를 검증합니다.

```sh
hopae --version
hopae --check --config /etc/hopae/hopae.json && echo ok
curl -fsS http://127.0.0.1:8700/healthz        # ready:true, store:"ok"
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8701/_hopae/verify'        # 호출자 키가 없으면 403
```

관련 페이지: [설정 참조](CONFIG.md), [게이트웨이 계약](GATEWAY_CONTRACT.md), [아키텍처](ARCHITECTURE.md)(장애 시 동작), [위협 모델](THREAT_MODEL.md).
