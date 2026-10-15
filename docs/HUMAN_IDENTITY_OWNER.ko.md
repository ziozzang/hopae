# Human durable identity 저장 기반 (schema10)

저장/H0 기반이며 Human RPC·receipt·subject 조회·route 활성화가 아니다. 일반 login에 새 issuer/realm 설정을 요구하지 않고 전역 UserId parser나 기존 ID 형식을 바꾸지 않는다.

0010 migration은 공개 Store authority realm을 random32byte/64소문자hex/nonzero로 한 번 만들고, 현재 users의 정확한 ID를 append-only 역사 예약 집합에 원자적으로 backfill한다. realm은 signing key·비밀·proof가 아닌 identity namespace다. before-insert guard는 recursive_triggers off에서도 realm singleton·기존 예약의 REPLACE를 거부하고 update/delete도 금지한다. 사용자 PK는 불변이며 새 INSERT와 같은 transaction에서 ID를 예약한다. hard delete 후에도 역사 ID INSERT/REPLACE를 거부하고 FK로 예약을 제거하지 않는다. 사용자 생성 실패는 identity/event와 함께 rollback한다.

역사는 schema10부터이며 이전 삭제 ID를 복원할 수 없다. 새 realm은 향후 이 기반을 쓰는 Human subject보다 먼저 생성된다. 기존 arbitrary legacy ID를 그대로 보존하고 여기서 canonical subject·issuer binding을 추가하지 않는다. explicit link는 같은 native ID를 유지하고 disable은 기존 authz/session 철회를 따른다. 제출한 UserId/realm으로 권한을 만드는 public API는 없다.

일반 app startup은 기존 lock→read-only precheck→일관된 이전 DB backup→Store migration 순서를 유지한다. 하위 Store::open 자체가 별도 app backup을 만들지는 않는다. v10 precheck는 SQL literal의 case/공백(GLOB 의미)을 보존해 정확한 table/guard·단일 realm·현재 사용자 예약을 확인한다. 손상·누락은 history를 수리하지 않고 거부한다. migration 실패는 rollback하며 zero/legacy realm fallback은 없다. 구 binary는 schema10을 거부하므로 binary만 내리는 rollback은 안전하지 않다. writer를 모두 정지하고 일관된 이전 DB backup을 명시적으로 복구해야 한다. hot rollback·독립 clone·악의적 SQL/DROP·외부 fencing 보장은 없다.

실제 H0 require_human_snapshot은 기존 Store.read_checked SQLite transaction과 main session/user/provider SELECT에서 reservation·realm을 추가 join하고 private Current equality에 realm을 포함한다. SQL 기반이며 zero-query/memory hot path가 아니고 별도 async Store/network 조회를 추가하지 않는다. provider/material/factor/session/handle/app/time/source 검사는 계속 필요하다. realm만으로 인증 capability가 생기거나 public subject/issuer constructor가 제공되지 않는다.

실제 Directory create/link·삭제 뒤 deterministic ID 충돌·reopen realm 유지·현재/역사 REPLACE·PK불변·v9 backfill·guard손상/quoted literal검증·zero realm rollback·실제 OIDC/Engine Current의 realm fault retirement를 검증한다. privileged fault injection은 field 비교/retirement 시험이며 손상·clone DB 지원 주장이 아니다. Human subject/receipt 후속 설계는 별도다.

검증: all-feature 전체workspace1125통과/기존ignore43, strict all-target/all-feature workspace Clippy·format통과. 소유 로컬 LDAP의 LDAPS와 필수 StartTLS 각각 실제 credential login/handoff·TOTP·native Engine/capture통과. 실제 CLI child 재시작/material-owner 검사도 통과했다. 초기 DDL변조 fixture 초기화와 구 exact table inventory 실패는 보존하고 수정 후 최종 전체 검사를 통과했다. 공개 Human proof·운영 배포를 뜻하지 않는다.
