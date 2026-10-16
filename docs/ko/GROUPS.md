# 그룹과 멤버십 투영

<!-- translation-status: source=../GROUPS.md source-rev=2 status=current -->

[문서 목차](README.md) · [English](../GROUPS.md)

Hopae는 그룹을 소유합니다(Hangang ADR 0021). 관리자가 관리하는 로컬 그룹, LDAP
디렉터리에서 동기화하는 그룹(`memberOf` 또는 그룹 검색), OpenID Connect `groups`
클레임에서 가져오는 그룹입니다. 각 그룹은 다시 쓰이지 않는 불투명 참조
`grp1:<26 crockford>`(GroupRef)를 가집니다. Pumgye는 역할을 GroupRef에 바인딩하며,
누가 어느 그룹에 속하는지는 Hopae의 **서명된 멤버십 투영**으로만 압니다. Pumgye는
LDAP나 토큰을 읽지 않고 요청 헤더의 그룹 이름을 신뢰하지 않습니다. 결정 기록은
[ADR-0018](../adr/0018-groups-and-membership-projection.md)입니다.

## 전제 조건과 설정

그룹에는 스키마 버전 14(시작 시 적용되는 마이그레이션 `0014_groups`)가 필요합니다.
로컬 그룹에는 다른 것이 필요 없습니다. 제공자 동기화는 제공자마다 설정하고, 투영에는
서명 키가 필요합니다.

```json
{
  "groups": {
    "max_groups_per_user": 256,
    "change_retention_days": 30,
    "maintenance_interval_secs": 300,
    "stale_group_days": 30,
    "max_staleness_secs": 604800,
    "gateway_header": false,
    "projection": {
      "issuer_ref": "hopae-groups", "key_epoch": 1,
      "public_key": "<base64 Ed25519 public key>",
      "seed_env": "HOPAE_GROUPS_PROJECTION_SEED", "audience": "pumgye"
    }
  },
  "providers": [
    {"provider_id": "corp", "kind": "oidc", "groups": {
      "claim": "groups", "include": "^eng-", "exclude": "-legacy$",
      "rewrite": {"pattern": "^eng-(.+)$", "replacement": "Engineering $1"},
      "max_groups": 100, "removal_grace_secs": 0}},
    {"provider_id": "directory", "kind": "ldap", "ldap": {"…": "…"}, "groups": {
      "ldap": {"mode": "member_of", "member_of_attribute": "memberOf"},
      "include": "ou=apps,dc=example,dc=test$",
      "sync_interval_secs": 3600, "sync_batch": 200}}
  ]
}
```

모든 키와 기본값, 범위는 [설정 참조](CONFIG.md)의 그룹 절에 있습니다. `groups` 절이 없는
제공자는 아무것도 동기화하지 않습니다. 투영 시드는 지정한 환경 변수에 담긴 base64
32바이트 Ed25519 시드입니다. `public_key`와 맞아야 하고 영수증 발급자의 키와 같으면
안 되며, 그렇지 않으면 Hopae는 시작을 거부합니다.

## 동작

### 모델

| 객체 | 필드 |
| --- | --- |
| 그룹 | `group_id`(GroupRef), `source`(`local`, `ldap`, `oidc`), `provider_id`(로컬은 null), `key`(안정적인 원천 키: 로컬 키, 정규화된 LDAP DN, OIDC 클레임 값), `name`, `description`, `state`(`active`, `deleted`), `revision`, `members`, `created_at`, `updated_at`, `last_seen_at`(마지막 동기화 보고), `deleted_at` |
| 멤버십 | 사람(Hopae 사용자 ID, `human1:` 주체로 내보냄), 그룹, `source`, `provider_id`, `first_seen_at`, `last_seen_at`(마지막으로 성공한 단언), `expires_at`(로컬만), `removal_pending_at`과 `stale_at`(제공자만), `added_by`와 `reason`(로컬만) |

시각은 Unix 초입니다. 삭제된 그룹은 묘비로 남아 참조가 계속 해석됩니다. 새 그룹은 같은
키라도 옛 참조를 받지 않습니다. 중첩 그룹은 범위 밖이며, 그룹은 사람만 담습니다.

### 진실의 원천

- 제공자 그룹과 그 멤버십은 그 제공자의 동기화만 씁니다. 관리자가 쓰려 하면
  `409 group_not_local`입니다.
- 로컬 그룹과 그 멤버십은 관리자만 씁니다.
- 한 사람의 전체 그룹 수는 `groups.max_groups_per_user`로 제한됩니다.

### 제공자 동기화

제공자의 단언은 그 제공자에서 본 그 사람의 **전체** 그룹 집합입니다. 저장소
트랜잭션 하나로 적용합니다.

1. 원천 값마다 제공자 규칙을 거칩니다. 잘못된 값(빈 값, 512바이트 초과, 제어 문자)은
   버립니다. `include`는 일치하는 키만 남기고, 이어서 `exclude`가 일치하는 키를
   버립니다. `rewrite`는 표시 이름을 바꾸며(키는 바뀌지 않음) 중복은 하나로 합칩니다.
   LDAP 키는 정규화된 DN(ASCII 문자를 소문자로)이므로 패턴은 소문자로 씁니다. 제어
   문자나 보이지 않는 서식 문자(양방향 재정의, 폭 없는 문자)가 든 이름은 버립니다.
2. 거른 뒤 `max_groups`를 넘거나, 원시 값이 4,096개를 넘거나, 결과가
   `groups.max_groups_per_user`를 넘으면 **단언 전체를 거부**합니다. 아무것도 바뀌지
   않으며 `group.sync_refused` 진단 이벤트를 씁니다. 잘린 집합은 제공자가 여전히
   단언하는 멤버십을 지우기 때문입니다.
3. 모르는 그룹은 만들고, 이름이 바뀌면 이름 변경(`group.updated`)입니다.
4. 새 멤버십을 더합니다. 더 이상 단언되지 않는 멤버십은 `removal_grace_secs`가
   0(기본값)이면 바로 지웁니다. 그렇지 않으면 `removal_pending_at`을 표시하고 유예
   기간 동안 유효하게 두었다가, 다시 단언되지 않으면 유예가 지난 뒤 다음 동기화나 유지
   관리 단계에서 지웁니다.

원천:

- **OIDC**: ID 토큰에서, 없으면 사용자 정보 응답(그 `sub`를 확인한 뒤)에서
  `groups.claim`(기본값 `groups`, `realm_access.roles` 같은 점 경로) 위치의 클레임을
  읽습니다. 클레임이 없거나 문자열 배열이 아니면 단언이 아니며 멤버십은 그대로입니다.
  빈 배열은 "그룹 없음"을 단언합니다. 그룹은 저장되는 식별 클레임에 들어가지 않습니다.
- **로그인 시 LDAP**: `member_of` 방식은 사람 항목을 찾는 같은 검색에서 그 항목의
  `memberOf`(또는 `member_of_attribute`)를 읽습니다. `search` 방식은
  `search_base_dn`(기본값은 제공자의 `base_dn`) 아래에서 `member_attribute`가 그
  사람의 DN인 `object_class` 항목을 찾고 `name_attribute`로 이름을 붙입니다. 둘 다 그
  사람의 바인드 전에 서비스 바인드로 실행하며, 결과는 비밀번호가 확인된 뒤에만
  적용합니다. 그룹 키는 ASCII 문자를 소문자로 바꾸고 구분자 주변 공백을 없앤 DN이며,
  이름은 첫 RDN 값(또는 `name_attribute`)입니다. 불완전한 응답(크기 제한, 참조, 오류)은
  단언이 아닙니다.
- **LDAP 주기 동기화**(`sync_interval_secs`): 유지 관리 단계마다 그 제공자에 연결된
  식별자를 최대 `sync_batch`개씩, 서비스 바인드로 변하지 않는 주체 속성으로 찾아
  갱신합니다. 한 바퀴는 간격당 최대 한 번 시작합니다. 디렉터리에 더 이상 없는 사람은
  "그룹 없음"을 단언합니다. 디렉터리가 답하지 않으면 그 단계를 멈추고 모든 멤버십을
  유지합니다(`last_error`를 기록).

동기화는 로그인을 막지 않습니다. 실패하거나 거부된 동기화는 이전 멤버십을 유지합니다.
따라서 멤버십은 마지막으로 성공한 동기화 시점의 제공자 상태를 반영하며, 디렉터리에
닿을 수 없는 동안에는 회수되지 않습니다. 다만 그 기간은 제한됩니다(최대 오래됨을 둔
정적 실패).

### 최대 오래됨

`groups.max_staleness_secs`(기본값 7일) 동안 어떤 성공한 단언(그 제공자를 통한 로그인,
또는 주기 LDAP 갱신)도 확인하지 않은 제공자 멤버십은 유지 관리 단계에서 **정지**됩니다.
`stale_at`이 설정되고 `group.membership_stale` 이벤트를 씁니다. 정지된 멤버십은
저장소에 남고 콘솔에 보이지만(`membership.stale_at`, 해석의 `stale: true`), 멤버십
투영(`member_removed`로 저널 기록)과 게이트웨이 반영에서는 빠집니다. 그 멤버십을
포함하는 다음 단언이 이를 되살리며(`group.membership_restored`, `member_added`로 저널
기록), 그것을 빠뜨린 단언은 평소처럼 지웁니다. 로컬 멤버십은 오래되지 않습니다.
게이지 `hopae_group_memberships_stale`은 단계마다 정지된 멤버십 수를, 카운터
`hopae_group_memberships_suspended_total`은 정지 횟수를 알립니다. 제공자의
`sync_interval_secs`는 이 한도보다 짧아야 하고, `sync_batch`는 연결된 사람 전체를 한
바퀴 도는 데 한도 안에 끝날 만큼 커야 합니다.

### 유지 관리

Hopae는 `maintenance_interval_secs`마다 만료된 로컬 멤버십, 유예가 지난 제공자
멤버십, 제공자 행이 삭제된 멤버십을 지우고, 구성원이 없고 `stale_group_days` 동안
어떤 동기화도 보고하지 않은(또는 제공자가 없어진) 제공자 그룹을 삭제하며,
`change_retention_days`보다 오래된 투영 저널 행을 정리하고(가장 새 행은 항상 남김)
주기 LDAP 동기화 단계를 실행합니다. 읽기는 유지 관리 전이라도 만료된 로컬 멤버십을
숨깁니다.

### 게이트웨이 헤더(기본값 꺼짐)

`groups.gateway_header: true`이면 Hopae는 사람의 그룹 참조(사전순 최대 32개)를
`users.groups`에 반영하여 [게이트웨이 계약](GATEWAY_CONTRACT.md)의
`x-forwarded-groups`가 이를 싣게 합니다. 변경은 `authz_version`을 올리며, 각
애플리케이션의 `on_authz_change`에 따라 세션을 갱신하거나 끝냅니다. 기본값이 꺼짐인
이유: 이 헤더는 애플리케이션을 위한 참고 정보이고, Pumgye는 이를 읽지 않으며, 영수증에는
그룹이 실리지 않습니다([ADR-0018](../adr/0018-groups-and-membership-projection.md)
결정 6).

## 관리 API, 콘솔, 관측

모든 엔드포인트는 관리 리스너의 JSON 본문 `POST`이며 콘솔의 JSON API 규칙
(`application/json`, `x-hopae-admin-request: 1`, 같은 출처의 `Origin`/`sec-fetch-site`)을
따르고 `cache-control: no-store`로 답합니다. Hangang 위임 콘솔 행위자는 본문 전체에
대한 서명된 단언으로 각각을 호출할 수 있습니다.

### 읽기(부여된 모든 역할)

| 엔드포인트 | 본문 | 응답 |
| --- | --- | --- |
| `/v1/groups/search` | `q`(이름 부분 문자열, 키 접두사, 또는 정확한 GroupRef, 128자 이하), `source`, `provider_id`, `include_deleted`, `limit`(1–100, 기본값 50), `cursor` | `items`(그룹 보기), `next_cursor` |
| `/v1/groups/get` | `group_id`, `members_limit`(0–200, 기본값 50), `members_cursor`, `privacy_profile` | `group`, `members`(해석 형식의 `subject`, `membership`), `next_members_cursor`, `privacy_profile` |
| `/v1/subjects/groups` | `id`(`u_…` 또는 `human1:…`), `limit`(1–200, 기본값 100), `cursor` | `id`, `user_id`, `status`(`resolved`, `unknown`), `items`(`membership`이 붙은 그룹 보기), `next_cursor` |
| `/v1/subjects/resolve` | [주체 디렉터리](SUBJECT_DIRECTORY.md)와 같고 `include_groups` 추가 | 사람 항목마다 `groups`(최대 20개: `group_id`, `name`, `source`)와 `groups_truncated` |
| `/v1/subjects/lifecycle` | 주체 디렉터리와 같고 `include_groups` 추가 | `group_id`가 붙은 `group_created`, `group_updated`, `group_deleted`, `member_added`, `member_removed`, `member_suspended`, `member_restored` 변경도 담음 |

목록 커서는 다른 콘솔 커서처럼 프로세스에 묶입니다. 답한 모든 읽기는 응답 전에
`admin.read`(`purpose`는 `groups.read`, `groups.projection`, 또는 주체 목적)를 씁니다.

### 쓰기(`admin` 역할)

| 엔드포인트 | 본문 | 성공 |
| --- | --- | --- |
| `/v1/groups/create` | `key`(`[A-Za-z0-9._:-]` 1–128자), `name`(256자 이하), `description`(1024자 이하), `reason` | `201 {"group": …}` |
| `/v1/groups/update` | `group_id`, `expected_revision`, `name`과/또는 `description`(`""`은 지움), `reason` | `200 {"group": …}` |
| `/v1/groups/delete` | `group_id`, `expected_revision`, `force`(구성원이 있으면 `true` 필수), `reason` | `200`, 묘비 |
| `/v1/groups/members/add` | `group_id`, `expected_revision`, `user_id`, `expires_at`(선택, 1년 이내), `reason` | `200`, 그룹 |
| `/v1/groups/members/remove` | `group_id`, `expected_revision`, `user_id`, `reason` | `200`, 그룹 |

`reason`은 필수(1–256자)이며 기록됩니다. 그룹이나 그 구성원이 바뀔 때마다 `revision`이
오르며, `expected_revision`이 다른 쓰기는 `current_revision`과 함께
`409 revision_conflict`입니다. 그 밖의 응답: `400 invalid_request`,
`404 group_not_found`, `404 unknown_user`, `409 key_in_use`(살아 있는 로컬 그룹이 그
키를 가짐), `409 already_member`, `409 not_member`, `409 group_not_local`,
`409 too_many_groups`, `409 group_full`(구성원 50,000명), `409 group_not_empty`
(구성원이 남았는데 `force: true` 없이 삭제), `409 too_many_local_groups`
(10,000개), `410 group_deleted`, 콘솔 인증·역할 확인·행위자 펜스에서 오는 `403`,
`429 rate_limited`, `503 store_unavailable`.

### 감사와 제한

모든 변경은 같은 트랜잭션에서 필수 이벤트를 씁니다. `group.created`,
`group.updated`(`attrs.change`: `renamed` 또는 `described`), `group.deleted`
(`attrs.count`: 지운 구성원 수), `group.member_added`, `group.member_removed`,
`group.membership_stale`, `group.membership_restored`이며,
`attrs.group_id`, `attrs.source`, `attrs.revision`, `attrs.cause`(`admin`, `login`,
`periodic_sync`, `expired`, `grace_elapsed`, `provider_deleted`, `stale`,
`maintenance`)를 담고, 관리자 쓰기는 행위자 속성과 `attrs.note`(사유)도 담습니다.
거부된 동기화는 진단 이벤트 `group.sync_refused`를 씁니다. 행위자별 토큰 버킷: 그룹
읽기는 버스트 60과 초당 1, 쓰기는 버스트 30과 초당 0.5, 투영은 버스트 120과 초당 2입니다.

## Pumgye를 위한 멤버십 투영

### 요청

`POST /v1/groups/projection/snapshot`:

```json
{"groups": ["grp1:…", "grp1:…"], "limit": 200, "cursor": null}
```

`POST /v1/groups/projection/changes`:

```json
{"groups": ["grp1:…"], "cursor": "r1042", "limit": 200}
```

`groups`는 관련 어휘입니다. 현재 Pumgye 문서가 참조하는 GroupRef 1개에서 1,024개이며
(더 큰 어휘는 샤드로 나눔), 응답에는 그 그룹의 멤버십만 들어갑니다. 스냅숏 `limit`은
1–500명(기본값 200)이며 그룹 참조가 50,000개에 이르면 페이지가 일찍 끝납니다. 피드
`limit`은 변경 1–500개(기본값 200)이며 페이지마다 저널 행을 최대 20,000개 살펴봅니다.
키가 설정되지 않으면 둘 다 `503 projection_unavailable`로 답합니다.

### 봉투와 서명

모든 응답은 서명된 봉투 하나입니다.

```json
{"format": "hopae.membership-projection.v1",
 "key": {"issuer_ref": "hopae-groups", "key_epoch": 1},
 "payload": "<base64url without padding: the payload bytes>",
 "signature": "<base64url without padding: Ed25519 signature>"}
```

서명은 `"hangang-zerotrust:hopae-membership-projection:v1\0" || 페이로드 바이트`에
대한 Ed25519입니다. 페이로드는 헤더 필드 `kind`(`snapshot` 또는 `changes`),
`issuer_ref`, `key_epoch`, `audience`, `store`(저장소 정체), `vocabulary_sha256`(정렬하고
중복을 없앤 어휘를 `\n`으로 이은 것의 SHA-256 16진), `issued_at`(밀리초), `max_aal`
(Hopae가 발급하는 가장 높은 AAL, ADR 0021의 능력 광고)을 담은 JSON 객체이며, 그 밖에:

- 스냅숏: `watermark`(첫 페이지 전의 저널 리비전. 이후 페이지는 커서에서 되돌려
  줌), `cursor`(요청의 커서, 첫 페이지는 null), `entries`(`principal` — `human1:`
  주체, Human 영수증이 설정되지 않으면 null — `user_id`, `status`, `groups`),
  `next_cursor`(`p1.<watermark>.<user_id>`), `more`;
- 변경: `from`, `head`, `changes`(`revision`, `at`, `change` — `group_created`,
  `group_updated`, `group_deleted`, `member_added`, `member_removed` — `group_id`,
  `user_id`, `principal`), `next_cursor`(`r<revision>`), `more`.

### 검증 계약(Pumgye가 구현할 것)

1. 봉투를 파싱합니다(모르는 필드는 거부). `format`은
   `hopae.membership-projection.v1`이어야 하고 페이로드는 4 MiB 이하입니다.
   GroupRef의 정규형은 **소문자**입니다. `grp1:` 뒤에
   `0123456789abcdefghjkmnpqrstvwxyz` 중 26자(Hopae가 쓰는 Crockford base32)가
   옵니다. 바이트 단위로 비교하고 다른 표기(대문자, `i`/`l`/`o`/`u`)는 거부하며, 대소문자를
   접지 않습니다.
2. `(issuer_ref, key_epoch)`에 대한 **고정된** 공개 키를 Pumgye 자신의 설정에서
   찾습니다. 봉투나 Hopae가 준 키는 받지 않습니다. 모르는 쌍은 거부합니다.
3. 도메인 문자열 뒤에 디코딩한 페이로드 바이트를 이은 것에 대해 서명을 엄격하게
   (`verify_strict`) 검증합니다. 그다음에야 페이로드를 파싱합니다.
4. `kind`가 요청한 엔드포인트(`snapshot` 또는 `changes`)와 같고,
   `issuer_ref`/`key_epoch`가 봉투와 같고, `audience`가 Pumgye 자신의 식별자와 같고,
   `vocabulary_sha256`이 Pumgye가 보낸 어휘의 다이제스트와 같고, `issued_at`이 Pumgye의
   신선도 범위 안(그리고 60초를 넘는 미래가 아님)인지 확인합니다.
5. `store`를 기억합니다. 값이 다르면 다른 Hopae 저장소이거나 복원된 것이므로 투영을
   버리고 새 스냅숏을 받습니다.
6. 스냅숏은 모든 페이지(같은 어휘)를 순회해 적용합니다. 각 페이지의 `cursor`는
   Pumgye가 보낸 커서(첫 페이지는 null)와, `watermark`는 첫 페이지의 것과 같아야
   합니다. 그다음 `more`가 false가 될 때까지 `watermark`부터 피드를 적용합니다. 변경
   페이지마다 `from`은 Pumgye가 요청한 리비전과 같아야 하고 `next_cursor`는 뒤로 가면
   안 됩니다. 투영 리비전은 마지막으로 적용한 `next_cursor`입니다. 변경은 집합 연산이므로 되풀이되거나 겹친 페이지는 해가
   없습니다. `410 cursor_expired`는 저널이 그 위치를 더 이상 갖고 있지 않다는
   뜻이므로(보존 기간, 또는 다른 저장소) 새 스냅숏을 받습니다.
7. `principal`이 null인 항목은 바인딩할 수 없으므로 무시합니다.

`hopae::groups::projection::verify`가 참조 구현이며, 시나리오 312가 실제 응답을 이것으로
확인합니다.

키 교체는 영수증 키 규칙을 따릅니다. 먼저 Pumgye에 다음 키를 설정하고(두 에포크를
모두 허용), Hopae의 `groups.projection`을 `key_epoch + 1`인 새 키로 바꾼 뒤, Pumgye에서
옛 에포크를 은퇴시킵니다(하한이 올라가 그 뒤로는 옛 에포크를 거부).

## 제한과 호환성

- 스키마 14는 패스키 브랜치의 0011–0013 다음 번호이며, 그 브랜치가 먼저 병합되어야
  합니다. 그것들 없이 14로 마이그레이션된 저장소는 나중에 그것들을 받지 못합니다.
- 중첩 그룹, 그룹 소유자, 동적(규칙 기반) 그룹은 범위 밖입니다.
- Hopae에는 주체 병합이 없습니다. 멤버십은 옮겨지지 않으며 `merged`는 만들어지지
  않습니다.
- SCIM 프로비저닝은 계획되어 있습니다(P2, [로드맵](ROADMAP.md)).
- 사람의 제공자 멤버십은 로그인할 때나 주기 LDAP 동기화로만 갱신됩니다. 더 이상
  로그인하지 않는 사람의 OIDC 그룹은 `groups.max_staleness_secs`가 지나면 정지됩니다.
- 투영 어휘는 요청당 최대 1,024개 그룹입니다.

## 예시, 검증, 관련 문서

```sh
curl -sS https://hopae-admin.example.test/v1/groups/create \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -b '__Host-hopae=<redacted>' \
  -d '{"key":"eng.oncall","name":"On-call","reason":"rota 2026-Q4"}'
```

자체 OpenLDAP 픽스처(`tools/owned_ldap_smoke.py`, `memberof` 오버레이 사용)는
`owned_ldap_groups_sync_by_member_of_and_group_search`를 실제 디렉터리에 LDAPS와
StartTLS로 실행합니다. 로그인 시 `memberOf`와 그룹 검색, 변하지 않는 주체로 찾는 주기
조회, 사라진 주체, 잘못된 비밀번호에는 그룹이 없음을 확인합니다.

시나리오 [310](../../scenarios/310-local-groups.md),
[311](../../scenarios/311-provider-group-sync.md),
[312](../../scenarios/312-membership-projection.md),
[313](../../scenarios/313-group-lifecycle-feed.md)이 동작을 규정합니다. 관련 문서:
[주체 디렉터리](SUBJECT_DIRECTORY.md), [관리](ADMIN.md),
[LDAP 인증](LDAP_AUTHENTICATION.md), [위협 모델](THREAT_MODEL.md)(TM-62, TM-63, TM-64).
