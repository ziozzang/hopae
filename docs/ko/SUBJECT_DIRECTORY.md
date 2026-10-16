# 주체 디렉터리 API

<!-- translation-status: source=../SUBJECT_DIRECTORY.md source-rev=4 status=current -->

[문서 목차](README.md) · [English](../SUBJECT_DIRECTORY.md)

주체 디렉터리는 스택 전체에서 쓰는 불투명한 주체 참조 — Hopae 사용자 ID(`u_…`),
정규 Human 주체(`human1:<64 hex>`), 서비스 주체(`s_<48 hex>`) — 를 운영자가 보아야
하는 정보로 바꿉니다. 표시 이름, 가린 이메일 주소, 주체 종류, 제공자, 상태(`active`,
`disabled`, `deleted`), 생성 시각과 활동 시각입니다. 주체 선택기를 위한 검색과,
정책 기관(Pumgye)이 주체가 비활성화되거나 삭제된 바인딩을 찾을 수 있도록 하는
생명주기 피드와 대조용 스냅숏도 제공합니다. 이는 통합 콘솔(Hangang ADR 0020)과
Pumgye 인가 모델 개정(Hangang ADR 0021)이 Hopae에 맡긴 소유자 API입니다. 관리
리스너에서 HTTP로만 제공하며 나머지 [관리 API](ADMIN.md)와 나란히 있습니다. Hopae의
gRPC 표면은 게이트웨이 트래픽만 다루며 관리용 대응이 없습니다.

## 전제 조건과 설정

- 관리 콘솔이 켜져 있어야 합니다(`admin.public_url`, `listen.admin`).
  [관리](ADMIN.md)를 참고하십시오. 추가 설정 키는 `admin.directory_privacy`
  (기본값 `standard`, 또는 `strict`) 하나뿐입니다. 주체 디렉터리와 explain API가
  답할 수 있는 가장 덜 엄격한 프로필입니다. 요청의 `privacy_profile`은 답을 더
  엄격하게만 만들 수 있습니다. 하한보다 낮은 프로필을 요청하면 하한으로 답하며, 응답의
  `privacy_profile`은 실제로 적용된 프로필을 밝힙니다.
- 부여된 역할(`viewer` 또는 `admin`)이면 네 가지 읽기를 모두 호출할 수 있습니다.
  Hangang 위임 콘솔 행위자(`admin.hangang_delegation`)는 본문 전체에 대한 서명된
  단언으로 호출할 수 있습니다.
- Human 주체(`human1:`)는 `receipt_issuer.human_receipts`가 설정된 경우에만
  해석됩니다. 주체는 영수증 발급자 참조, 저장소의 Human 영역(realm), 사용자 ID로부터
  유도됩니다. 설정이 없으면 `human1:` 참조는 사유 `human_subjects_not_configured`와
  함께 `unknown`으로 답하며, 생명주기 피드의 `human_subject`는 `null`입니다.
- 서비스 주체는 게시된 서비스 인증 프로필에서 해석합니다. 모든 프로필의 모든
  `api_keys[]` 주체가 대상입니다. 인증 시점에 원격 검증기가 만드는 주체(API 릴레이,
  Kubernetes TokenReview)는 열거할 수 없으므로 `not_enumerable`과 함께 `unknown`으로
  답합니다.
- Kubernetes 워크로드 주체(`wk2:<64 hex>`)와 SPIFFE ID도 인증 시점에 만들어지므로
  `not_enumerable`, `kind: workload`와 함께 `unknown`으로 답합니다. 그 생명주기는
  `include_workloads`를 준 피드에 있습니다([Kubernetes 워크로드](KUBERNETES_WORKLOAD.md)).

## 동작

### 요청 규칙

모든 읽기는 JSON 본문을 가진 `POST`이며 감사 기록 외에는 어떤 상태도 바꾸지 않습니다.
`POST`이므로 브라우저 요청은 콘솔의 JSON API 규칙을 지켜야 합니다.
`content-type: application/json`, 헤더 `x-hopae-admin-request: 1`, 그리고 있을 경우
콘솔 출처와 같은 `Origin`과 `same-origin` 또는 `none`인 `sec-fetch-site`입니다. 지키지
않은 요청은 `403 csrf_rejected`입니다. 본문은 최대 64 KiB이며 알 수 없는 필드는
거부합니다. 응답에는 `cache-control: no-store`가 붙습니다.

### 해석

`POST /v1/subjects/resolve`

```json
{"ids": ["u_01J...", "human1:9f…", "s_3c…", "u_gone"], "privacy_profile": "standard"}
```

- `ids`: 참조 1~100개, 각각 1~256바이트입니다. 더 긴 목록, 빈 목록, 너무 긴 참조는
  `400 invalid_request`입니다. 중복은 처음 나온 순서대로 한 번만 답합니다.
- `privacy_profile`: `standard`(기본값)는 표시 이름과, 첫 글자와 도메인만 남기고 가린
  기본 이메일 주소(`a***@example.test`)를 돌려줍니다. `strict`는 표시 이름만 돌려주며
  이메일 주소는 어떤 형태로도 돌려주지 않습니다.

서로 다른 참조마다 항목이 하나씩 있으며, 아무것도 가리키지 않는 참조도 오류가
아닙니다.

| `status` | `reason` | 의미 |
| --- | --- | --- |
| `active` | `null` | 살아 있는 사용자, 또는 설정되어 있고 만료되지 않은 서비스 주체 |
| `disabled` | `null` | 관리자가 비활성화한 사용자 |
| `disabled` | `credential_expired` | 설정된 자격 증명이 만료된 서비스 주체 |
| `deleted` | `null` | 묘비(tombstone): 사용자 ID가 추가 전용 예약 원장에는 있지만 사용자 행이 없습니다. 개인 정보는 돌려주지 않습니다. |
| `unknown` | `not_found` | 형식은 맞지만 Hopae가 발급한 적이 없는 사용자 ID 또는 Human 주체 |
| `unknown` | `unrecognized` | 사용자 ID, `human1:` 주체, `s_` 주체 어느 것도 아님(세션 ID는 주체가 아닙니다) |
| `unknown` | `human_subjects_not_configured` | Human 영수증이 설정되지 않은 상태의 `human1:` 주체 |
| `unknown` | `index_incomplete` | Human 주체 색인이 요청 예산 안에 원장을 따라잡지 못했습니다. 다시 시도하십시오. |
| `unknown` | `not_enumerable` | 설정된 API 키 주체가 아닌 `s_` 주체 |

항목 필드는 `id`, `status`, `reason`, `kind`(`human`, `service`, `workload`),
`user_id`, `human_subject`, `display_name`, `email`, `providers`(연결된 신원의
제공자), `created_at`, `last_login_at`, `last_seen_at`(가장 최근 세션 활동),
`service_id`, `realm`, `expires_at`(서비스 자격 증명, 밀리초)입니다. 값이 없으면
생략하지 않고 `null`입니다. 응답에는 `resolved`, `unknown`, `privacy_profile`,
`complete`(Human 주체 색인이 불완전했으면 `false`)도 들어 있습니다.

Human 주체는 주체에서 예약 원장 위치로 가는 색인으로 해석하며, 이 색인은 원장을
점진적으로 따라잡습니다(원장은 추가 전용입니다). 모든 후보는 믿기 전에 원장 행에서
다시 유도하므로, 오래되었거나 충돌한 색인 항목은 놓침만 일으킬 수 있습니다. 색인은
저장소와 발급자마다 최대 2,097,152개 위치를 담습니다.

### 검색

`POST /v1/subjects/search`

```json
{"q": "alice", "kind": "human", "status": "active", "limit": 20, "cursor": null, "privacy_profile": "standard"}
```

- `q`: 제어 문자가 없는 1~128자입니다. `kind: "human"`(기본값)이면 기본 이메일과
  사용자 이름은 접두사로, 표시 이름은 대소문자를 구분하지 않는 부분 문자열로
  일치시키며, 제한된 후보 창을 가진 콘솔의 사용자 목록 조회를 거칩니다. 정확한 사용자
  ID나 Human 주체는 해석으로 답합니다. `kind: "service"`이면 주체 이름, 서비스,
  영역, 참조를 ASCII 대소문자를 구분하지 않는 부분 문자열로 일치시킵니다.
- `status`: `active` 또는 `disabled`. `limit`: 1~50, 기본값 20. `cursor`: 이전 응답의
  `next_cursor`(다른 콘솔 목록 커서와 마찬가지로 프로세스에 묶여 있습니다).

응답은 `{"items": [...], "next_cursor": ..., "privacy_profile": ...}`이며 항목은 해석과
같은 모양입니다.

### 생명주기 피드

`POST /v1/subjects/lifecycle`

```json
{"cursor": "f1.42.1093.e_06GM8SA6R985XVGVXG1P2787G0", "limit": 100}
```

피드는 지속 커서 이후에, Hopae가 설명 대상 상태와 원자적으로 기록하는 변화를
알립니다.

| `change` | 출처 | 기록 시점 |
| --- | --- | --- |
| `created` | 사용자 ID 예약 원장(스키마 v10), 생성 순서 | 사용자를 만드는 트랜잭션 안 |
| `disabled` | `admin.user_disable` 아웃박스 이벤트 | 사용자를 비활성화하는 트랜잭션 안, 상태가 바뀔 때만 |
| `enabled` | `admin.user_enable` 아웃박스 이벤트 | 사용자를 활성화하는 트랜잭션 안, 상태가 바뀔 때만 |

각 변화에는 `user_id`, `human_subject`, `at`, 그리고 `status`(페이지를 읽은 시점의
주체 상태: `active`, `disabled`, `deleted`)가 들어 있습니다. 소비자는 `status`를
적용하므로, 다시 받거나 순서가 바뀐 페이지도 해가 없습니다. 한 페이지 안에서는
`created` 변화가 먼저 옵니다. `next_cursor`는 페이지 다음 위치이고 `more`는 이미 더
가져올 것이 있는지 알려 줍니다. 커서 `f1.<ledger>.<outbox row>.<event id>`는 비밀이
아니고 프로세스에 묶여 있지 않으므로, 소비자는 어느 쪽이 다시 시작해도 이를 유지합니다.
커서 없이 호출하면 보존된 가장 오래된 변화부터 시작합니다.

Hopae에는 사용자 삭제나 계정 병합 작업이 없습니다. 다른 방법으로 지워진 사용자 행은
스냅숏에서만(`deleted`) 보이며 `merged`는 만들어지지 않습니다. 따라서 소비자는 피드와
함께 스냅숏도 주기적으로 실행합니다(Hangang ADR 0021: 워터마크 비교와 주기적 전체
대조).

`410 cursor_expired`는 커서의 아웃박스 행이 더 이상 커서가 가리킨 행이 아니거나
(`events.retention_days`/`events.max_rows`에 의한 정리, 복원되거나 교체된 저장소), 원장
위치가 저장소의 것을 넘어선다는 뜻입니다. 새 스냅숏을 받아 그 워터마크부터 이어
가십시오.

### 대조 스냅숏

`POST /v1/subjects/lifecycle/snapshot`

```json
{"cursor": null, "limit": 200}
```

예약된 모든 사용자 ID를 원장 순서대로 `user_id`, `human_subject`, `status`(`active`,
`disabled`, `deleted`), `created_at`과 함께 돌려줍니다. 페이지당 최대 200개이며 끝날
때까지 `next_cursor`(`l1.<position>`)가 있습니다. 첫 페이지에는 `watermark`도 있습니다.
첫 페이지를 읽기 전에 잡은 피드 커서이므로, 페이지가 놓친 변화도 그 이후의 것은 모두
피드에 있습니다. 스키마 v10 이전에 삭제된 ID는 원장에 없으므로 알릴 수 없습니다.

## 관리 API, 콘솔, 관측

| 엔드포인트 | 본문 | 응답 |
| --- | --- | --- |
| `POST /v1/subjects/resolve` | `ids`, `privacy_profile` | `items`, `resolved`, `unknown`, `complete`, `privacy_profile` |
| `POST /v1/subjects/search` | `q`, `kind`, `status`, `limit`, `cursor`, `privacy_profile` | `items`, `next_cursor`, `privacy_profile` |
| `POST /v1/subjects/lifecycle` | `cursor`, `limit`(1~200, 기본값 100), `include_groups`, `include_workloads` | `changes`, `next_cursor`, `more` |
| `POST /v1/subjects/lifecycle/snapshot` | `cursor`, `limit`(1~200, 기본값 200) | `items`, `next_cursor`, `watermark` |
| `POST /v1/subjects/workloads/snapshot` | `cursor`, `limit`(1~200, 기본값 200) | `items`, `next_cursor`, `watermark` |

오류: `400 invalid_request`(모양, 범위, 알 수 없는 필드), `400 invalid_cursor`, 콘솔
인증과 JSON API 규칙에 따른 `403`, `410 cursor_expired`, `retry-after`가 붙은
`429 rate_limited`, `503 store_unavailable`, `503 audit_unavailable`.

행위자마다 읽기 계열별 토큰 버킷이 있습니다. 해석은 순간 60건에 초당 1건, 검색도
같고, 생명주기 피드와 스냅숏은 합쳐서 순간 120건에 초당 2건입니다. 위임된 요청이면
행위자는 Hangang 위임 행위자이고, 아니면 로그인한 관리자입니다.

답한 모든 읽기는 응답이 나가기 전에 필수 이벤트 `admin.read`를 씁니다. 기록을 쓸 수
없는 읽기는 `503 audit_unavailable`로 거부합니다. 기록에는 행위자(`attrs.actor`,
`attrs.actor_session`, 위임 요청이면 `attrs.delegated_actor`), `attrs.purpose`
(`subjects.resolve`, `subjects.search`, `subjects.lifecycle`), `attrs.endpoint`,
`attrs.query_sha256`(요청 본문의 SHA-256), `attrs.requested`, `attrs.count`가
들어갑니다. 참조, 검색어, 개인 정보는 절대 담지 않습니다. 변화가 없는 생명주기 조회는
기록하지 않습니다. 거부된 요청은 읽기가 아니므로 읽기로 기록하지 않습니다.

## 제한과 호환성

- 그룹, 그 생명주기, 서명된 멤버십 투영은 [그룹](GROUPS.md)에서 설명합니다.
  `include_groups: true`이면 해석은 사람마다 그룹을 최대 20개 붙이고, 생명주기 피드는
  `group_created`, `group_updated`, `group_deleted`, `member_added`, `member_removed`
  변경도 알립니다(`group_id` 포함. 그룹 자체의 변경은 `user_id: null`이며 `status`는
  그룹의 상태). 이것이 없으면 두 응답 모두 바뀌지 않습니다.
- `include_workloads: true`이면 생명주기 피드는 Kubernetes 워크로드 주체 변경도
  알립니다. `workload_observed`(인스턴스의 첫 인증), `workload_retired`(ServiceAccount
  삭제 또는 재생성, `cause`와 `replacement` 주체 포함), `workload_legacy_mapped`(이전
  기간에 사용 중단된 Pod 기반 주체가 주체로 관찰됨)입니다. 이 변경은 `user_id: null`,
  `status` `active` 또는 `retired`, 그리고 `principal`(`wk2:`), `subject_ref`(`s_`),
  `spiffe_id`, `cluster`, `namespace`, `service_account`, `service_account_uid`,
  `service`와 해당하면 `cause`, `replacement`, `legacy_subject_ref`를 담은 `workload`
  객체를 가집니다. 이것이 없으면 응답은 바뀌지 않습니다. 워크로드 주체는 사용자
  스냅숏에 없습니다. `410 cursor_expired` 뒤에 소비자는 `POST
  /v1/subjects/workloads/snapshot`(`cursor`, `limit` 1~200, 기본값 200)을 읽습니다.
  기록된 모든 주체를 등록 순서대로, 살아 있는 것과 retired를 함께 `principal`,
  `subject_ref`, `spiffe_id`, `service`, `cluster`, `namespace`, `service_account`,
  `service_account_uid`, `status`, `first_seen_at`, `last_seen_at`, `retired_at`,
  `cause`, `replacement`, 최대 64개 `legacy_subject_refs`와 함께 돌려줍니다. 끝까지
  `next_cursor`(`w1.<position>`)가 있고 첫 페이지의 `watermark`는 그 전에 잡은 피드
  커서이며 피드(`include_workloads`)는 거기서 이어집니다. 등록부(스키마 16)는 이벤트와
  같은 트랜잭션에 기록되고 이벤트 보존 기간에 정리되지 않으며 retired는 되돌릴 수
  없습니다. 소비자는 retired 주체의 binding을 고아로 처리합니다(한강 ADR 0021).
- 서비스 주체의 생명주기는 이 피드가 아니라 프로필 게시(프로필 리비전)를 따릅니다.
- 검색 커서는 다른 콘솔 목록 커서처럼 프로세스에 묶여 있습니다. 생명주기와 스냅숏
  커서는 지속됩니다.
- 관리자가 볼 수 없는 주체라는 개념은 Hopae의 인가 모델에 없습니다. 부여를 가진
  사람은 모든 주체를 해석할 수 있습니다.

## 예제, 검증, 관련 페이지

```sh
curl -sS https://hopae-admin.example.test/v1/subjects/resolve \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -b '__Host-hopae=<redacted>' \
  -d '{"ids":["u_01HZY5W0000000000000000000","s_3c5e…"]}'
```

시나리오 [307](../../scenarios/307-subject-resolution-and-search.md)과
[308](../../scenarios/308-subject-lifecycle-feed.md)이 동작을 명세합니다. 관련:
[관리](ADMIN.md), [인증 설명](AUTHENTICATION_EXPLAIN.md),
[Human 신원 저장소 · 영문](../HUMAN_IDENTITY_OWNER.md), [위협 모델](THREAT_MODEL.md)
(TM-60).
