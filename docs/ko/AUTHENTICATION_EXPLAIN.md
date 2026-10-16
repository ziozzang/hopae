# 인증 설명 API

<!-- translation-status: source=../AUTHENTICATION_EXPLAIN.md source-rev=3 status=current -->

[문서 목차](README.md) · [English](../AUTHENTICATION_EXPLAIN.md)

`POST /v1/explain/authentication`은 대상 URL과 주체에 대해 Hopae의 인증 검사가 무엇을
답할지와 그 이유를 알려 줍니다. 어떤 애플리케이션 정책이나 서비스 인증 프로필이
적용되는지, 어떤 제공자와 2단계 인증 수단을 쓸 수 있는지, 현재·요구·달성 가능 보증
수준, 어느 단계 상향 규칙이 결정하는지, 신선도 한도를, 안정적인 사유 코드와 영어·한국어
메시지가 붙은 검사 순서 기록으로 돌려줍니다. Hangang ADR 0019의 설명·모의 흐름과
Hangang ADR 0020 콘솔에서 Hopae가 맡는 부분입니다(그 문서에서는
`/v1/admin/explain/authentication`이라 부르며, Hopae 관리 리스너에서의 경로는
`/v1/explain/authentication`입니다). 나머지 [관리 API](ADMIN.md)와 나란히 HTTP로만
제공합니다.

## 전제 조건과 설정

- 관리 콘솔이 켜져 있어야 하며, 부여된 역할(`viewer` 또는 `admin`)이나 Hangang 위임
  콘솔 행위자가 호출할 수 있습니다. 설정 키는 없습니다.
- 요청은 콘솔의 JSON API 규칙(`content-type: application/json`,
  `x-hopae-admin-request: 1`, 있을 경우 같은 출처의 `Origin`과 `sec-fetch-site`)을
  따릅니다. [주체 디렉터리](SUBJECT_DIRECTORY.md)를 참고하십시오.

## 동작

### 요청

```json
{
  "url": "https://app.example.test/admin/reports",
  "navigation": "document",
  "session_id": "s_01J…",
  "subject": null,
  "client_ip": "192.0.2.10",
  "user_agent": null,
  "at": null,
  "hypothetical": {"aal": 2, "factors": ["totp"], "auth_age_seconds": 0, "provider_id": "mock", "auth_time_source": "hopae_completion"},
  "privacy_profile": "standard"
}
```

| 필드 | 의미 |
| --- | --- |
| `url` | 게이트웨이가 알릴 원래 URL(필수, 최대 2,048바이트) |
| `navigation` | `document`(기본값) 또는 `other`(fetch나 API 호출) |
| `session_id` | 이 살아 있는 세션을, URL 호스트의 핸들이 평가되는 방식 그대로 평가합니다 |
| `subject` | 세션 대신 사용자 ID, `human1:` 주체, `s_` 서비스 주체([주체 디렉터리](SUBJECT_DIRECTORY.md)와 같은 방식으로 해석), 또는 SPIFFE ID(`spiffe://<td>/ns/<ns>/sa/<sa>`)나 `system:serviceaccount:<ns>:<sa>`로 지정한 Kubernetes 워크로드 |
| `client_ip`, `user_agent` | 요청 클라이언트. `client_ip`가 없으면 세션 바인딩과 프로필 네트워크는 평가하지 않았다고 알립니다 |
| `at` | 평가 시각(유닉스 초), 지금부터 최대 30일(기본값은 지금) |
| `hypothetical` | 로그인이 만들 세션: `aal`(1 또는 2, 기본값 1), `factors`(`totp`, `webauthn`, `external` 같은 인증 수단 종류), `auth_age_seconds`, `provider_id`(기본값은 주체의 첫 연결 제공자, 없으면 첫 활성 제공자), `auth_time_source`(기본값 `hopae_completion`, `provider_claim`) |
| `privacy_profile` | 주체 표시 정보에 쓸 `standard` 또는 `strict`. `admin.directory_privacy`가 더 엄격하면 그 값으로 올라감 |

`session_id`와 `subject`는 함께 쓸 수 없으며, 둘 다 없으면 익명 요청입니다. 형식이
잘못된 요청은 `400 invalid_request`입니다.

### 평가

평가는 현재 설정 스냅숏과 서비스 프로필 게시본 위에서, 실제 경로가 호출하는 함수를
실제 순서대로 호출합니다.

1. 게이트웨이 어댑터의 정규 경로(`path_not_canonical`)
2. 전송 방식과 반환 대상 검증, 애플리케이션(`insecure_transport`, `unknown_app`,
   `app_disabled`, `port_not_allowed`, `contract_violation`)
3. 예약된 `/_hopae` 이름공간(`reserved_path`. 진입점은 `not_applicable`)
4. 호스트와 포트를 처리하는 서비스 인증 프로필: 게시 진행 중(`authority_unavailable`),
   실제 경로와 같은 만료 규칙·네트워크 판정·적격성 스크립트를 쓰는 서비스 주체의 API 키
   경로(`service_principal_unknown`, `credential_expired`, `network_denied`,
   `eligibility_denied`, `eligibility_unavailable`), 원격 커넥터(`remote_verifier`,
   `indeterminate`), AAL 0인 서비스·워크로드 주체가 만족할 수 없는 단계 상향
   규칙(`machine_step_up`), 세션 대체가 없는 프로필의 브라우저 세션
   거부(`service_credential_required`), 프로필이 없는 호스트의 서비스
   주체(`service_profile_absent`). Kubernetes 워크로드 주체이면 워크로드 커넥터의
   판정을 실제 순서대로 평가합니다. 주체 형식과 신뢰 도메인(`workload_subject_invalid`),
   네트워크(`network_denied`), namespace와 ServiceAccount 허용 목록
   (`workload_namespace_not_allowed`, `workload_service_account_not_allowed`), 레거시
   기간(`workload_legacy_window_expired`), 키 최신성(`workload_keys_unavailable`),
   폐기 인덱스(`workload_revocation_stale`, `workload_service_account_absent`, 감시가
   없으면 `workload_revocation_not_evaluated`)입니다. 토큰 검사 자체는 실제 토큰이
   필요하며(`workload_token_not_simulated`) 추적은 SPIFFE ID와, 폐기 인덱스가
   ServiceAccount UID를 알면 `wk2:` 주체와 전송 주체를 보고합니다
5. 세션이면: 종료 여부, 호스트에서의 살아 있는 핸들(`handle_absent`), 수명 상태
   기계(`idle`, `absolute`, `clock_skew`), 바인딩 정책(`binding_ip`, `binding_ua`,
   또는 `binding_not_evaluated`), 사용자 상태와 권한 버전(`user_disabled`,
   `authz_change`)
6. 단계 상향 규칙(`step_up_required`. 2단계 인증 수단이 설정되지 않은 문서 요청은
   `step_up_unavailable`로 거부하고, `max_age`가 있는 AAL 1 규칙은 다시 로그인을
   요구합니다: `reauth_required`)과 콘솔 신선도 한도(`reauth_required`)

아무것도 쓰지 않습니다. 세션, 핸들, 로그인 트랜잭션, 핸드오프 코드, `last_seen_at`
갱신을 만들지 않고, 만료된 것으로 보이는 세션도 종료하지 않으며, 서비스 런타임의 관측
시각 하한도 올리지 않습니다. 유일한 기록은 감사 이벤트 `admin.read`입니다.

요청이 로그인으로 보내질 경우(`login`), `after_login`은 로그인이 줄 세션에 대해 같은
단계 상향과 신선도 검사를 평가합니다. 포털이 세션을 넘겨줄 때(`handle_absent`)는 살아
있는 그 세션 자체(`basis: "handoff"`), 그 밖에는 `hypothetical`로 모양을 정한 가상의
새 로그인(`basis: "sign_in"`)입니다. 비활성화된 사용자의 로그인은 거부되고
(`user_disabled`), 알 수 없거나 삭제된 주체는 `indeterminate`입니다
(`subject_unknown`, `subject_deleted`).

### 응답

| 필드 | 의미 |
| --- | --- |
| `outcome` | `allow`, `login`, `step_up`, `reauth`, `deny`, `unavailable`, `indeterminate`, `not_applicable` |
| `status_code` | 게이트웨이 응답의 상태(`200`, `302`, `401`, `403`, `503`). 정해지지 않으면 `null` |
| `reason` | `code`(`hopae.<reason>`), `message_key`(`hopae.explain.<reason>`), `message` |
| `application` | 애플리케이션 정책: 수명, 바인딩, `on_authz_change`, `max_auth_age_seconds`, `step_up_rules`, `config_generation` |
| `service_profile` | 서비스 프로필: `service_id`, `realm`, `connectors`, `session_fallback`, `networks_restricted`, `client_ip_permitted`, `eligibility_script`, `revision` |
| `subject` | `input`(`session`, `subject`, `anonymous`)과 해석된 `item` |
| `session` | 평가한 세션: 제공자, `aal`, `handle_aal`, 인증 수단, `auth_time`과 그 출처 |
| `providers` | 선택 화면 순서의 설정된 제공자. `enabled`, `reauth` 능력, 주체에 대한 `linked` 포함 |
| `assurance` | `current_aal`, `required_aal`, `achievable_aal`, 설정된 2단계 인증 수단(`totp_configured`, `totp_enrolled`, `external`) |
| `step_up` | `matched_rules`, `deciding_rule`(색인), `required_aal`, `verdict` |
| `freshness` | `max_auth_age_seconds`, `auth_age_seconds`, `auth_time_source`, `provider_capability`, `fresh` |
| `after_login` | 위에서 설명한 로그인 후 평가. 자체 `trace` 포함 |
| `trace` | 수행한 모든 검사: `check`, `result`(`pass`, `fail`, `skip`, `info`), `reason`, `detail` |
| `evaluated_at`, `config_generation`, `service_profile_revision`, `simulated` | 평가 시각과 리비전. `simulated`는 항상 `true` |

`message`는 요청의 `accept-language`(영어 또는 한국어, 기본값 영어)를 따르며, 자체
카탈로그를 가진 콘솔은 `message_key`를 씁니다. 카탈로그는 다음과 같습니다.

| 코드 | 한국어 메시지 |
| --- | --- |
| `allowed` | 요청이 허용됩니다. |
| `unknown_app` | 이 호스트에 등록된 애플리케이션이 없습니다. |
| `app_disabled` | 이 호스트의 애플리케이션이 비활성화되어 있습니다. |
| `port_not_allowed` | 포트가 애플리케이션의 포트 목록에 없습니다. |
| `insecure_transport` | 보안 쿠키를 쓰는 설정에서는 HTTP 요청을 거부합니다. |
| `contract_violation` | 대상 URL이 유효한 반환 대상이 아닙니다. |
| `path_not_canonical` | 경로가 정규형이 아니어서 게이트웨이가 거부합니다. |
| `reserved_path` | 경로가 예약된 /_hopae 이름공간에 있습니다. |
| `entry_point` | 경로가 Hopae 진입점이며 접근 결정 대상이 아닙니다. |
| `login_required` | 세션이 없어 요청을 로그인으로 보냅니다. |
| `handle_absent` | 세션에 이 호스트용 핸들이 없어 브라우저를 포털로 보내며, 살아 있는 세션은 다시 로그인하지 않고 넘겨받습니다. |
| `unknown_handle` | 세션이 존재하지 않습니다. |
| `session_terminated` | 세션이 종료되었습니다. |
| `idle` | 유휴 시간이 만료되었습니다. |
| `absolute` | 절대 수명이 만료되었습니다. |
| `clock_skew` | 저장된 시각이 허용 범위를 넘어 미래에 있어 요청이 일시 불가로 응답됩니다. |
| `binding_ip` | 클라이언트 주소가 세션의 바인딩과 일치하지 않습니다. |
| `binding_ua` | 사용자 에이전트가 세션의 바인딩과 일치하지 않습니다. |
| `binding_not_evaluated` | 클라이언트 주소가 주어지지 않아 바인딩 정책을 평가하지 않았습니다. |
| `user_disabled` | 사용자가 비활성화되어 있습니다. |
| `authz_change` | 로그인 이후 사용자의 권한 정보가 바뀌었고 이 애플리케이션은 그런 세션을 종료합니다. |
| `step_up_required` | 단계 상향 규칙이 더 높은 보증 수준이나 더 최근의 2단계 인증을 요구합니다. |
| `step_up_unavailable` | 단계 상향이 필요하지만 2단계 인증이 설정되어 있지 않아 요청을 거부합니다. |
| `reauth_required` | 이 경로에 비해 로그인이 오래되어 다시 로그인해야 합니다. |
| `subject_unknown` | Hopae가 알지 못하는 주체이며, 로그인하면 계정이 만들어지거나 연결됩니다. |
| `subject_deleted` | 삭제된 주체이며, 새로 로그인하면 다른 주체가 만들어집니다. |
| `service_credential_required` | 이 호스트와 포트는 서비스 프로필이 처리하며 브라우저 세션으로 대체하지 않습니다. |
| `service_profile_absent` | 서비스 자격 증명을 제시했지만 이 호스트와 포트를 처리하는 서비스 프로필이 없습니다. |
| `service_principal_unknown` | 주체가 이 프로필의 API 키 주체가 아닙니다. |
| `credential_expired` | 서비스 자격 증명이 만료되었습니다. |
| `network_denied` | 클라이언트 주소가 프로필의 네트워크 범위 밖에 있습니다. |
| `network_not_evaluated` | 클라이언트 주소가 주어지지 않아 프로필의 네트워크 범위를 평가하지 않았습니다. |
| `eligibility_denied` | 프로필의 적격성 스크립트가 이 주체를 거부합니다. |
| `eligibility_unavailable` | 프로필의 적격성 스크립트를 지금 실행할 수 없어 요청이 일시 불가로 응답됩니다. |
| `remote_verifier` | 자격 증명을 요청 시점에 원격 커넥터가 검증하므로 결과를 모의할 수 없습니다. |
| `machine_step_up` | 서비스와 워크로드 주체는 AAL 0이어서 단계 상향 규칙을 만족할 수 없습니다. |
| `authority_unavailable` | 서비스 인증을 다시 게시하는 중이어서 요청이 일시 불가로 응답됩니다. |
| `workload_subject_invalid` | 워크로드가 이 신뢰 도메인의 SPIFFE ID나 system:serviceaccount 이름이 아닙니다. |
| `workload_namespace_not_allowed` | 워크로드의 네임스페이스가 서비스 프로필에서 허용되지 않습니다. |
| `workload_service_account_not_allowed` | ServiceAccount가 프로필의 ServiceAccount 허용 목록에 없습니다. |
| `workload_service_account_absent` | 현재 폐기 인덱스에 ServiceAccount가 없습니다. |
| `workload_keys_unavailable` | 발급자 서명 키를 사용할 수 없거나 허용된 경과 시간을 넘었습니다. |
| `workload_revocation_stale` | 폐기 인덱스가 허용된 지연 범위 안에서 최신 상태가 아닙니다. |
| `workload_legacy_window_expired` | 레거시 Pod 기반 주체 호환 기간이 끝났습니다. |
| `workload_revocation_not_evaluated` | 폐기 감시가 구성되지 않아 삭제된 ServiceAccount는 토큰 만료 시에만 거부됩니다. |
| `workload_token_not_simulated` | 토큰 검사(서명, 대상, 수명, 바인딩 객체)는 실제 토큰이 필요하여 모의 평가하지 않습니다. |

## 관리 API, 콘솔, 관측

오류: `400 invalid_request`, 콘솔 인증과 JSON API 규칙에 따른 `403`,
`retry-after`가 붙은 `429 rate_limited`(행위자마다 순간 30건, 2초에 1건),
`503 store_unavailable`, `503 audit_unavailable`.

모든 응답은 먼저 필수 이벤트 `admin.read`를 씁니다. `attrs.purpose =
explain.authentication`, `attrs.endpoint`, `attrs.query_sha256`, `attrs.status`의 결과,
`attrs.host`, `attrs.port`, `attrs.navigation`, `attrs.app`, 행위자 속성, 그리고
이벤트의 `user_id`와 `session_id` 열에 평가한 사용자와 세션이 들어갑니다. 응답에는
`cache-control: no-store`가 붙습니다.

## 제한과 호환성

- 세션은 URL 호스트에서의 가장 최근 살아 있는 핸들로 평가하며, 설명 API는 핸들 값을
  보지 않습니다. `handle_absent`이면 포털 핸들의 수준이 세션의 수준과 같다고
  가정합니다.
- 원격 커넥터(API 릴레이, Kubernetes TokenReview, 합성 자격 증명)가 검증하는 자격
  증명은 `indeterminate`입니다.
- 실제 경로의 요청별 속도 제한(로그인 트랜잭션, 핸드오프 실패)과 저장소 가용성은
  모의하지 않습니다.
- 시각 이동은 평가 시계만 옮기며, 설정과 상태는 현재 것입니다.

## 예제, 검증, 관련 페이지

```sh
curl -sS https://hopae-admin.example.test/v1/explain/authentication \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -H 'accept-language: ko' -b '__Host-hopae=<redacted>' \
  -d '{"url":"https://app.example.test/admin","subject":"u_01HZY5W0000000000000000000"}'
```

시나리오 [309](../../scenarios/309-authentication-explain.md)는 다루는 모든 세션 상태에
대해 같은 상태에서 설명 결과와 실제 verify 엔드포인트를 비교합니다. 관련:
[주체 디렉터리](SUBJECT_DIRECTORY.md), [게이트웨이 계약](GATEWAY_CONTRACT.md),
[관리](ADMIN.md), [위협 모델](THREAT_MODEL.md)(TM-61).
