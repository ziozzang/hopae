# Kubernetes 워크로드 인증

<!-- translation-status: source=../KUBERNETES_WORKLOAD.md source-rev=7 status=current -->

[문서](README.md) · [English](../KUBERNETES_WORKLOAD.md)

호패는 Kubernetes 워크로드를 projected ServiceAccount 토큰으로 인증합니다.
한강 ADR 0022(P0) 이후 기본 connector는 `kubernetes_workload`입니다. 토큰은
클러스터의 OIDC discovery 문서와 JWKS로 **오프라인** 검증하고, 인증된 주체는
Pod가 아니라 **ServiceAccount**이며, 요청 경로에서 Kubernetes API를 호출하지
않습니다. 캐시되지 않은 요청마다 TokenReview를 호출하고 ServiceAccount와 Pod를
읽는 기존 `kubernetes_tokenreview` connector는 **사용 중단(deprecated)** 대체
경로로 남아 있으며 프로필이 명시하지 않으면 사용되지 않습니다
([아래](#사용-중단된-tokenreview-대체-경로)).

구현: `auth_gateway::workload`(오프라인 connector, 신원, 키 원천, 폐기 감시,
수명주기 신호)와 `auth_gateway::kubernetes`(대체 경로). 오프라인 connector의
실제 클러스터 검증은 아직 남은 관문입니다([제한 사항](#제한-사항과-남은-작업)).

## 워크로드 신원 모델

| 식별자 | 형식 | 범위 | 용도 |
| --- | --- | --- | --- |
| 주체(principal) | `wk2:<64 hex>` = 도메인 `hopae:kubernetes:workload-principal:v2` 뒤에 길이 접두 issuer, cluster ID, namespace, ServiceAccount 이름과 ServiceAccount **UID**를 이은 SHA-256 | 한 ServiceAccount의 한 생성 인스턴스 | 한강 ADR 0021의 `workload` 종류 `PrincipalRef`, 수명주기 피드, 응답 헤더 `x-hopae-principal` |
| SPIFFE ID | `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>` | 신뢰 도메인 안의 ServiceAccount 이름(UID 없음) | 한강 워크로드 mTLS와 공유하는 정규 워크로드 이름, 응답 헤더 `x-hopae-workload-spiffe-id`, explain 주체 |
| 전송 주체(wire subject) | `s_<48 hex>`: 주체에 기존 stable-subject 인코딩(종류 workload, issuer, cluster realm)을 적용한 값 | 주체와 같음 | 전달 사용자 헤더, 품계 `workload_users`, receipt. 한강·품계 파서는 바뀌지 않습니다 |
| 감사 속성 | Pod 이름/UID, 바인딩된 Secret 이름/UID, Node 이름 | 한 자격증명 | 근거와 감사 전용. 주체에 포함되지 않고 전송되지 않습니다 |

- **롤아웃해도 접근이 유지됩니다.** 한 ServiceAccount의 모든 Pod는 모든 복제본과
  롤아웃에서 같은 주체와 전송 주체로 인증됩니다.
- **재생성 정책.** ServiceAccount를 삭제하고 같은 이름으로 다시 만들면 새 UID를
  받으므로 주체와 전송 주체도 새로 생깁니다. 이전 주체에 묶인 권한은 넘어가지
  않습니다. 폐기 감시가 이를 관찰하면 호패는 이전 주체를 retired로 보고합니다
  (`workload.principal_retired`, cause `uid_changed`, `replacement` 주체 포함).
  재생성 뒤에도 유지되어야 하는 의도는 이름으로 표현합니다(World controller가
  해석하는 `AccessBinding` 주체 `ServiceAccount{namespace,name}`, ADR 0022).
  이 방식은 해당 namespace에서 ServiceAccount를 다시 만들 수 있는 사람을 신뢰합니다.
- 주체 종류는 AAL 0의 `workload`입니다. 기계 자격증명은 사람 step-up 규칙을
  만족하지 않습니다.

## 오프라인 검증(`kubernetes_workload`)

한 프로필은 `kubernetes_workload`와 `kubernetes_tokenreview` 중 최대 하나만
가집니다. discovery, 전용 audience, 폐기 감시를 쓰는 예(모든 자료는 참조로 지정):

```json
{
  "service_id": "orders", "host": "orders.example.test", "ports": [443],
  "realm": "example-cluster",
  "kubernetes_workload": {
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "cluster_id": "example-cluster",
    "trust_domain": "cluster.example.test",
    "audience": "world.hangang.dev/example-cluster",
    "namespaces": ["blue"],
    "service_accounts": ["blue/worker"],
    "keys": {
      "source": "discovery",
      "jwks_origins": ["https://10.0.0.1:6443"],
      "ca_pem_env": "HOPAE_KUBERNETES_CA_PEM",
      "token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    },
    "revocation": {
      "mode": "watch",
      "api_origin": "https://kubernetes.default.svc/",
      "token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    },
    "token_prefix": "k8s:"
  }
}
```

| 필드 | 기본값 | 규칙 |
| --- | --- | --- |
| `issuer` | 필수 | HTTPS URL, 최대 256 bytes. 토큰 `iss`와 discovery `issuer`가 바이트 단위로 같아야 합니다 |
| `cluster_id` | 필수 | 프로필 `realm`과 같아야 하며 주체의 일부입니다 |
| `trust_domain` | 필수 | SPIFFE 신뢰 도메인(소문자, 숫자, `.`, `-`, `_`) |
| `audience` | 필수 | 이 서비스가 요구하는 audience. issuer나 API 서버 audience(`api`, `kubernetes`, `https://kubernetes.default.svc[.cluster.local]`)일 수 없습니다. API 서버용 토큰을 여기서 받아서는 안 됩니다 |
| `exclusive_audience` | `true` | 토큰에 다른 audience가 없어야 하므로 호패용 토큰이 다른 서비스에서도 유효하지 않습니다 |
| `namespaces` | 필수 | 서로 다른 namespace 1–128개 |
| `service_accounts` | 전체 | 선택적 `namespace/name` 허용 목록(최대 1,024개, `namespaces` 안) |
| `bound_objects` | `["pod"]` | `pod` 그리고/또는 `secret`: 허용할 바인딩 객체 클레임. `kubernetes.io` 클레임이 없는 토큰(구형 Secret 토큰)과 아무것에도 바인딩되지 않은 projected 토큰은 거절합니다 |
| `keys.source` | 필수 | `discovery`, `jwks_url` 또는 `static` |
| `keys.discovery_url` | `<issuer>/.well-known/openid-configuration` | discovery 전용 |
| `keys.jwks_url` | — | `jwks_url`에 필수. `discovery`와 함께 쓰면 광고된 `jwks_uri`를 고정합니다 |
| `keys.jwks_origins` | issuer와 discovery origin | 광고된 `jwks_uri`가 추가로 쓸 수 있는 origin(최대 8개). Kubernetes는 보통 issuer 호스트가 아니라 API 서버 주소를 광고합니다 |
| `keys.jwks_env` | — | `static`: JWKS 문서 참조(클러스터에 닿을 수 없는 호스트용. 재게시로 회전) |
| `keys.ca_pem_env` | — | 네트워크 원천에 필수. 이 루트만 신뢰합니다 |
| `keys.token_env` / `keys.token_file` | 없음 | discovery/JWKS용 선택적 bearer. 파일은 가져올 때마다 다시 읽습니다(projected 토큰은 회전합니다) |
| `keys.refresh_seconds` | 300 | 30–3,600: 백그라운드 갱신 주기 |
| `keys.max_stale_seconds` | 3,600 | `refresh_seconds`–86,400: 마지막 정상 키 사용 한도. 넘으면 503으로 응답합니다 |
| `keys.kid_miss_min_interval_ms` | 10,000 | 1,000–300,000: 모르는 `kid`에 대한 재조회는 이 간격마다 최대 한 번 |
| `keys.timeout_ms` | 2,000 | 조회당 100–10,000 |
| `clock_skew_seconds` | 30 | 0–300, `exp`·`nbf`·`iat`에 적용 |
| `max_token_lifetime_seconds` | 86,400 | 600–604,800: `exp − iat`가 이를 넘으면 거절 |
| `cache.ttl_ms` / `cache.max_entries` | 10,000 / 10,000 | 0–60,000 ms / 0–262,144. 0이면 양성 캐시를 끕니다 |
| `revocation` | 없음 | 선택적 감시, [아래](#폐기-감시) |
| `subject` | `service_account` | `legacy_pod`는 이전 전용, [아래](#pod-기반-주체에서-이전) |
| `legacy_until_ms`, `legacy_mapping_until_ms` | 없음 | 이전 기간(Unix 밀리초) |
| `token_prefix` | 필수 | `:`로 끝나는 2–32자. `Bearer <prefix><token>`을 이 connector로 보냅니다 |

알 수 없는 필드는 거절하며 비밀 자료는 설정에 들어가지 않습니다(`ca_pem`, 인라인
JWKS나 토큰은 알 수 없는 키로 거절됩니다).

### 검증 순서

1. 자격증명이 프로필 접두사를 가져야 하고(아니면 이 connector에 오지 않으며 다른
   connector의 라우팅은 그대로입니다), 최대 8,192 bytes이며 프로필 네트워크 조건을
   통과해야 합니다.
2. 토큰 SHA-256으로 양성 캐시를 조회합니다(토큰은 저장하지 않습니다). 적중은
   서명 검사만 건너뛰며 범위와 폐기는 다시 검사합니다.
3. 헤더: `alg`는 RS256/RS384/RS512/ES256/ES384(`none`이나 HMAC 불가), `crit` 없음.
   키는 `kid`로 고릅니다. 모르는 `kid`는 `kid_miss_min_interval_ms`마다 최대 한 번
   재조회합니다(single flight). 위조 `kid` 폭주가 API 서버 요청 폭주가 되지 않습니다.
4. 선택한 키로 서명을 검증합니다.
5. 검증된 payload의 클레임: `iss`, `aud`(필수, 기본 배타), `exp`·`iat` 필수와
   선택적 `nbf`(각각 `clock_skew_seconds` 적용), `exp − iat ≤ max_token_lifetime_seconds`,
   `kubernetes.io.namespace`, `serviceaccount{name,uid}`와 설정된 바인딩 객체,
   `sub = system:serviceaccount:<ns>:<sa>`, namespace·ServiceAccount 허용 목록.
   과거의 `warnafter`(연장 만료 토큰)는 집계만 하고 거절하지 않습니다.
6. (설정 시) 폐기 인덱스, 프로필 Lua 적격성 규칙, 근거 생성 순서입니다. 근거는
   종류 `workload`, AAL 0, 서비스 범위이며 lease는 최대 1초이고 `exp`+허용 오차를
   넘지 않습니다.

거절은 `401`(자격증명) 또는 `503`(키 사용 불가, 폐기 인덱스 지연, 레거시 기간
종료)입니다. 호출자는 어떤 규칙이 거절했는지 알 수 없습니다.

### 키: 회전, 장애, 고정

discovery는 설정한 issuer를 정확히 반환해야 하고, 광고된 `jwks_uri`는 허용된
origin의 HTTPS여야 합니다(또는 고정한 `jwks_url`과 같아야 합니다). 모든 조회는
`ca_pem_env`만 신뢰하고 프록시를 쓰지 않으며 리다이렉트를 따르지 않습니다. 본문은
64 KiB, 키 집합은 비대칭 서명 키 64개로 제한합니다(대칭 키와 암호화 키는 버립니다).
백그라운드 작업이 `refresh_seconds`마다 집합을 갱신합니다. 실패하면 1초부터 32초까지
두 배로 물러나며(최대 갱신 주기) `max_stale_seconds`보다 젊은 동안 마지막 정상 집합을
계속 사용합니다. 클러스터가 서명 키를 회전하면 새 `kid`는 다음 갱신이나 그 `kid`를
쓰는 첫 토큰에서 즉시 반영됩니다. JWKS에서 빠진 키는 다음 갱신 뒤 검증에 쓰이지 않습니다.

### 요청 경로

양성 캐시, 키 캐시, 메모리 폐기 인덱스로 인증은 **네트워크 요청을 하지 않습니다**.
TokenReview도, ServiceAccount나 Pod GET도 없습니다. 시나리오 900-1은 반복 인증 동안
fixture API 서버의 요청 수를 세어 이를 확인합니다. 네트워크 트래픽은 백그라운드 키
갱신, 속도 제한된 `kid` 재조회, 감시 스트림뿐입니다.

## 폐기 감시

오프라인 검증은 토큰이 바인딩된 객체가 삭제되었는지 알 수 없습니다.
`revocation.mode: "watch"`이면 connector는 허용된 각 namespace의 ServiceAccount
(그리고 `resources`에 `pods`가 있으면 Pod)의 metadata 전용 인덱스를 LIST와 WATCH로
유지합니다(`PartialObjectMetadata`, bookmark, `resourceVersion` 재개, `410 Gone`이면
재목록). 요청 경로에서는 이 인덱스만 읽습니다.

| 인덱스 상태 | 응답 |
| --- | --- |
| ServiceAccount가 없거나 다른 UID(재생성) | `401` |
| Pod가 없거나 다른 UID이거나 종료 중(`deletionTimestamp` 설정) | `401` |
| 아직 목록을 받지 못했거나 `max_staleness_seconds`보다 오래되었거나 `max_objects` 초과 | `503`(실패 시 닫힘) |

최신성은 완료된 LIST, 이벤트, bookmark, (재)수립된 watch로 확인합니다. 각 watch는
서버에 지연 한도의 1/3(1–290초) 뒤 종료를 요청하고 5초 뒤 클라이언트 기한을 두므로
조용하거나 멈춘 스트림도 한도 안에서 갱신됩니다. LIST 페이지는 500개·최대 4 MiB,
watch 줄은 최대 64 KiB입니다. 양성 캐시 적중도 같은 검사를 받으며, 감시가 관찰한
삭제는 캐시 항목도 제거합니다. `max_staleness_seconds`는 5–600(기본 60),
`max_objects`는 1–1,000,000(기본 200,000. 초과하면 더 큰 한도로 프로필을 재게시할
때까지 계속 실패 시 닫힘)입니다. 감시 자격증명(`token_env` 또는 다시 읽는
`token_file`)에는 다음 권한만 필요합니다.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: hopae-workload-revocation, namespace: blue}
rules:
- apiGroups: [""]
  resources: ["serviceaccounts", "pods"]
  verbs: ["list", "watch"]
```

감시가 없으면 ServiceAccount나 Pod가 삭제된 뒤에도 토큰은 `exp`까지 유효합니다.
토큰 수명을 짧게 유지하십시오(`expirationSeconds`, `max_token_lifetime_seconds`).
ADR 0022의 controller tombstone(서명된 폐기 delta)이 이 authority별 감시를 대체할
계획입니다.

## Pod 기반 주체에서 이전

ADR 0022 이전에 `kubernetes_tokenreview`는 namespace, ServiceAccount 이름/UID와
**Pod 이름/UID**를 해시한 주체(`w_…`, 전송 주체 `s_…`)를 게시했기 때문에 권한이
Pod와 함께 사라졌습니다. 새 `kubernetes_workload` 프로필은 기본으로 ServiceAccount
주체를 게시합니다. 기존 `kubernetes_tokenreview` 프로필은 `subject`를 **명시**해야
합니다. 없으면 설정 로드, preflight 검사, 프로필 게시가
`kubernetes_tokenreview.subject is required since Hangang ADR 0022 …` 메시지와 이 절을
가리키는 안내와 함께 실패하므로, 업그레이드가 게시 주체를 조용히 바꾸는 일은
없습니다. 운영자 이전 절차:

0. **현재 동작 선언.** 업그레이드 전(또는 함께) 모든 기존 TokenReview 프로필에
   `"subject": "legacy_pod"`, `"legacy_until_ms"`(이전 기간 끝), `"legacy_mapping_until_ms"`를
   추가합니다. 호출자는 Pod 기반 주체를 유지하며 그 밖에는 바뀌지 않습니다.
1. **대응 관계 관찰.** `legacy_mapping_until_ms`를 설정합니다(예: 2주 뒤). 인증되는
   각 Pod 기반 레거시 주체는 프로세스마다 한 번 `workload.legacy_subject_mapped`로
   `legacy_subject_ref`와 새 `principal`/`subject_ref`를 함께 보고합니다.
2. **품계에서 조정.** `include_workloads: true`로 수명주기 피드를 소비합니다.
   ADR 0021 변환기는 관리자가 namespace/ServiceAccount를 확인한 뒤에만 Pod 기반
   권한을 ServiceAccount 주체로 옮기고, 그렇지 않으면 사용 중단된 레거시 항목으로 둡니다.
3. **권한 재부여.** ServiceAccount 주체에 binding을 만듭니다(품계 v2 변환기는
   `legacy_subject_mapped` 이벤트를 소비합니다). 품계가 아직 Pod 기반 권한을 평가하는
   동안 `legacy_pod`는 레거시 주체를 계속 게시합니다(Pod 바인딩 토큰만).
   `legacy_until_ms`가 되면 connector는 `503`으로 거절하며 조용히 주체를 바꾸지 않습니다.
4. **전환.** `"subject": "service_account"`로 바꾸고 `legacy_until_ms`를 제거하며 대응
   관찰 기간은 유지하거나 제거한 뒤 Pod 기반 권한을 정리합니다.

## SPIFFE 정렬과 한강 워크로드 mTLS

SPIFFE ID는 한강의 전용 워크로드 mTLS listener(`allowed_uri_sans`)와 공유하는
워크로드 이름입니다. 호패는 그 연결을 종료하지 않고 기존 HTTP/HOP1 경로에서
클라이언트 인증서를 받지 않으므로 X.509-SVID 호출자는 한강이 인증합니다. 하나의
신원 모델과 두 자격증명 형식을 위한 계약:

- 한강은 X.509-SVID(정규 SPIFFE URI SAN 정확히 하나, 설정된 CA)를 검증하고
  `spiffe://<td>/ns/<ns>/sa/<sa>`를 호패가 `x-hopae-workload-spiffe-id`로 보고하는
  것과 같은 워크로드 이름으로 매핑합니다. SPIFFE ID나 `ServiceAccount{namespace,name}`로
  ServiceAccount를 지정하는 route 정책과 품계 binding은 두 자격증명 형식 모두에 맞습니다.
- SVID에는 UID가 없으므로 그것만으로 UID에 고정된 `wk2:` 주체를 만들 수 없습니다.
  World controller가 현재 ServiceAccount UID를 배포하기 전까지(ADR 0022 결정 3)
  `wk2:` 주체에 고정된 binding은 토큰 호출자에게만, 이름 기반 binding은 둘 다에
  적용됩니다.
- 신뢰 도메인은 호패(`trust_domain`)와 한강(`allowed_uri_sans`)에서 같게 설정해야 합니다.

## 수명주기 이벤트와 주체 수명주기 피드

| 이벤트 | 종류 | 시점 | 속성 |
| --- | --- | --- | --- |
| `workload.principal_observed` | 필수 | 이 프로세스가 주체를 처음 인증할 때(메모리 제한: 잊힌 주체는 다시 보고) | `service`, `principal`, `subject_ref`, `spiffe_id`, `cluster`, `namespace`, `service_account`, `service_account_uid`, `status: active` |
| `workload.principal_retired` | 필수 | 폐기 감시가 ServiceAccount 삭제(`cause: deleted`)나 재생성(`cause: uid_changed`, `replacement`)을 관찰할 때 | 위와 같음, `cause`, `replacement`, `status: retired` |
| `workload.legacy_subject_mapped` | 필수 | `legacy_mapping_until_ms` 동안 Pod 기반 레거시 주체가 주체로 인증될 때 | 위와 같음, `legacy_subject_ref` |
| `workload.keys_rotated` | 진단 | issuer 키 집합이 바뀔 때 | `service`, `keys_added`, `keys_removed` |
| `workload.revocation_stale` | 진단 | 폐기 인덱스가 지연되거나(`stale: true`, outcome failure) 다시 최신이 될 때 | `service`, `stale` |

신호는 제한된 큐(4,096)를 거쳐 프로세스당 하나의 기록기로 갑니다. 큐가 가득 차면
버리고 집계하며(`hopae_workload_signals_total{result="dropped"}`) 소비자의 주기적
조정이 따라잡습니다. `POST /v1/subjects/lifecycle`에 `include_workloads: true`를
주면 이를 `user_id: null`과 `workload` 객체를 가진 `workload_observed`,
`workload_retired`, `workload_legacy_mapped` 변경으로 보고합니다. 옵션이 없으면
피드는 바뀌지 않습니다([주체 디렉터리](SUBJECT_DIRECTORY.md)). 어떤 이벤트도 토큰,
Pod 이름이나 Pod UID를 담지 않습니다.

## 상태, 지표, explain

`GET /v1/status`는 프로필마다 `kubernetes-workload` connector를 `circuit`(키가
최신이고 폐기 인덱스가 현재이면 `closed`)과 `workload` 객체로 나열합니다. issuer,
cluster, 신뢰 도메인, audience, 주체 모드, 키 원천 상태(`source`, `keys`, `age_ms`,
`fresh`, `consecutive_failures`, `last_error`), 폐기 상태(`ready`, `staleness_ms`,
`max_staleness_ms`, `objects`, `overflow`), 캐시 항목 수를 포함합니다. 키 자료,
자격증명, 참조 이름은 보이지 않습니다.

| 카운터 또는 게이지 | 레이블 |
| --- | --- |
| `hopae_workload_authentications_total` | `service`, `verification`(`offline_jwks`, `tokenreview`), `result`(`authenticated`, `denied`, `warning`), `reason` |
| `hopae_workload_cache_total`, `hopae_workload_cache_entries` | `service`, `result`(`hit`, `miss`) |
| `hopae_workload_jwks_fetch_total`, `hopae_workload_jwks_keys` | `service`, `result`(`ok`, `rotated`, `kid_miss_rate_limited` 또는 실패 사유) |
| `hopae_workload_revocation_events_total`, `hopae_workload_revocation_staleness_ms` | `service`, `resource`, `event` |
| `hopae_workload_signals_total` | `kind`, `result`(`queued`, `dropped`, `recorded`, `failed`) |

[인증 explain API](AUTHENTICATION_EXPLAIN.md)는 워크로드 주체를 프로필 신뢰 도메인의
SPIFFE ID나 `system:serviceaccount:<ns>:<sa>`로 받고, 실제 경로 순서대로 프로필,
네트워크 조건, namespace·ServiceAccount 허용 목록, 키 최신성, 폐기 인덱스, 이전
기간을 평가합니다. 토큰이 필요한 검사는 `workload_token_not_simulated`로 보고합니다.

## 배포 참고

- 클러스터 안에서 discovery endpoint는 보통 bearer가 필요합니다.
  `system:service-account-issuer-discovery`를 호패 ServiceAccount에 바인딩하고 그
  projected 토큰을 `keys.token_file`로 쓰거나, issuer discovery를 익명으로 공개합니다.
  `keys.ca_pem_env`에는 클러스터 CA를 둡니다.
- 워크로드는 전용 토큰을 요청합니다.

```yaml
volumes:
- name: hopae-token
  projected:
    sources:
    - serviceAccountToken:
        audience: world.hangang.dev/example-cluster
        expirationSeconds: 600
        path: token
```

- 클러스터 밖(운영 호스트)에서는 `kubectl get --raw /openid/v1/jwks`로 얻은 JWKS를
  `keys.source: "static"`으로 쓰고 키 회전 시 재게시하거나, API 서버 주소로 닿는
  `jwks_url`을 씁니다.

## 사용 중단된 TokenReview 대체 경로

**사용 중단**(한강 ADR 0022): issuer 키에 닿을 수 없는 경우가 아니면
`kubernetes_workload`를 쓰십시오. 네이티브 라이브러리는 `auth_gateway::kubernetes::Connector`입니다.
Pod에 바인딩된 ServiceAccount JWT를 고정된 신뢰 Kubernetes TokenReview API로 검증합니다.
참조형 루트/프로필 설정·HTTP/HOP1 dispatch·콘솔 요약은 연결했습니다. 프로필을
컴파일하면 사용 중단 경고를 기록합니다. 소유 실제 API 검증은 아래에 기록했습니다.

소유자는 HTTPS API origin, 기대 HTTPS issuer, cluster 식별자, workload audience,
1–1000ms 기한, CA 묶음과 별도 reviewer 자격증명을 제공합니다. Config에는 비밀값이
없습니다. 지정 CA만 신뢰하고 리다이렉트·환경 프록시는 사용하지 않습니다. endpoint는
/apis/authentication.k8s.io/v1/tokenreviews로 고정합니다. 클라이언트 JWT는 spec.token에,
reviewer는 Authorization 헤더에 전달합니다. reviewer는 TokenReview create와 namespace 범위 Pod/ServiceAccount metadata get의
최소 권한으로 구성하고 workload Secret이나 임의 Role/Binding 쓰기를 부여하지 않습니다.
TokenReview API 인가는 앱 정책과 별개입니다.

JWT 파싱은 거절을 위한 사전 검사이며 인증이 아닙니다. 허용 알고리즘 식별자·issuer/
audience·만료·선택적 nbf·ServiceAccount namespace/name/UID·Pod name/UID를 요구합니다.
구형 무기한/unbound 및 Pod 외 바인딩은 미지원입니다. 신뢰 API가 원래 토큰을
인증하고 사용자명·ServiceAccount UID·audience·user.extra의 정확한 Pod name/UID를
반환해야 근거를 만듭니다. 실제 서명과 객체 존재는 API가 검증합니다. Node 정보는
검증된 신원으로 주장하지 않습니다. 선택한 클러스터 버전·authenticator의 Pod extra
지원은 실제 환경에서 확인해야 합니다.

신원 종류는 Workload이며 사람 MFA 등급을 만들지 않습니다. 주체는
[신원 모델](#워크로드-신원-모델)의 ServiceAccount 주체(issuer, cluster, namespace,
ServiceAccount 이름과 UID)이고 Pod 이름/UID는 감사 속성입니다. 선택적
`trust_domain`을 주면 SPIFFE ID를 추가합니다. `subject`는 필수입니다
(`service_account`, 또는 필수 `legacy_until_ms`와 함께 `legacy_pod`,
[이전](#pod-기반-주체에서-이전)). 근거는 서비스 범위와 토큰 만료/인증 시작 후 1초 중
이른 기한에 제한합니다. 토큰·Pod labels는 근거에 포함하지 않으며 신뢰 시각은
네이티브 호출자가 제공합니다. `cache_ttl_ms`가 없으면 결과 캐시가 없어 매 호출
TokenReview를 요청합니다. `cache_ttl_ms`(최대 10,000)는 토큰 digest를 키로 양성
결과를 그 시간 동안 보관해 API 부하를 제한하는 대신 그만큼 폐기가 늦어집니다.
풀 연결·최대 64개 요청을 사용하고 원천 오류 3건이면 취소 안전한 회로를 30초간 엽니다. 사용자 거절은
원천 실패가 아니며 reviewer 401/403·TLS/응답 형식/크기 오류·모순된 양성 증명은
원천 실패입니다. 인증 거절의 error 진단도 사용자 거절로 처리해 회로를 열지 않습니다.

네트워크·body 전체는 지정 기한과 응답 64 KiB로 제한합니다. 응답 bytes는 zeroize하며
API가 돌려주는 spec.token은 타입 파싱에서 무시합니다. 인증/응답 자료를 로깅하지
않습니다. reviewer·CA 변경은 소유자가 connector를 재컴파일하고 이전 것을 회수해야
합니다. 연결 설정·실제 CA/reviewer 값·접두사·서비스/realm이 모두 같을 때만
기존 원천 회로를 재사용합니다. 파일 자동 회전은 남았고, 프로필 게시 snapshot
fence로 회수 중인 HTTP/HOP1 결과는 거절합니다.

Kubernetes는 deletion pending 객체를 문서의 삭제 유예 동안 인정할 수 있습니다.
호패 근거 1초 제한이 API 원천의 이 창을 없애지는 않습니다. 아래 현재 객체 검사로
조기 바인딩 객체 회수를 보완합니다(양성 캐시 적중 시에는 생략).

```sh
cargo test --locked --lib auth_gateway::kubernetes
cargo build --locked --example qualify_kubernetes_tokenreview
python3 tools/kubernetes_tokenreview_smoke.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview
```

소유 HTTPS mock은 reviewer/사용자 토큰 분리·신원 불일치·클러스터 격리·응답 제한·
CA/프록시/리다이렉트 거절·회로 차단을 검증합니다. 가상 토큰을 사용하므로 실제 API
서버의 서명/삭제 동작을 검증한 것이 아닙니다. 공식 근거 링크는 대응 영문 문서에 있습니다.

## 네이티브 프로필과 HTTP/HOP1

kubernetes_tokenreview 프로필을 자체 키·API relay와 함께 설정할 수 있습니다.
CA PEM·reviewer는 별도 네이티브 환경 참조이며 owner 문서/UI에 값을 넣지 않습니다.
참조형 JSON 예제는 다음과 같습니다.

```json
{
  "kubernetes_tokenreview": {
    "connection": {
      "api_origin": "https://kubernetes.example.test/",
      "issuer": "https://issuer.example.test",
      "cluster_id": "example-cluster",
      "audience": "orders-workload",
      "namespaces": ["blue"],
      "timeout_ms": 500
    },
    "ca_pem_env": "HOPAE_KUBERNETES_CA_PEM",
    "reviewer_token_env": "HOPAE_KUBERNETES_REVIEWER",
    "token_prefix": "k8s:",
    "subject": "service_account",
    "trust_domain": "cluster.example.test",
    "cache_ttl_ms": 0
  }
}
```

profile realm은 cluster_id와
같아야 합니다. 필수 2–32자 접두사는 :로 끝나며 표시된 토큰만 TokenReview로 보내고
API 요청 전에 접두사를 제거합니다. 자체 키가 해당 접두사를 차지할 수 없고 relay를
혼합하면 다른 명시적 접두사가 필요합니다. 미표시·잘못된·실패한 Kubernetes 자격은
다른 원천으로 전달하지 않습니다. 네트워크 조건을 원격 호출 전에 검사하고 선택적
제한 Lua 조건을 이후 적용합니다. 접두사를 포함한 전체 자격은 최대 4096 bytes,
바인딩 신원 식별자는 최대 128자입니다.

HTTP/HOP1은 같은 런타임·게시 fence·현재 앱 step-up 검사를 사용합니다. workload,
서비스·정규 native subject·AAL 0을 반환하고, 두 워크로드 connector 모두
`x-hopae-principal`과 (신뢰 도메인이 있으면) `x-hopae-workload-spiffe-id`를 함께
반환합니다. 기계 근거로 사람 step-up을 만족하지 않습니다. 한강의 신뢰 네이티브 호패→품계 파서는 workload AAL 0만 허용하고 사람
등급·비정규 subject·중복 metadata·network 단독 신원을 거절합니다. 콘솔 0.1.7은
TokenReview·issuer·cluster·audience·허용 namespace·접두사를 기존 owner 편집/게시 경로와 함께 표시합니다.
HTML처럼 보이는 값도 text이며 viewer는 읽기 전용입니다.

소유 HTTPS/HTTP/HOP1 시나리오는 자체/워크로드 혼합, 자격 라우팅 격리, 원천/사용자
오류 구분, 사람 step-up 거절, 원격 TokenReview 대기 중 프로필 회수를 검증합니다.
TLS 원천은 mock입니다. 실제 클러스터 서명/삭제·분산 fence·장기 스트림 신원 회수·
품계 매핑 권한·워크로드 receipt·전체 성능 검증이 남았습니다. 컴파일된 기능을 배포해도
내부 운영 프로필은 native-only로 유지할 수 있습니다.

## 현재 바인딩 객체 검사와 실제 API 검증

connection.namespaces는 필수이며 서로 다른 DNS-label namespace 1–128개를 지정합니다.
원격 호출 전에 검사하고 다른 namespace는 사용자 거절로 처리합니다. 실제 음성
TokenReview는 authenticated/audiences를 생략하고 user:{}를 반환할 수 있으며 error 진단이
있어도 원천 장애가 아닙니다. 비어 있거나 모순된 양성 user는 원천 오류입니다.

성공 review 뒤 같은 CA/API/전체 기한으로 ServiceAccount·Pod PartialObjectMetadata를
인증된 GET으로 확인합니다. 각각 16 KiB 제한이며 전체 Pod spec·Secret은 읽지 않습니다.
누락·UID/name/namespace 변경·null이 아닌 deletionTimestamp는 즉시 거절하고 통신/권한/
형식 오류는 거절하며 원천 회로에 반영합니다. 반환 전에 바인딩 사실을 확인하고 lease는
인증 시작부터 1초에 제한합니다. native metadata 조회이며 고속 watch 인덱스는 아닙니다.

소유 kind Kubernetes v1.37.0에서 TokenReview만 쓸 때 Pod 삭제 전파가 약 9.8초였고
현재 객체 검사 후 동일한 강제 삭제 fixture는 약 0.12초에 회수됐습니다. fixture 관찰이며
fleet 지연 보장이 아닙니다. 실제 서명·서명 변조·issuer/audience/namespace·unbound 거절·
reviewer 최소 권한·Pod/ServiceAccount 삭제·동명 Pod 재생성을 검증했습니다. 정상 종료·
분할·스트림·다른 클러스터 버전은 배포 검증이 남습니다. 근거 1초 자체가 원천 캐시를
제한하지 않으며 metadata 검사가 바인딩 객체 회수를 보완합니다.

```sh
python3 tools/kubernetes_real_cluster.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview \
  --state-dir /private/owned-kind-qualification
```

도구는 고정된 소유 kind 클러스터·비공개 kubeconfig에 제한하며 고유 fixture namespace/
RBAC를 만들고 제거합니다. 자격은 출력·인자에 넣지 않습니다. Python PyYAML·클러스터
내 kubectl이 필요하고 운영 설정은 바꾸지 않습니다.

기존 workload 설정은 업그레이드 전에 connection.namespaces를 명시해야 합니다.
누락 시 다른 namespace를 허용하는 대신 시작을 거절합니다. Kubernetes RBAC는
metadata 전용 권한이 아닌 객체 GET을 인가합니다. 네이티브는 partial metadata만
요청하지만 reviewer 권한은 Pod/ServiceAccount GET으로 검토해야 합니다.


## 네이티브 인증 근거 유효기간

HTTP·HOP1의 기계 인증 응답은 x-hopae-evidence-ttl-ms로 응답 생성 시 남은
검증 근거 수명을 최대 1000ms로 전달합니다. 만료된 근거는 신원 헤더 없이 503을
반환합니다. 인증된 응답 메타데이터이며 판단 캐시·서명 receipt·클라이언트 인증
주장이 아닙니다. 한강은 교환 시작 시각에 묶어 통신/처리 시간이 수명을 늘리지
않도록 합니다. 향후 인증된 갱신/구독으로 근거를 교체하지 않는다면 서비스·워크로드
스트림도 기한에 종료해야 합니다.

초기 구현은 인증 후 최대 1초에 회수 poll 스케줄링 간격을 더한 시점에 장기 기계
스트림을 닫습니다. 한강은 이제
auth.renew_native_evidence로 선택형 네이티브 재인증을 제공합니다. 명시적 유효 TTL과
같은 신원/종류/AAL/service가 필요하며 실패·늦은 갱신은 거절합니다. 개별 자격 회수
구독과 실제 클러스터 원천의 지속 가용성은 미구현입니다. 이번 수명 검증은
기존 운영 이미지를 전환하지 않으며 장기 워크로드 인증 완료를 의미하지 않습니다.

## 소유한 verifier 준비 파일

로컬 mock API의 임시 port는 같은 디렉터리의0600 임시 파일에 완전히 기록하고
flush/fsync 후 원자적으로 `ready`로 교체합니다. 최종 파일 이름을 빈/부분 내용으로
관측할 수 없습니다. 네이티브 RPC와 HTTP/HOP1 fixture는 URL 구성 전에 ASCII
정규 십진수1..65535만 허용하여 빈 port가 HTTPS 기본443으로 해석되지 않게 합니다.
운영 API origin 의미, 자격 검증, 인증 재시도나 원래1초 원천 예산을 변경하지 않는
fixture IPC 보완입니다.

결정적 스케줄링 제어로 기존 create-before-write 경합과 실제 production 설정 검사기의
빈 port origin 수락을 재현했습니다. 구체적 경합 메커니즘의 증명이지 과거 Workload
첫 Issue 거부의 원인 확정은 아닙니다. 당시 ready 내용이 보존되지 않아 원인은
미확정이며 단독 시험 성공으로 인과관계를 주장하지 않습니다.

`python3 -m unittest discover -s tools -p test_owned_kubernetes_verifier.py -v`로
게시·교체·실패 정리·잘못된 port를 검사합니다. 공통 Rust fixture parser도 빈 값,
0, 선행0, 범위 초과, 공백, 부호, 비ASCII 및 경로 형태를 URL 전에 거부합니다.
소유 TokenReview API는 프로토콜 fixture이며 실제 Kubernetes JWT 서명을 검증하지
않습니다.


## 제한 사항과 남은 작업

- 아직 실제 클러스터에서 검증하지 않았습니다. 오프라인 connector, kube-apiserver
  대상 discovery, 감시는 소유한 프로세스 내 fixture(생성한 RSA/ECDSA 키, JWKS/discovery와
  LIST/WATCH 서버)로만 시험했습니다. TokenReview 대체 경로는 이전 소유 kind 검증을
  유지합니다.
- controller가 보내는 tombstone과 서명 snapshot(ADR 0022 결정 3)은 구현하지 않았습니다.
  프로필별 감시가 임시 폐기 원천이며 별도의 최소 범위 자격증명이 필요합니다.
- X.509-SVID 호출자는 호패가 아니라 한강이 인증합니다(위 계약).
- 프로필당 issuer는 하나입니다. issuer 이전(여러 `--service-account-issuer` 값)에는
  프로필 두 개나 재게시가 필요합니다.
- ADR 0021의 `wk2:` 주체는 전송 주체 `s_…`를 대체하지 않고 함께 보고됩니다. 품계 v2는
  헤더와 수명주기 피드에서 `wk2:`를 소비합니다.
