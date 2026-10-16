# 관리 리스너용 서비스 자격 증명

<!-- translation-status: source=../SERVICE_CREDENTIALS.md source-rev=1 status=current -->

[문서](README.md) · [English](../SERVICE_CREDENTIALS.md)

관리 리스너를 호출하는 기계 호출자는 관리자 세션이나 위임 키 대신 **경로 범위가
정해진 읽기 전용 서비스 자격 증명**으로 인증합니다. 첫 사용자는 서명된 멤버십
투영과 주체 생명주기 피드를 읽는 Pumgye 정책 v2입니다(한강 ADR 0021). 서비스
자격 증명은 바인딩된 클라이언트 인증서와 함께일 때만, 이 인스턴스의 audience에
대해서만, 정확히 지정된 읽기 경로에서만 쓸 수 있으며 상태를 바꾸는 경로에는 절대
쓸 수 없습니다.

## 전제 조건과 설정

- 콘솔이 켜져 있고(`admin.public_url`, `listen.admin`) 관리 리스너가 상호 TLS를
  씁니다(`listen.admin_tls`: `certificate`, `key`, `client_ca`). 평문 관리 리스너에
  제시된 서비스 토큰은 거부됩니다(`403 service_transport_required`).
- `admin.service_audience`(선택, 보이는 ASCII 1~256자): 호출자가 지정해야 하는
  audience입니다. 기본값은 콘솔 출처(예: `https://hopae-admin.example.test`)입니다.
- 저장소 스키마 버전 15(마이그레이션 `0015_service_credentials`, 시작 시 적용).
  모든 마이그레이션과 마찬가지로 업그레이드 전에 저장소를 백업합니다.

클라이언트 인증서는 `client_ca`의 CA가 발급합니다. Hopae는 여기에 더해 자격 증명마다
SubjectPublicKeyInfo의 SHA-256 그리고/또는 정확한 주체 대체 이름(DNS 또는 URI,
예: SPIFFE ID)으로 인증서를 고정합니다.

## 동작

요청은 다음을 담습니다.

```http
POST /v1/subjects/lifecycle HTTP/1.1
Host: hopae-admin.example.test
Authorization: Bearer hsc1.pumgye-v2.<43 characters>
X-Hopae-Audience: https://hopae-admin.example.test
X-Hopae-Admin-Request: 1
Content-Type: application/json

{"cursor": null, "limit": 100}
```

검사는 아래 순서이며 처음 실패한 검사가 응답합니다.

| 검사 | 거부 |
| --- | --- |
| 연결이 검증된 클라이언트 인증서를 가진 관리 mTLS 리스너입니다 | `403 service_transport_required` |
| `Authorization` 헤더가 하나이고 `hsc1.<id>.<secret>` 형식이며, 자격 증명이 있고, 비밀값 digest가 current 또는 next digest와 같고(상수 시간 비교), 폐기되지 않았고 만료되지 않았습니다 | `401 service_credential_rejected`(모든 경우에 같은 응답) |
| 클라이언트 인증서가 자격 증명의 SPKI 고정값 그리고/또는 SAN과 맞습니다 | `403 service_binding_mismatch` |
| `x-hopae-audience`가 정확히 하나이고 이 인스턴스의 audience와 같으며 자격 증명이 허용합니다 | `403 service_audience_mismatch` |
| `METHOD /path`가 자격 증명의 허용 목록에 있고 **동시에** 부여 가능한 읽기 경로입니다(저장소 내용과 관계없이 변경 경로는 절대 아님) | `403 service_route_forbidden` |
| 자격 증명의 토큰 버킷에 토큰이 있습니다 | `429 rate_limited`와 `retry-after` |

그다음 요청은 대상 읽기로 실행되며 콘솔의 JSON API 규칙(`content-type:
application/json`, `x-hopae-admin-request: 1`), 해당 읽기의 행위자별 버킷, 그 읽기의
`admin.read` 감사 기록이 그대로 적용됩니다. 서비스 자격 증명은 위임
(`x-hopae-delegation`)과 결합되지 않고 브라우저 쿠키를 읽지 않습니다. TLS 상대가
곧 클라이언트이므로 이 경로에서는 전달 헤더를 신뢰하지 않으며, 지정된 `Host`는
콘솔 호스트여야 합니다.

부여 가능한 경로(CLI는 다른 경로를 저장할 수 없습니다):

| 경로 | 목적 |
| --- | --- |
| `POST /v1/groups/projection/snapshot`, `POST /v1/groups/projection/changes` | 서명된 멤버십 투영([그룹](GROUPS.md)) |
| `POST /v1/subjects/lifecycle`, `POST /v1/subjects/lifecycle/snapshot` | 주체 생명주기 피드와 대조 스냅숏([주체 디렉터리](SUBJECT_DIRECTORY.md)) |
| `POST /v1/subjects/resolve`, `POST /v1/subjects/search`, `POST /v1/subjects/groups` | 주체 디렉터리 읽기 |
| `POST /v1/groups/search`, `POST /v1/groups/get` | 그룹 읽기 |
| `POST /v1/explain/authentication` | [인증 설명](AUTHENTICATION_EXPLAIN.md) |
| `GET /v1/status` | 상태 |

프리셋 `pumgye-v2`는 처음 네 경로만 정확히 부여합니다.

### 비밀값, 교체, 폐기

토큰은 `hsc1.<id>.<secret>`입니다. id(소문자, 숫자, 안쪽 `-`로 된 3~48자)와 base64url로
쓴 32바이트 난수입니다. 저장되는 것은
`SHA-256("hopae:service-credential:v1\0" || id || 0x00 || secret)`뿐이며 비밀값은 CLI가
한 번만 보여 줍니다. 비밀값의 엔트로피가 256비트이므로 도메인을 분리한 빠른 해시로
충분합니다(비밀번호 해시 불필요).

중단 없는 교체: `rotate`가 **next** 비밀값을 발급하면(current와 next 모두 허용, 기록에는
`credential_slot: next`) 호출자에게 배포하고, `promote`로 current로 바꾸면 이전 비밀값은
더 이상 동작하지 않습니다. 교체가 대기 중이면 두 번째 `rotate`는 거부됩니다. `revoke`는
행을 묘비로 남기고(id는 재사용되지 않음) 이후 모든 변경을 거부합니다.

## 관리 API, 콘솔, 관측

| 명령 | 효과 |
| --- | --- |
| `hopae admin service-credentials create <id> (--preset pumgye-v2 \| --route "METHOD /path"…) [--audience A…] (--client-spki-sha256 HEX \| --client-san SAN)… [--expires-in-days 90] [--rate-per-minute 120] [--burst 30] [--note TEXT] --config <path>` | 생성하고 토큰을 한 번만 출력(stdout). 부여할 수 없는 경로, mTLS 바인딩 없음, 400일을 넘는 수명, 범위 밖의 비율(분당 1~6,000)과 버스트(1~1,000), 이미 있는 id는 거부 |
| `hopae admin service-credentials rotate <id>` | next 비밀값을 발급해 출력 |
| `hopae admin service-credentials promote <id>` | next를 current로 |
| `hopae admin service-credentials revoke <id>` | 폐기(묘비) |
| `hopae admin service-credentials list` | id, 상태, 경로, audience, 바인딩, 만료, 교체, 비율. 비밀값이나 digest는 절대 출력하지 않음 |

각 변경은 필수 이벤트 `admin.service_credential`(`attrs.change` = `created`,
`rotated`, `promoted`, `revoked`, `attrs.credential_id`, `attrs.actor = cli`)과 함께
커밋됩니다. 응답한 각 읽기는 `attrs.actor = service:<id>`, `attrs.credential_id`,
`attrs.credential_slot`을 담은 `admin.read`를 씁니다. 거부는 거부 코드와 경로(토큰은
절대 아님)와 함께 경고로 기록되고 `hopae_admin_service_credentials_total{result}`
(`accepted`, `accepted_next` 또는 거부 코드)로 집계됩니다.

## 제한과 호환성

- 자격 증명은 저장소에 있고 CLI로 관리합니다(인스턴스 실행 중에도 안전). HTTP 관리
  API는 없으므로 관리자 세션으로 발급할 수 없습니다.
- 비율 제한은 프로세스별입니다. 인스턴스가 여러 개면 각각 설정된 비율을 허용합니다.
- 클라이언트 인증서 폐기(CRL/OCSP)는 `client_ca` 처리를 따릅니다. 호출자를 즉시
  차단하려면 서비스 자격 증명을 폐기합니다.
- 스키마 15는 0014 다음입니다. 다른 0015를 추가하는 브랜치는 번호를 바꿔야 합니다.

## 예제, 검증, 관련 페이지

```sh
hopae admin service-credentials create pumgye-v2 --preset pumgye-v2 \
  --client-san spiffe://cluster.example.test/ns/world/sa/pumgye \
  --client-spki-sha256 "$(openssl x509 -in pumgye.pem -pubkey -noout \
     | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)" \
  --config /etc/hopae/hopae.json > /run/secrets/pumgye-hopae-token
```

이후 Pumgye의 `token_env`에 토큰을 두고, TLS 클라이언트 신원으로 고정된 인증서를 쓰며,
`x-hopae-audience`를 보냅니다. 시나리오 [318](../../scenarios/318-service-credentials.md)이
동작을 규정하고 위협 모델은 TM-75~TM-77입니다. 관련: [관리](ADMIN.md),
[그룹](GROUPS.md), [주체 디렉터리](SUBJECT_DIRECTORY.md), [위협 모델](THREAT_MODEL.md).
