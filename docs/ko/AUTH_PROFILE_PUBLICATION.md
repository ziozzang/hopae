# 인증 프로필 게시

<!-- translation-status: source=../AUTH_PROFILE_PUBLICATION.md source-rev=12 status=current -->

[문서](README.md) · [English](../AUTH_PROFILE_PUBLICATION.md)

## 상태와 소유권

구현을 위한 제안 계약입니다. 현재 인증 프로필은 파일 소유이며 시작 시 컴파일합니다.
향후 호패가 프로필 DB·credential 참조·게시 감사·컴파일 런타임을 소유합니다.
Hangang은 기존 인증된 콘솔 lease로 관리를 위임하고 품계는 권한을 소유합니다.
게이트웨이 호출자나 분류기는 프로필을 게시할 수 없습니다.

## 영속 모델

호패 SQLite 트랜잭션에 revision·정규 문서 digest·schema version의 authority 문서와
추가 전용 게시 감사를 저장합니다. 문서에는 bearer 값 없이 환경변수 참조만 둡니다.
삭제는 영속된 빈/비활성 authority이며 행 누락으로 표현하지 않습니다. 재시작이
bootstrap 파일의 삭제된 프로필을 복원해서는 안 됩니다. 최초 행 생성 전에만 파일을
가져옵니다. authority/realm/issuer 변경에는 명시적인 신원 이전이 필요하며 이전
권한을 자동 상속하지 않습니다.

## 게시와 요청 실행

제한된 blocking worker가 기존 독점 인스턴스 소유권 아래 게시를 직렬화합니다.
쓰기 전에 문서 크기·앱 범위·커넥터 제한을 검증하고 허용된 비밀 참조를 해석하여
후보 전체를 컴파일합니다. 변경에는 관리자 권한·기존 CSRF/origin 검사·정확한
revision 조건이 필요합니다. viewer나 data-plane credential은 변경할 수 없습니다.

문서·다음 revision·digest·감사를 함께 commit한 뒤 해당 revision의 ArcSwap 런타임을
원자 교체하며 중간에 await하지 않습니다. HTTP 호출자 취소가 worker를 취소하지
않습니다. commit 이후 스냅샷 설치 실패는 복구까지 인증 readiness를 차단합니다.
알려진 오래된 허용을 계속 반환하지 않습니다. 시작 시 영속 행을 컴파일한 뒤 ready가
되며 참조 누락이나 손상은 차단합니다.

요청은 불변 런타임 스냅샷 하나를 읽습니다. 인증 hot path에는 프로필 DB 질의나
잠금을 넣지 않습니다. 근거에는 authority revision과 제한된 freshness를 전달합니다.
게시 성공은 Hangang stream/pool이 소비하는 회수 generation도 올립니다. 프로필/키
삭제는 선언된 1초 근거 기한 내 열린 stream까지 무효화해야 합니다. 검증 서버의
endpoint·issuer·비밀 참조·보안 옵션이 모두 같을 때만 기존 circuit을 유지할 수 있습니다.

## 인터페이스와 검증

제안 GET/PUT `/v1/authentication/profiles`는 revision·digest·참조 전용 설정을 반환합니다.
PUT은 If-Match를 요구하며 충돌은 409, 잘못된 후보는 422, 저장 장애는 503입니다.
인증된 actor와 결과를 감사하되 credential이나 검증 응답 본문을 기록하지 않습니다.

활성화 전에 재시작 후 삭제 유지·과대/손상 본문·비밀 참조 누락·viewer/data-plane 거부·
동시 CAS·commit 전후 취소·영속화 실패·스냅샷 설치 실패·열린 stream 회수를 검증합니다.
실제 호패/Hangang 프로세스로 기존 provider 세션 보존도 확인합니다. DB 분산 follower의
서명/revision 스냅샷 lease는 별도 설계이며 이 단일 소유자 계약에서 구현하지 않습니다.

## 구현된 저장 기초 계층

`auth_gateway::publication`은 호패의 기존 `meta` 테이블에 revision 문서와 추가 전용
감사 키를 하나의 immediate SQLite 트랜잭션으로 저장합니다. 제한된 참조 전용 설정을
검증하고 읽기 시 digest를 확인하며 오래된 revision을 거부하고 재연결 후에도 비활성
삭제 상태를 유지합니다. 감사 키 충돌은 authority 갱신까지 롤백합니다. 시작 로더·관리
API·컴파일 런타임 교체·stream 회수는 아직 연결하지 않았으며 활성화 검증이 필요합니다.
운영 호출자는 게시 전에 컴파일·권한 검증을 하고 commit 후 런타임 설치 또는 차단을
수행해야 합니다.

`auth_gateway::authority` worker 기초 계층은 영속화 전에 컴파일하고 commit 직후
revision 런타임을 ArcSwap으로 설치합니다. 공유 reader handle은 DB 잠금을 피합니다.
시작 시 삭제 상태를 포함한 DB 상태가 bootstrap 설정보다 우선하며 앱 범위 거부나
비밀 참조 누락은 DB를 변경하지 않습니다. 요청/관리자 연결과 stream generation 집행은
남아 있습니다. 기존 스냅샷 보유자는 호출자가 수명을 집행할 때까지 이전 스냅샷을 유지합니다.

GatewayState에 공유 authority reader를 전달할 수 있습니다. HTTP/HOP1 검증마다
스냅샷 하나를 읽고 삭제된 프로필의 bearer credential은 사람 cookie로 우회하지 않고
거부합니다. 네이티브 parity 시나리오는 연결을 유지한 상태로 삭제를 게시하고 다음
요청의 거부를 확인합니다. 운영 시작 경로와 위임 관리는 명시적인 연결 구현까지 기존
파일 소유 경로를 사용합니다. 이미 열린 upstream 애플리케이션 stream 회수는 아직
구현하지 않았습니다.

프로필 또는 영속 상태가 있으면 애플리케이션 시작 시 기존 utility connection으로
authority를 초기화하고 앱 범위를 검증하여 reader를 gateway router와 공유합니다.
실제 세 프로세스 fixture에서 bootstrap 파일을 그대로 둔 호패 교체 후에도 DB 삭제
상태가 유지됩니다. 첫 오래된 pooled 연결은 503일 수 있고 이후 재연결은 401입니다.
fixture의 삭제는 소유한 오프라인 DB 운영자 작업이며 아직 구현하지 않은 위임 관리
API를 증명하지 않습니다. 운영의 오래된 bootstrap 비밀 참조를 제거하기 전 파일 중심
CLI/preflight 동작에 대한 별도 이전 검토도 필요합니다.

GET `/v1/authentication/profiles`를 기존 관리자 인증/위임 gate 뒤에 등록했습니다.
DB의 참조 전용 문서·revision ETag·no-store를 반환하고 authority가 없으면 revision
0입니다. 전용 blocking worker permit 4개는 HTTP 기한이 끝나도 DB 읽기가 완료될
때까지 유지됩니다. 인증 시나리오에서 익명 거부와 소유한 저장 프로필 조회를 확인합니다.
PUT은 기존 관리자 fence로 쓰기 트랜잭션 안에서 actor를 재검증해야 하므로 아직
구현하지 않았습니다. Hangang 플러그인 UI와 이 endpoint 운영 배포 검증도 남아 있습니다.

PUT `/v1/authentication/profiles`는 단일 따옴표 If-Match revision과 필수
`configuration` 필드만 있는 본문을 요구합니다. null은 비활성화입니다. listener가
이 PUT의 CSRF·관리자 역할을 확인합니다. 제한된 blocking worker는 후보를 다시
컴파일하고 immediate 트랜잭션 내부 및 commit 직전에 기존 actor fence를 확인한 뒤
중간 await 없이 스냅샷을 설치합니다. 호출자 취소가 worker를 취소하지 않습니다.
현재 비밀 참조 허용 목록은 bootstrap 선언이며 verifier credential·사설 endpoint는
원래 endpoint/issuer/보안 옵션 바인딩도 일치해야 합니다. 새 참조 선언은 운영자 설정이
필요합니다. viewer/CSRF 거부·미선언 사설 endpoint 거부·오래된 revision·영속 삭제·
commit 직전 actor 거부 시 상태와 감사 동시 롤백을 검증합니다. Hangang 위임
middleware의 endpoint 허용 목록 연결은 남아 있으므로 새 쓰기는 현재 인증된 호패
자체 admin API 경로입니다. 통합 콘솔 쓰기·배포는 남아 있고 stream 회수나 전체
인증 수명주기 완성을 주장하지 않습니다.

위임 adapter는 프로필 GET 조회와 필수 `revision`·`configuration`의 서명된 POST
`/v1/authentication/profiles/publish`를 받습니다. 원본 본문 digest와 nonce를
검증한 뒤 인증된 필드로 내부 PUT 본문과 If-Match를 만들고 기존 관리자 gate·
트랜잭션 actor fence를 적용합니다. 재사용·오래된 revision 시나리오를 통과했습니다.
호패 콘솔 패키지 0.1.3에 프로필 탭·참조 전용 JSON 편집기를 추가하고 읽은 revision으로
저장하며 viewer 쓰기를 비활성화합니다. 소유한 브라우저 컴포넌트 fixture는 mock host
API로 표시·revision/설정 제출·viewer 거부·abort 정리를 확인합니다. 실제 배포된
broker/UI 게시 검증과 stream 회수는 남아 있습니다.

## 내부 배포 검증

정적 Linux 빌드와 콘솔 패키지 0.1.3을 내부 배포했습니다. 실제 Hangang 콘솔
브라우저로 DB의 참조 전용 프로필을 읽고 서명 broker를 통해 동일 설정을 게시하여
revision 증가·로그아웃 정리·익명 거부를 확인했습니다. Hangang 설정 revision과
인증 설정은 유지됐습니다. 실제 서비스 인증·권한 매트릭스·mTLS 네이티브 전송·
통합 메뉴·기존 SSO 회귀 검사를 통과했습니다. 일관된 DB 백업·패키지 pin·이전
이미지 복구 자료는 비공개입니다. 전체 target 검사에서 라이브러리 400·기타 통합
15·시나리오 365건이 통과했고 시나리오 40건은 명시적 ignored입니다. 기존 PEM
parser 유지보수 중단 audit 경고는 남아 있습니다. 내부 기능 배포이며 새 공개 다중
플랫폼 릴리즈나 전체 수명주기/처리량 검증을 의미하지 않습니다.

## 게시 상태 연속성

서비스/realm과 verifier 바인딩이 같으면 게시 후에도 커넥터의 전송 풀·동시성 permit·
circuit 상태를 유지합니다. 바인딩 fingerprint는 커넥터 설정 전체와 해석된 verifier
credential digest를 포함하므로 비밀이나 보안 옵션이 바뀌면 재사용하지 않습니다.
실제 루프백 검증 서버로 circuit을 연 뒤 network 프로필을 바꾸고 추가 외부 호출 없이
다음 인증이 억제됨을 검증합니다. authority는 비활성 기간을 포함해 스냅샷 간 관측 시간
기준을 공유하므로 게시와 시계 rollback이 이미 관측한 credential 만료를 되돌리지
않습니다. 시간 기준은 프로세스 로컬이며 재시작 watermark는 아닙니다. 삭제 후 재생성
커넥터·프로세스 교체의 영속 circuit/quarantine 수명주기는 남아 있습니다. 소스 검증된
변경이며 현재 내부 바이너리에는 이 연속성 수정이 아직 들어가지 않았습니다.


## 설정 권위 모드

`authentication.source`는 인증 프로필(`authentication_gateway`)과 자격 증명 투영
계획(`credential_projection`)의 소유자를 정합니다.

| `authentication.source` | 소유자 | 시작 | 콘솔·API 편집 |
| --- | --- | --- | --- |
| `store`(기본값) | 저장소 | 파일은 빈 저장소만 초기화하며, 저장된 문서(또는 tombstone)가 바뀐 파일보다 우선합니다 | 허용(`PUT /v1/authentication/profiles`, `/projections`) |
| `config` | 파일 | 시작할 때마다 저장소를 파일에 맞춥니다 | 거부: `409 config_authoritative` |

`config` 모드의 시작은 먼저 파일의 프로필을 게시와 같은 검사로 검증하고 컴파일합니다.
파일이 잘못되었으면 명확한 오류로 시작을 멈추고 저장소는 건드리지 않습니다. 저장된
문서가 파일과 다르면 CAS 게시로 파일을 게시합니다. 다음 리비전, actor가 `config`인 감사
행, 파일에 없으면 비활성 tombstone, 그리고 필수 이벤트 `authentication.reconciled`
(`attrs.kind` = `profiles` 또는 `projections`, `previous_revision`, `revision`,
`actor`)가 남습니다. 같은 문서는 리비전을 유지하고 아무것도 쓰지 않습니다. 투영 계획은
plans를 비교하고 파일의 plans를 저장소의 다음 리비전으로 게시합니다(이 모드에서는 파일의
`revision`을 무시합니다). `GET /v1/authentication/profiles`는 `source`를 알려 줍니다.

Kubernetes 패키지가 필요로 하는 선언적 모드입니다. Helm values가 파일을 바꾸면 재시작
없이도 저장소가 따라갑니다(아래).

### 실행 중 맞춤

`config` 모드에서 Hopae는 실행 중에도 설정 파일을 주기적으로 확인합니다
(`authentication.reload_interval_ms`, 기본 1000, `0`이면 끄며 시작할 때만 맞춥니다).
파일 내용의 다이제스트를 비교하며 파일 시스템 알림은 쓰지 않습니다. ConfigMap 볼륨은
심볼릭 링크(`..data`)를 바꾸는데 파일에 건 inotify 감시는 이를 놓치기 때문입니다. 바뀐
파일은 시작과 똑같은 과정(크기 한도, 파싱, 설정 전체 검증, 참조한 환경 변수 확인, 프로필
컴파일)을 모두 거친 뒤에야 같은 CAS 게시(다음 리비전, actor가 `config`인 감사 행)로
저장소에 반영되고 실행 중 스냅숏이 교체됩니다. 기록은 `attrs.cause = reload`인
`authentication.reconciled`입니다. 폐기한 API 키나 제거한 프로필은 교체 직후 요청부터
인증되지 않습니다.

| 바뀐 파일 | 결과 |
| --- | --- |
| 유효하고 프로필이나 투영 계획이 다름 | 실행 중 반영: 새 리비전, 기록, `hopae_config_reloads_total{result="reconciled"}` |
| 유효하고 프로필과 계획이 같음 | 아무것도 쓰지 않음 |
| 잘못됨(파싱 불가, 잘못된 프로필, 없는 변수 등) | 아무것도 바뀌지 않음: 현재 프로필이 유지되고, 유효한 파일이 올 때까지 `hopae_config_reload_failing` = `1`, 경고, `GET /v1/status`의 `reload.config.failing`과 `error` |
| 다른 키가 바뀜(리스너, 제공자, `authentication.source` 등) | 적용하지 않음: `reload.config.restart_required = true`, `result="restart_required"`, 경고. 다음 시작에서 적용 |
| 프로필 없이 시작했는데 프로필이 생김 | 잘못됨으로 보고: 인증 게이트웨이를 시작하려면 재시작이 필요 |

**시간.** 기본 1초 주기에서 폐기는 컨테이너 안의 파일이 바뀐 뒤 약 1초 안에(확인 주기와
검증, 저장소 트랜잭션 한 번) 적용됩니다. ConfigMap 객체를 고친 뒤 파일이 바뀌기까지의
시간은 Hopae 밖의 일입니다. kubelet은 동기화 주기와 캐시 TTL에 따라(기본 최대 약 1분)
ConfigMap 볼륨을 갱신하며 `subPath` 마운트는 갱신하지 않습니다. 더 빠른 폐기가 필요하면
ConfigMap을 디렉터리째(`subPath` 아님) 마운트하고, kubelet의
`configMapAndSecretChangeDetectionStrategy`나 동기화 주기를 낮추거나, API를 지켜보며
파일을 직접 쓰는 사이드카(config-reloader 등)가 채우는 projected 볼륨을 쓰거나, `store`
모드에서 콘솔로 폐기하세요. Hopae 쪽 지연은 `authentication.reload_interval_ms`로
제한됩니다.

이전 절차:

- **store → config:** 현재 문서(`GET /v1/authentication/profiles`와 `/projections`)를
  파일에 옮기고 `authentication.source = "config"`로 설정한 뒤 재시작합니다. 같은 문서는
  리비전을 유지하고, 다른 부분은 다음 리비전으로 게시되고 기록됩니다.
- **config → store:** `authentication.source = "store"`로 설정(또는 제거)하고
  재시작합니다. 저장소는 마지막으로 맞춘 문서를 유지하고 콘솔 편집이 다시 동작합니다.
  이후 파일 변경은 적용되지 않으며 파일은 빈 저장소만 초기화합니다.
