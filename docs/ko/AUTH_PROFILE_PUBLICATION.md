# 인증 프로필 게시

<!-- translation-status: source=../AUTH_PROFILE_PUBLICATION.md source-rev=9 status=current -->

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
