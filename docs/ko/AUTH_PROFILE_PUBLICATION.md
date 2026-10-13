# 인증 프로필 게시

<!-- translation-status: source=../AUTH_PROFILE_PUBLICATION.md source-rev=1 status=current -->

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
