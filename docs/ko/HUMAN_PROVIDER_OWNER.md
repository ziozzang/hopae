# Provider incarnation 영속화 선행 경계

[English](../HUMAN_PROVIDER_OWNER.md)

내부 SQLite provider owner는 이후 native Human 세션 capture를 준비하는 기반입니다.
Human receipt/RPC·로그인 증명이나 전체 Human owner 구현을 제공하지 않습니다.
Service·Workload·기존 native 세션과 별도이며 LDAP 비밀번호 양식을 자체 계정으로
확대하거나 Google 강제 재인증 지원을 추가하지 않습니다.

migration 7은 기존 provider의 양수 incarnation을 초기화하고 삭제 후에도 별도
sidecar tombstone을 유지합니다. insert·delete 및 kind·활성/삭제 상태·직렬화 config·
secret 참조·도메인/연결/신뢰 정책 변경은 같은 트랜잭션의 trigger가 incarnation을
증가시킵니다. 이전 설정 복원이나 ID 재생성은 옛 incarnation을 재사용하지 않습니다.
ID 직접 변경은 거부하며 명시적 삭제·생성을 사용합니다. 정수 overflow는 변경을
원자적으로 거부합니다. 표시명·정렬·관리 출처·시각 및 동일 파일 재수입은 유지합니다.
JSON 직렬화만 달라도 보수적으로 무효화할 수 있습니다. 기존 세션·factor·권한은
migration에서 재작성하지 않습니다.

crate 내부 참조는 숫자 생성자·직렬화·Debug를 제공하지 않고 하나의 열린 Store에
바인딩됩니다. 제한된 현재 조회는 실제 활성 provider와 incarnation을 함께 확인하고
누락·비활성·삭제·다른 Store·재개방된 Store를 거부합니다. cookie·provider 설정·비밀은
참조에 보존하지 않습니다. 조회는 해당 DB 읽기 시점만 보장하며 이후 회수를 막는 lock은
아닙니다.

후속 실제 native 검증·세션/handle/사용자/factor 근거·현재 설정 owner·원래 BOOTTIME
예산·최종 공개 fence 연결이 필요합니다. 이 참조 자체는 Human/MFA 권위가 아닙니다.
원격 LDAP/OIDC 계정 상태 polling, 임의 DB 복구 rollback 및 live process clone 방어를
제공하지 않습니다. migration backup과 원천 process retirement는 별도입니다.

## 실제 컴파일된 Registry 준비

production startup은 기존 설정 세대/import 쓰기가 끝난 뒤 실제 DB provider 행과
incarnation을 하나의 제한된 SQLite 읽기 트랜잭션에서 준비합니다. 기존 양수 설정
세대가 일치해야 하며 기본값을 만들지 않고 최대4096행을 허용합니다. 같은 행으로
OIDC·LDAP adapter와 Registry 내부 비공개 owner map을 구성합니다. 파일 설정이
retained/API-managed DB 권위를 대체하지 않습니다.

정확한 application snapshot을 한 번 동결하고 같은 ArcSwap을 Services에서도
사용합니다. Registry는 원래 Arc와 publisher를 보존합니다. 실제 컴파일된 adapter가
사용 가능해야 하며 자격 누락·LDAP trust/config 오류·미지원 kind·adapter 부재는
DB enabled 값만으로 추가 owner를 얻지 못합니다. 기존 공개 from_snapshot은 일반
용도를 유지하지만 추가 owner map을 제공하지 않습니다.

fallible bind/listener 준비 후 Bound 반환 전에 DB owner set/설정 세대와 application
동일성을 재확인하고 그 뒤 OIDC refresher를 시작합니다. 이후 run/router 생성은
여전히 실패할 수 있습니다. 기존 Weak refresher가 제한된 진행 중 요청을 끝낸 뒤
종료할 수 있으므로 모든 startup 실패에 외부 요청이 전혀 없었다는 주장은 하지 않습니다.

비공개 fence는 해당 Registry·Store에 속하고 새 DB 행으로 뒤늦게 갈아타지 않습니다.
비활성/재활성·material ABA·삭제/재생성·application Arc 교체를 거부하고 관측한 실패는
그 fence를 은퇴시킵니다. 변경 provider는 새로 준비한 Registry가 필요합니다. 현재
Registry는 startup 고정이며 reload는 재시작이 필요합니다. 관측하지 못한 특권
ArcSwap rollback·임의 DB 복구·live clone 방어를 제공하지 않습니다.

현재의 fresh durable 조회는 정확성 기반이며 인증 hot path나 Human 권한 완성이
아닙니다. 후속 원천 소유 불변 memory snapshot·membership/publication gate가 숫자
capability 공개 없이 은퇴 경계를 유지해야 합니다. cache/follower/성능 검증과 실제
Engine 세션/factor/app 결합·Human protocol은 남아 있습니다.
