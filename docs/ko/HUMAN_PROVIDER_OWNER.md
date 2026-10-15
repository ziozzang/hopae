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
