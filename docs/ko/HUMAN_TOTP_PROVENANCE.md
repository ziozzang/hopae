# Native TOTP 원래 factor 근거 선행 경계

[English](../HUMAN_TOTP_PROVENANCE.md)

migration 8의 내부 `session_totp_provenance`는 세션당 하나의 현재 연결을 보존합니다.
실제 native TOTP elevation 트랜잭션만 원래 enrollment ID/revision·사용자/세션·새
credential generation·factor index/시각·선택적 설정 세대를 기록합니다. seed·code·
envelope·cookie·원문 proof·OTP counter는 기록하지 않습니다. 근거·challenge 소비,
credential 회전과 감사가 함께 commit되거나 함께 rollback됩니다. 같은 사용자의 더
높은 credential generation만 이전 연결을 교체하며 세션 삭제 시 연결도 삭제됩니다.

기존 AAL2 세션에 현재 enrollment나 factor label로 근거를 소급 생성하지 않습니다.
설정 세대 없는 기존 native 흐름은 유지하지만 추가 owner 자격은 주지 않습니다.
일반 verify 동작은 그대로이고 추가 내부 검사는 근거 누락·현재 설정 세대 불일치를
거부합니다. 정확한 세션 factor entry·세션 세대/사용자 상태·활성 enrollment revision을
확인합니다. 다른 세션의 정상 OTP 사용에 따른 counter 증가만으로 기존 근거를
무효화하지 않습니다. factor 회수·세션 종료·근거/설정 변경·누락·저장소 실패·기한
초과·다른 Store는 거부하고 원래 factor 시각·세션 touch·신선도를 갱신하지 않습니다.
손상된 schema는 읽기 전용 사전 검사에서 복구 없이 거부합니다.

이 기반은 Human 인증 capability·observed clock proof·전체 current-session owner가
아니며 공개 RPC·추가 권한을 제공하지 않습니다. 후속 실제 Engine Allow의 정확한
HandleView/native snapshot과 provider/session/user/factor/app 현재 owner 및 원래
admission/공개 fence 연결이 필요합니다. 자체 비밀번호 계정·Google 강제 재인증·복구·
원격 디렉터리 회수·임의 SQL rollback/live clone 방어도 별도입니다.
