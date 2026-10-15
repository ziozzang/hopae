# Human 네이티브 ingress 전송 선행 기반

`Services`의 정확히 같은 비공개 Human owner를 HTTP gateway와 공유하고, **운영 RPC에 연결하지 않은** 비공개 gRPC ingress adapter를 추가합니다. Human RPC·receipt 발급·공개 capability 생성자·운영 활성화는 추가하지 않습니다. 기존 Service/Workload RPC 연결은 그대로입니다.

최초 네이티브 Admission은 **호출자 인증 callback과 첫 body poll 이전**에 샘플링합니다. 인증된 호출자만 mutex 안의 `Option<Admission>`을 담은 비공개 holder를 받습니다. generated tonic decoder의 request extension을 실제 HTTP gateway까지 명시적으로 전달하고, gateway는 정확한 owner를 검사한 뒤 원래 Admission을 한 번만 소비하여 기존 네이티브 Engine에 전달합니다. token 누락 시 새 Admission으로 대체하지 않습니다. owner 불일치, 중복 소비, Human/Workload marker 혼합, 원래 수명 만료와 readiness 철회는 거부합니다.

소비 이후에도 같은 readiness를 Admission 안에 유지하여 비동기 Engine/Store 작업, Witness finish 및 Checked current 검사까지 적용합니다. 실패가 관측된 기존 증거는 다시 유효해지지 않습니다. 마지막 검사 직후 발생하는 shutdown까지 원자적으로 막는다고 주장하지 않습니다. 원래 BOOTTIME·벽시계 floor·deadline·양자화 계산을 유지하며, decode나 호출자 처리 뒤 예산을 갱신하지 않습니다.

테스트 전용 owned harness에서 기존 generated Authentication Verify를 연결하고 실제 fixture 호출자 인증, owned OIDC 로그인, 운영 gateway 및 네이티브 Engine capture를 실행합니다. 정상 decode, 원래 예산 만료, 호출자 callback 지연, 잘못된 호출자의 body poll 차단, 취소/슬롯 반환, one-shot owner, 혼합 marker, Store await 중 및 Checked 생성 후 readiness 철회를 구분합니다. 이는 전송/owner 기반 검증이며 향후 Human wire 계약이나 외부 Human endpoint의 검증 완료를 뜻하지 않습니다. 제어 가능한 body fixture에 개발 전용 `http-body` 의존성만 추가합니다.

## 보관된 검증 결과의 현재 상태 재확인

실제 Engine이 만든 비공개 `Checked`는 원본 쿠키를 보관하거나 재구성하지
않고 같은 네이티브 owner 검사를 반복할 수 있습니다. 실제 Engine이 확정한
scope만 사용하며 공개 생성자나 호출자가 지정하는 subject는 없습니다.
원래 Admission·readiness·프로바이더/실제 인증 재료/앱과 DB의 세션·사용자·
primary·factor 검사 및 철회 처리를 그대로 적용합니다. 입력을 받는 검사는
원래 scope와 정확히 일치해야 합니다. 이 검사에서 실패하면 비동기 검사가
겹쳐 있어도 이후 보관된 결과의 검사 역시 거부합니다. 원천 record의 선행
기능이며 receipt 발급이나 RPC 활성화를 의미하지 않습니다.

## 고정 publication과 보관 용량

Human 원천은 실제 native Owner와 앱 publication 하나에 고정됩니다. 최종
publication 검사는 로컬 atomic 상태와 snapshot 동일성만 확인하며 최종
원천 시간 보고 뒤 시계를 호출하지 않습니다. 관측한 철회는 다시 유효해지지
않습니다. 원격 철회까지 원자적으로 보장하는 기능은 아닙니다.

Engine 검증 결과는 불변 snapshot 안의 비공개 앱 위치를 보관합니다.
요청마다 앱 정책 전체를 복제하지 않습니다. Engine이 실제 선택한 앱의
주소로 후보 위치를 계산한 뒤 실제 snapshot 원소와 pointer 동일성을
검사합니다. 같은 내용의 외부 복사본은 앱을 선택할 수 없습니다. Store
재검증의 기존 제한된 작업 안에서는 임시 앱 복사가 발생할 수 있습니다.

보관 용량 helper는 중첩 String·Vec의 capacity를 checked 산술로 합칩니다.
공유 Scope·publication은 record마다 계산하지 않으며 Human 준비 metadata는
원천에서 한 번 계산합니다. 기존 설정·프로바이더 client·DB pool은 서비스
기본 메모리입니다. 이 값은 요청한 보관 할당 용량이며 RSS나 할당자 내부
메모리가 아닙니다. 원천은 index·expiry 항목, Arc·record 구조, 동시 임시
작업과 quota reservation 수명을 별도로 제한해야 합니다. 이 선행 구현은
Human endpoint 활성화나 처리량 검증 완료를 의미하지 않습니다.
