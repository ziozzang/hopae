# Human 네이티브 ingress 전송 선행 기반

`Services`의 정확히 같은 비공개 Human owner를 HTTP gateway와 공유하고, **운영 RPC에 연결하지 않은** 비공개 gRPC ingress adapter를 추가합니다. Human RPC·receipt 발급·공개 capability 생성자·운영 활성화는 추가하지 않습니다. 기존 Service/Workload RPC 연결은 그대로입니다.

최초 네이티브 Admission은 **호출자 인증 callback과 첫 body poll 이전**에 샘플링합니다. 인증된 호출자만 mutex 안의 `Option<Admission>`을 담은 비공개 holder를 받습니다. generated tonic decoder의 request extension을 실제 HTTP gateway까지 명시적으로 전달하고, gateway는 정확한 owner를 검사한 뒤 원래 Admission을 한 번만 소비하여 기존 네이티브 Engine에 전달합니다. token 누락 시 새 Admission으로 대체하지 않습니다. owner 불일치, 중복 소비, Human/Workload marker 혼합, 원래 수명 만료와 readiness 철회는 거부합니다.

소비 이후에도 같은 readiness를 Admission 안에 유지하여 비동기 Engine/Store 작업, Witness finish 및 Checked current 검사까지 적용합니다. 실패가 관측된 기존 증거는 다시 유효해지지 않습니다. 마지막 검사 직후 발생하는 shutdown까지 원자적으로 막는다고 주장하지 않습니다. 원래 BOOTTIME·벽시계 floor·deadline·양자화 계산을 유지하며, decode나 호출자 처리 뒤 예산을 갱신하지 않습니다.

테스트 전용 owned harness에서 기존 generated Authentication Verify를 연결하고 실제 fixture 호출자 인증, owned OIDC 로그인, 운영 gateway 및 네이티브 Engine capture를 실행합니다. 정상 decode, 원래 예산 만료, 호출자 callback 지연, 잘못된 호출자의 body poll 차단, 취소/슬롯 반환, one-shot owner, 혼합 marker, Store await 중 및 Checked 생성 후 readiness 철회를 구분합니다. 이는 전송/owner 기반 검증이며 향후 Human wire 계약이나 외부 Human endpoint의 검증 완료를 뜻하지 않습니다. 제어 가능한 body fixture에 개발 전용 `http-body` 의존성만 추가합니다.
