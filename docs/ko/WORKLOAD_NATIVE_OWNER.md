# 네이티브 Workload receipt owner

이 단계는 실제 Workload 인증 receipt 발급과 원천 시각 관측만 연결합니다.
Pum Workload permit RPC·소비형 호패 projection·한강 Workload dispatch는 후속
통합 게이트입니다. Human은 세션/핸들/사용자/팩터 owner가 별도로 필요하며
Workload나 Service로 변환하지 않습니다. 기존 Service API·기본 동작은 유지합니다.

기존 `receipt_issuer`에 선택적으로 다음 설정을 추가합니다.

```json
"workload_receipts": {
  "scopes": [{"service": "orders", "audience": "orders-api"}],
  "capacity": 131072
}
```

scope는 기존 issuer 선언의 중복 없는 부분집합이어야 하고, 해당 애플리케이션과
실제 Kubernetes TokenReview profile이 필요합니다. 인증된 mTLS gRPC와 Linux
BOOTTIME이 필요하며 지원하지 않는 플랫폼은 이 선택 기능을 거절합니다. 기본
동작은 영향을 받지 않습니다. Workload 사용 시 논리적 identity_authority_epoch는
40 ASCII바이트 이하입니다. 이는 TokenReview issuer URL/cluster realm과 다릅니다.
설정이 없으면 새 RPC를 등록하지 않습니다. 비밀값은 기존 네이티브 참조를 사용합니다.

새 IssueObserved는 실제 caller·parse·gateway·profile 인증 경로를 호출합니다.
비공개 request extension을 통해 원래 source attempt를 전달하고 실제
kubernetes-tokenreview Workload만 CapturedWorkload로 만들 수 있습니다.
클라이언트 헤더·Service 키/조합·relay·Lua·Human 세션으로 만들 수 없습니다.
기존 subject 해시 및 wire kind3/AAL0를 유지합니다.

provider 이전 BOOTTIME 시작점에 최대1000ms를 고정하고 원래 네이티브
토큰/provider UTC 만료는 이를 줄이기만 합니다. 원래 wall 표본과 양자화1ms
차감을 사용하며 TokenReview/서명/Observe/retry 뒤에서 새 수명을 시작하지 않습니다.
서명된 expiry 자체가 원래 deadline 이내입니다. 관측 remaining은 추가1ms를
차감합니다. 이 tick은 UTC가 아닙니다. strict UTC verifier는 Workload의 완전한 canonical
workload_epoch 문법을 예약하여 거절합니다. 기존 Service의 wobs1: authority와
일반 UTC Workload의 wobs1:legacy 같은 자유 식별자는 기존 동작을 유지합니다.
과거 일반 UTC 호출자가 우연히 새 canonical 전체 문법과 같은 식별자를 썼다면
명시적 식별자 이주가 필요하다는 namespace 예약 한계가 있습니다. 현재 native
production strict Workload issuer는 없지만 generic 라이브러리 계약은 보존합니다.
잘못된 wobs1 문법은 기존 generic UTC 식별자/서명 규칙을 따르며, 새 Workload RPC는
항상 엄격한 canonical decode·정확한 process nonce·record를 요구하고 UTC로
fallback하지 않습니다. Workload record는 ObservedChecked만 보관하므로 strict
Checked 소비 capability로 전달할 수 없습니다.

provider 전 application publication을 캡처하고 profile/application/caller/원천
시각을 콜백·RNG·서명·키 검증 뒤에도 확인합니다. 원래 캡처의 만료/owner교체는
복구해도 되살리지 않습니다. BOOTTIME 읽기 오류·진짜 역행은 domain을 영구
거절하고 정상적인 동시 읽기의 완료 순서 역전은 오탐하지 않습니다.
Observe는 정확한 receipt hash·문맥의 원래 record가 있어야 합니다. 누락/재시작/
만료 시 서명만으로 수명이나 record를 재구성하지 않습니다. raw token을 보관하거나
Observe에서 TokenReview를 다시 호출하지 않습니다. 따라서 외부 Pod/SA 철회는
순간 무효화가 아니라 최대 원래1초 증명의 한계로 설명합니다. 실제 클러스터 JWT
검증·Workload 전체 체인 완료를 주장하지 않습니다.

전역 용량은 기본131072, 설정 범위1..1048576입니다. provider 전 semaphore로
예약하며 발행 전 취소는 반납합니다. 살아 있는 record를 밀어내지 않고 용량 초과를
거절합니다. 256개 shard의 짧은 잠금 map+만료 heap을 사용합니다. shard당 최대
2*ceil(capacity/256)개(기본1024개)로 과거 편중 트래픽의 잔여 할당도 제한하며
편중 용량 초과도 살아 있는 record를 축출하지 않고 거절합니다. 발급마다 전체 맵을
복사하지 않습니다. lookup은 Arc 복사, insert는 O(log shard_size), 평상시 begin마다
다음 한 shard에서 최대8개 만료 항목만 정리합니다. 전역 용량이 소진된 경우만
최대256개 atomic heap-head hint를 읽고 만료된 shard만 잠가 각 최대8개를 정리하며
permit 확보 즉시 멈춥니다. hint는 같은 shard 잠금 안에서 heap과 함께 갱신합니다.
따라서 capacity1·먼 shard의 만료 record도 다음 요청에서 회수하며256번 거절할
필요가 없습니다. 살아 있는 record를 지우지 않습니다. 잠금 안에서는 provider·서명·
시계/owner콜백·await를 실행하지 않습니다. 유휴 만료 record가 남더라도 전체 용량
이하이며 다음 요청이 제한된 정리를 합니다. attempt의 owner는 Weak 참조여서
순환 보관을 피합니다.

64비트 구조체 크기는 Record112/Attempt56/Checked176/heap40/mapentry40/shard72
바이트였습니다. Arc/할당자·맵/heap 여유 공간과 공유 owner snapshot,2KiB 만료 hint는 별도입니다.
record당 약0.5–1KiB, 기본 약64–128MiB/최대 약0.5–1GiB의 구조적 추정이며
실측 RSS 상한이 아닙니다. 큰 과거 owner generation은 메모리를 더 사용합니다.
100000개 동시 record 기능 테스트는 조기 축출·용량·제한 정리를 검증하며 성능
벤치마크가 아닙니다.

이 임시 lookup은 인증 원천의 유효성만 나타내며 replay 소비가 아닙니다.
원천 record 만료/철회/정리가 durable paired replay 소비 기록의 보관 기간을
줄여서는 안 됩니다. 후속 Workload projection도 기존 signing-key/purpose/nonce
식별자와 전체 signed proof retention 상한을 공유해야 합니다.
