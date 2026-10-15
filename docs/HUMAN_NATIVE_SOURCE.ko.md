# 네이티브 Human source record (구현 후보)

이 추가 source는 실제 네이티브 Engine의 비공개 `Checked`와 고정 scope를 검증한 `human_request::Binding`만 받습니다. 제출된 identity·realm·서명 단독 증거·숫자 수명을 capability로 받지 않습니다. 실제 설정 signing key로 Human=1, 실제 AAL1 또는 TOTP AAL2, 사용자 권한 revision 및 승격 후 session credential generation을 서명합니다. `human1`은 실제 durable user/realm과 고정 issuer에서 나옵니다. 기존 Service/Workload 발급 경로는 유지합니다.

하나의 정확한 native Owner와 불변 publication에 묶입니다. publication 변경 시 새 source를 준비하고 이전 source를 retire해야 하며, 제출 generation으로 갱신하지 않습니다. 원래 Admission, 같은 Owner BOOTTIME 세대, 실제 Store/provider/material/session/user/factor/app current 및 readiness 검사가 필수입니다. 서명 만료와 관측 예산은 원래 수명의 교집합이며 ObserveTime으로 갱신하지 않습니다. 유효 서명이어도 정확한 로컬 record가 없으면 거부하며 독립된 빈 source instance도 마찬가지입니다. 분산 authority fencing 전까지 process에 종속된 증거입니다. Human RPC/listener 활성화나 Human/Root/Pum 전체 체인 완료는 이 모듈의 주장이 아닙니다.

`receipt_issuer.human_receipts`는 기본 미설정인 선택 항목입니다. `source_revision`, `capacity`, `retained_bytes`와 고정 scope를 지정합니다. scope에는 service/audience/application/route, route revision, 소문자 64자리 destination digest, header revision, 고정 header/reserved-header 이름 및 최대 entity bytes가 있습니다. issuer의 선언 service/audience에 속해야 하며 Service 인증 profile을 요구하지 않습니다. 기존 SDK는 실제 본문 최대 16 MiB를 해시하고 RPC는 metadata만 보내며 향후 native frame은 128 KiB 제한을 유지합니다.

count 기본 131,072, 최대 1,048,576입니다. 요청한 retained capacity 기본 256 MiB, 최대 16 GiB이며 native 크기 변환과 계산을 검사합니다. **두 제한을 모두 적용하므로** byte가 count보다 먼저 소진될 수 있습니다. 이 count는 수용량이나 처리량 보장이 아닙니다. record 소유 allocation capacity, 고정 context 예약, 준비된 scope/publication lease metadata를 한 번 계상합니다. 기존 불변 application/provider/DB/transport 기반과 allocator 부가 비용·단편화는 별도이며 RSS 제한을 주장하지 않습니다. 전체 설정을 record마다 곱하지 않고 raw cookie를 재구성하지 않으며 AppPolicy를 record마다 복사하지 않습니다.

256개 짧은 lock shard를 사용합니다. 각 shard record index와 expiry heap을 각각 `2 * ceil(capacity / 256)`개로 제한합니다. 최대 설정에서는 전체 record index 항목과 expiry entry가 각각 2,097,152개 이하입니다. 불투명한 HashMap/heap allocator 기반은 record byte quota와 별도입니다. 평상시 한 shard 만료 head 최대 8개를 정리하고 압박 시 최대 256 shard에서 각 8개만 검사하며 여유 확보 시 중단합니다. live 증거를 퇴출하지 않습니다. index에서 제거해도 외부 Arc가 보유한 record의 quota는 유지합니다. shard lock 안에서 SQL·서명·RNG·환경 조회·native callback을 실행하지 않습니다. 할당 증가는 실패를 처리하고 취소/실패 시 예약을 회수합니다.

최종 보고 metadata를 먼저 할당한 뒤 마지막 source clock을 읽고, 이후 계산 및 callback 없는 publication/key/source 검사만 합니다. RPC 응답 구성도 같은 최종 검사를 지켜야 합니다. 마지막 로컬 관측 이후 상태 변경까지 원자적으로 보장하거나 부하 검증 전 극단적 처리량 완료를 주장하지 않습니다. 실제 후보 테스트 실행 근거는 별도 private handoff에 기록합니다.

요청 capacity 계상은 보수적인 상한입니다. Checked/Binding inline이 Record와 중복 계상될 수 있고 Arc header/정렬 여유 및 고정 context 예약도 과대 계상할 수 있습니다. 정확한 allocator 배치나 RSS 측정이 아닙니다.

서명 key registry publication도 Source마다 한 번 고정합니다. registry가 바뀌면 이전 source 사용을 거부하고 새 source를 준비해야 합니다. record마다 서로 다른 이전 registry graph를 숨겨 보유하지 않습니다. HashMap의 실제 할당 bucket 수는 항목 수 제한보다 클 수 있으며 별도로 명시한 불투명 index 기반 비용에 속합니다.

독립 observation은 보존한 검증 Binding의 canonical `scope_sha256`도 반환합니다. service/audience와 요청 digest에 더해 정확한 application/route/destination/header policy를 인증하며, 공유 source revision만으로 이 범위를 증명하지 않습니다. RPC·SDK 통합은 이 필드를 필수로 검사해야 합니다.

최종 순수 제약 함수는 마지막 native SourceTime sample 자체를 받아 admission만 줄일 수 있습니다. 서명 expiry·보존 record·retention은 바꾸지 않습니다. 독립 query는 시계를 다시 읽지 않고 이 sample에서 원래의 sealed Admission과 교집합을 계산해야 합니다.

최종 observer는 마지막 source·key publication load 뒤에 callback 없는 native publication/readiness/retirement 검사를 반복합니다. 다른 observer가 동일한 retained Checked를 철회한 경우 앞서 시계를 읽었다는 이유로 이를 놓치지 않습니다. 이는 로컬 시점 검사이며 원격 철회를 원자적으로 보장하지 않습니다.

## 관리자 정책 식별자

네이티브 Human 증명을 설정하면 인증된 관리자 사용자 응답에서 지원되는 현재 계정의
`human_subject`를 조회할 수 있다. 상세 페이지와 호패 콘솔 패키지는 실제 네이티브 서명
증명에 쓰이는 동일 식별자를 표시한다. 설정 issuer·불변 Store realm·정확한 사용자 ID로
도출하며 이메일·세션·AAL·권한 부여 증명이 아니다. 비활성 계정도 식별자를 유지하지만
네이티브 인증 적격성 검사는 여전히 거부한다. 이 메타데이터 조회는 primary/factor
인증 이력을 확립하지 않는다.

목록은 최대 200개 계정을 한 번의 제한된 Store 쿼리로 조회하고 현재 사용자·ID 영구
예약·실제 realm을 결합한다. 행마다 DB를 질의하지 않는다. 지원하지 않는 기존 ID도
사용자 관리에 표시하되 Human 식별자만 생략한다. 정규화·절단·대체 신원을 만들지 않고
네이티브 증명 발급의 엄격한 조건은 유지한다. 관리자 API 질의로 issuer나 realm을
지정할 수 없다.
