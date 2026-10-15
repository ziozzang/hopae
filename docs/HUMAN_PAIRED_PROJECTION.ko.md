# 네이티브 Human paired projection 기반

이 후보는 H4의 비공개 native current 검사와 Store writer 기반입니다. Human projection RPC를 등록하거나 Human credential 전체 체인을 검증한 상태가 아닙니다.

`SnapshotCheck`는 기존 joined handle/session/user/provider/realm, primary material, TOTP provenance, 수명·step-up 비교를 유지합니다. 기존 비동기 native read도 동일한 expected facts를 준비해 원래 checked read 트랜잭션에서 비교합니다. application policy는 실제 불변 publication Arc와 비공개 O(1) locator로 보존하며 AppPolicy 전체를 복사하지 않습니다.

실제로 보존한 native `Checked`만 `ProjectionCurrent`를 준비합니다. native sample 전에 시스템의 suspend-aware elapsed clock을 고정합니다. 반복 검사는 원래 sample을 ceiling·quantum을 포함해 보수적으로 진행시킬 뿐, 원래 admission이나 native expiry를 갱신하지 않습니다. writer 안에서 wall·caller metric·network·Owner 테스트 clock callback을 호출하지 않습니다. 시계 읽기 실패·역행, owner/readiness/publication 철회 또는 durable 비교 실패는 해당 check와 capture를 영구 거부합니다.

`Store::human_ledger`는 기존 native Store writer에 작업을 보냅니다. 요청이 연결을 선택하거나 바꿀 수 없는 sealed Ledger와, 정확한 Store를 트랜잭션 guard에 구조적으로 묶는 읽기 전용 LedgerSnapshot을 제공합니다. ProjectionCurrent는 스키마가 같더라도 다른 Store를 거부합니다. 기존 canonical `consume_observed_pair`에 위임하며 별도 replay 테이블·알고리즘·class namespace를 만들지 않습니다. wrapper의 중첩 트랜잭션도 없습니다. 후속 H4 operation은 취소·만료 fence를 보존해 공통 pair 트랜잭션의 commit 전에 확인해야 합니다. commit 후 취소는 pair를 소모한 상태이며 rollback이나 secret 재전송을 보장하지 않습니다.

H4 orchestration, 실제 Source Arc 공유, typed Pum Human permit observation, 기본 비활성 scope, 원래 predecode query 교집합, 최종 비동기 native 검사와 실제 credential/replay endpoint는 후속 구현 gate입니다. 로컬 native check로 public SDK Observation을 위조하지 않습니다. H3는 인증된 scope 지문을 포함해 실제 native source를 public Human SDK로 독립 검증해야 합니다. 단일 signed final H1v2 digest를 체인 전체에서 동일하게 유지하며 digest를 다시 묶지 않습니다.
