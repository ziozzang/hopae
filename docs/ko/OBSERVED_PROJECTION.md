# 네이티브 관측형 paired projection

<!-- translation-status: source=../OBSERVED_PROJECTION.md source-rev=1 status=current -->

[문서 목차](README.md) · [English](../OBSERVED_PROJECTION.md)

관측형 경로는 기존 경로에 추가된다. 엄격 시간 `CredentialProjection.Project`,
계약 1, UTC 원장 의미는 별도로 유지한다. 관측형 계약 2는
`ObservedCredentialProjection.Project` 서비스와 `permission_query`의 정확하고
크기가 제한된 Pumgye `PermitValidationRequest` 바이트를 사용한다. 응답의
`chain_sha256`은 허용된 protobuf 미지 필드를 포함한 정확한 바이트의 SHA-256이다.
디코딩·재인코딩 정규화는 하지 않는다.

기존 고정 mTLS `projection_receiver.authority`와 함께
`projection_receiver.observed_clock_rates`를 명시적으로 설정한다. 예:

```yaml
projection_receiver:
  observed_clock_rates:
    source_ppm: 500
    receiver_ppm: 500
```

이 값은 운영자가 성립시킨 Pumgye 소스와 Hopae 수신자의 물리적 오차 한계이며,
각각 1,000,000 ppm 미만이어야 한다. 자동으로 검증한 하드웨어 측정값은 아니다.
설정이 없으면 엄격 경로는 유지하고 관측형은 permit 질의나 자격증명 해석 전에
거부한다. 같은 프로세스의 Hopae 인증은 진행하는 소스와 수신자가 같은 호스트의
BOOTTIME 백엔드를 공유하므로 동일 속도 변환을 쓴다. UTC 전진은 인증 소스를
앞당겨 허용을 거부하거나 줄일 수만 있다.

Hopae는 먼저 정확한 발급 인증 시계 도메인과 실제 현재 프로필·애플리케이션·키
소유자를 검사한다. 봉인된 로컬 인증 관측은 원래 수신자 기한을 유지한다. 영속적인
고정 네이티브 Pumgye 클라이언트는 수신자 소유 키로 permit 서명을 검증하고,
새 RPC 상관값으로 mTLS `ObservedProjectionPermits.Observe`를 호출하여 서명된
Pumgye 도메인·해시·전체 서명 잔여 기간·소유자 revision을 검사한다. 호출자가 제공한
보고서나 런타임 숫자 경계로 네이티브 projection admission을 생성할 수 없다.
직접 SQL fixture의 숫자 보고서 조립은 테스트에서만 허용한다.

실제 네이티브 plan 소유자는 두 nonce 예약과 함께 하나의 SQLite Immediate
트랜잭션에서 자격증명을 해석한다. 서명·레지스트리 증거는 관측 시간과 분리한다.
트랜잭션은 작업 전후에 불변 소유자 세대와 레지스트리 내용을 검사한다. 커밋 전
fence가 취소·기한 만료·콜백 실패·비밀값 실패·레지스트리 변경을 관측하면 두 예약과
소유자 작업을 롤백한다.
커밋한 결과는 응답 유실이나 최종 출력 거부가 발생해도 소비 상태를 유지한다.
보호된 출력에는 독립된 `hproj1:<32자리 소문자 hex 시작 세대>` 시계 식별자가 있다.
기간은 자격증명 처리와 최종 콜백 후 실제 BOOTTIME 잔여 예산을 내림한 값이다.
인증과 permit의 절대 만료 좌표를 최솟값으로 비교하지 않는다. Root는 RPC 전후
구간을 사용하여 이 보고서와 원래 전제조건 기한을 교차하고 dispatch 소유권을
다시 검사해야 한다.

## 영속 재생 방지 저장소와 재시작

두 모드는 정확히 같은 기존 재생 식별자를 사용한다. v1 소비 도메인 구분자,
issuer 길이와 바이트, 증명 purpose, nonce를 SHA-256으로 해시한다. 모드 접두사는
없다. `projection_nonce_id:`와 용량 카운터를 공유하므로 어댑터 전환으로 같은
nonce를 두 번 소비할 수 없다.

엄격 행은 UTC 숫자값과 기존 만료 인덱스를 유지한다. 관측형 행은 미지 필드를
거부하는 v2 JSON에 수신자 세대·전체 서명 보존 tick·소스 도메인을 저장하고,
별도의 세대별 정렬 만료 인덱스를 사용한다. 정리는 트랜잭션마다 최대 128개만
삭제하며 정확히 같은 수신자 인스턴스의 BOOTTIME tick만 사용한다. 짧아진 허용
또는 전제조건 예산은 각 증명의 전체 서명 재생 보존 기간을 줄이지 못한다. UTC나
소스 시계 전진은 관측형 행을 정리하지 않는다.

수신자 재시작 후 알 수 없는 이전 수신자 세대의 행은 무기한 tombstone으로
유지한다. 이전 숫자 tick을 새 세대와 비교하지 않는다. 시작 대기·임의 유예·추정한
도메인 폐기·시계 초기화 정리는 없다. 알 수 없는 세대의 tombstone을 포함하여
용량이 고갈되면 닫힌 상태로 거부한다. 운영자 조정에는 별도로 성립시킨 명시적인
소스 폐기·소유권 증명이 필요하며 여기서는 그러한 조정 API를 제공하지 않는다.
인증 소스와 projection 소유자는 정확히 같은 발급 런타임이어야 한다. DB 유실·
롤백, 살아 있는 소스 세대 복제, 복제된 소유자의 동시 실행, VM 복원은 검증된
복구 작업이 아니다. 서비스를 복원하기 전에 이전 소유자를 중단·차단하고 발급
도메인을 회전해야 한다. 임의 세대 생성만으로 복제나 롤백을 탐지하지는 못한다.

## 검증 범위

네이티브 SQL 테스트는 독립 소스 오프셋, paired replay, 모드 간 식별자, 롤백,
비밀값 실패, 응답 유실, 짧아진 허용과 전체 보존의 구분, UTC 전진 정리 격리,
알 수 없는 세대의 재시작 보존, 용량 거부, 최종 출력 만료·폐기를 검증한다.
생성된 mTLS fixture는 실제 Hopae identity·key·plan 소유자, 네이티브 SQL,
관측형 projection RPC를 사용하며 Pumgye 소스 peer만 프로토콜 fixture이다.
전체 4프로세스 릴리스 검증과 복원·복제 검증은 이 테스트들과 별도이다.
