# Workload observed 자격 증명 출력 (contract3)

이 경로는 명시적으로 활성화한 Workload 전용 경로입니다. 실제 Native TokenReview
인증과 별도의 Pum Workload 권한 관측, 기존 정확한 credential plan이 모두 있어야
최종 요청에 바인딩된 credential을 반환합니다. 인증만으로 자원 권한이나 credential을
부여하지 않습니다. 기존 Service strict/observed 엔드포인트는 kind2 전용이며,
Workload는 kind3/AAL0와 contract3만 받습니다. Service·UTC fallback은 없습니다.

## 활성화

유일한 출력 활성화 모델은 `projection_receiver.workload_observed_scopes`입니다.
기본값은 빈 목록이고 이때 Workload projection RPC를 등록하지 않습니다.
각 `{service,audience}`는 고유해야 하며, Native issuer의
`workload_receipts.scopes`와 기존 AAL0 허용 plan에 정확히 속해야 합니다.
명시적인 유효 `observed_clock_rates`와 인증된 mTLS gateway 설정도 필요합니다.
알 수 없는 scope·중복·미완성 의존성은 시작 검증에서 거부합니다.
기존 Service plan과 기본 활성화 의미는 그대로입니다.

```json
{
  "projection_receiver": {
    "authority": {
      "address": "https://pumgye.example.test:443",
      "server_name": "pumgye.example.test",
      "ca": "/etc/owned/pumgye-ca.pem",
      "certificate": "/etc/owned/hopae-client.pem",
      "key": "/etc/owned/hopae-client.key",
      "token_env": "OWNED_PUM_CALLER"
    },
    "observed_clock_rates": {"source_ppm": 500, "receiver_ppm": 500},
    "workload_observed_scopes": [{"service": "orders", "audience": "orders-api"}],
    "secrets": [{"reference": "vault:orders", "token_env": "OWNED_ORIGIN"}]
  }
}
```

이는 완전한 Native 설정에 추가하는 예시입니다. 예약 예시 경로와 환경변수 참조만
포함하며 실제 비밀값을 넣지 않습니다. Native TokenReview의 cluster와 profile realm이
일치해야 하며 issuer·권한 키·plan 설정도 별도로 필요합니다.

## 검증·시간·재생 방지

외부 projection ID는 원본 `permission_query`의 최상위 validation ID와 같아야 합니다.
내부 native request/permit ID는 원래 발급 ID를 유지합니다. 원본 query 바이트의 SHA256을
출력에 바인딩하며 재인코드 강제나 새로운 protobuf canonical 제약은 추가하지 않습니다.
두 proof의 kind3/AAL0·wobs1·subject·세대·scope·최종 요청 hash, authentication SHA와
resource/action/route/plan 제약을 모두 확인합니다.

실제 로컬 Workload Record와 고정된 Pum Workload Observe 응답이 필요합니다. 서명이
유효해도 원천 레코드가 없거나 만료·퇴역·새 owner로 바뀌면 거부합니다. pobs1 domain,
proof SHA, 전체 서명 보존용 proof_remaining과 별도 허용 remaining 및 세대들을 확인합니다.
공개 숫자 TTL·서명·allow flag로 capability를 만드는 API는 없습니다.

TokenReview 전의 원래 최대1초 예산을 갱신하지 않습니다. 각 독립 시계는 호출 전
실제 BOOTTIME anchor와 기존 오차·양자 산술로 로컬 만료에 변환합니다. 서로 다른
절대 시각을 비교하거나 UTC로 바꾸지 않습니다. 허용 remaining0은 거부하며 TTL0은
lease가 아닙니다. 지연으로 보수적 허용 구간이 없어지면 예산을 늘리지 않고 거부합니다.

Service/Workload는 동일한 기존 paired DB transaction·replay key·IDS/COUNT를 씁니다.
nonce ID에 kind·RPC·contract 번호·원천 cache를 넣어 재사용 공간을 만들지 않습니다.
두 nonce의 전체 서명 보존 상한과 짧은 허용 하한은 분리하며, 원천 cache 정리가 ledger
소비 기록을 지우지 않습니다. 늦은 출력 실패로 이미 소비한 nonce를 되돌리지 않습니다.

## 마지막 출력 경계

Service와 Workload observed 출력은 공통 private finalizer를 사용합니다. 응답 문자열·
hash·domain·보류 비밀 바이트를 먼저 할당하고, 마지막 caller/원천 guard·시간·순수 owner
검사를 끝낸 뒤 숫자 report와 바이트 이동만 수행합니다. 실패한 보류 비밀 버퍼는
zeroizing이며 불투명 출력에는 Clone/Debug/serde가 없습니다. RPC 비밀 Debug도 가립니다.
worker 취소·콜백 중 profile/app/plan/key 철회·만료는 출력으로 이어지지 않습니다.

이 결과는 원격 철회 lease나 원격 바이트 회수를 보장하지 않습니다. Root는 독립된
인증·권한·출력 만료와 기존 TLS 아래의 최종 전송 guard를 유지해야 합니다.

## 검증 범위

실제 로컬 TLS TokenReview 모의 API→제품 Native 인증→mTLS contract3 출력→SQL paired
ledger를 검사하며, Pum Observe는 소유한 typed 서명 fixture입니다. 실제 Pum 정책 평가를
완료했다는 뜻은 아닙니다. 실제 Kubernetes JWT·OS프로세스 재시작·Root backend 전체
체인은 후속 통합 게이트이며 같은 OS프로세스의 새 서버 인스턴스와 구분합니다.
기능 통과는 처리량·pooling 완료를 의미하지 않습니다.

Pum 의존성은 immutable `dd62d6559613923f421cb76f0e65aea48224ea76`이며 해당 wire SDK는
Hop `4ea3e1473de61d6b46f5420efe481c126790d800`입니다. 미커밋 경로 의존성은 없습니다.
