# Kubernetes 워크로드 인증

<!-- translation-status: source=../KUBERNETES_WORKLOAD.md source-rev=5 status=current -->

[문서](README.md) · [English](../KUBERNETES_WORKLOAD.md)

네이티브 라이브러리 auth_gateway::kubernetes::Connector를 구현했습니다. Pod에
바인딩된 ServiceAccount JWT를 고정된 신뢰 Kubernetes TokenReview API로 검증합니다.
참조형 루트/프로필 설정·HTTP/HOP1 dispatch·콘솔 요약은 연결했습니다.
워크로드 receipt 발급·실제 클러스터 운영 활성화는 아직 남았습니다. 오프라인 JWT 서명 검증기는 아닙니다. 소유 실제 API 검증은 아래에 기록했습니다.

소유자는 HTTPS API origin, 기대 HTTPS issuer, cluster 식별자, workload audience,
1–1000ms 기한, CA 묶음과 별도 reviewer 자격증명을 제공합니다. Config에는 비밀값이
없습니다. 지정 CA만 신뢰하고 리다이렉트·환경 프록시는 사용하지 않습니다. endpoint는
/apis/authentication.k8s.io/v1/tokenreviews로 고정합니다. 클라이언트 JWT는 spec.token에,
reviewer는 Authorization 헤더에 전달합니다. reviewer는 TokenReview create와 namespace 범위 Pod/ServiceAccount metadata get의
최소 권한으로 구성하고 workload Secret이나 임의 Role/Binding 쓰기를 부여하지 않습니다.
TokenReview API 인가는 앱 정책과 별개입니다.

JWT 파싱은 거절을 위한 사전 검사이며 인증이 아닙니다. 허용 알고리즘 식별자·issuer/
audience·만료·선택적 nbf·ServiceAccount namespace/name/UID·Pod name/UID를 요구합니다.
구형 무기한/unbound 및 Pod 외 바인딩은 미지원입니다. 신뢰 API가 원래 토큰을
인증하고 사용자명·ServiceAccount UID·audience·user.extra의 정확한 Pod name/UID를
반환해야 근거를 만듭니다. 실제 서명과 객체 존재는 API가 검증합니다. Node 정보는
검증된 신원으로 주장하지 않습니다. 선택한 클러스터 버전·authenticator의 Pod extra
지원은 실제 환경에서 확인해야 합니다.

신원 종류는 Workload이며 사람 MFA 등급을 만들지 않습니다. issuer와 cluster로
네임스페이스를 나누고 길이 구분 SHA-256으로 namespace·서비스 계정 name/UID·Pod
name/UID를 묶은 뒤 기존 stable-subject 변환을 적용합니다. 동명 객체 재생성은
신원을 바꿉니다. 근거는 서비스 범위와 토큰 만료/인증 시작 후 1초 중 이른 기한에
제한합니다. 토큰·Pod labels는 근거에 포함하지 않으며 신뢰 시각은 네이티브 호출자가
제공합니다. 결과 캐시는 없고 매 호출 TokenReview를 요청합니다. 풀 연결·최대 64개
요청을 사용하고 원천 오류 3건이면 취소 안전한 회로를 30초간 엽니다. 사용자 거절은
원천 실패가 아니며 reviewer 401/403·TLS/응답 형식/크기 오류·모순된 양성 증명은
원천 실패입니다. 인증 거절의 error 진단도 사용자 거절로 처리해 회로를 열지 않습니다.

네트워크·body 전체는 지정 기한과 응답 64 KiB로 제한합니다. 응답 bytes는 zeroize하며
API가 돌려주는 spec.token은 타입 파싱에서 무시합니다. 인증/응답 자료를 로깅하지
않습니다. reviewer·CA 변경은 소유자가 connector를 재컴파일하고 이전 것을 회수해야
합니다. 연결 설정·실제 CA/reviewer 값·접두사·서비스/realm이 모두 같을 때만
기존 원천 회로를 재사용합니다. 파일 자동 회전은 남았고, 프로필 게시 snapshot
fence로 회수 중인 HTTP/HOP1 결과는 거절합니다.

Kubernetes는 deletion pending 객체를 문서의 삭제 유예 동안 인정할 수 있습니다.
호패 근거 1초 제한이 API 원천의 이 창을 없애지는 않습니다. 현재 객체 검사로 조기 바인딩 객체 회수를 보완하며 watch 기반 삭제/revision
fence는 남았습니다. watch·장기 스트림 회수·품계 신원 연관 검증·프로필
수명주기·전체 경로 성능을 운영 활성화 전에 검증해야 합니다.

```sh
cargo test --locked --lib auth_gateway::kubernetes
cargo build --locked --example qualify_kubernetes_tokenreview
python3 tools/kubernetes_tokenreview_smoke.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview
```

소유 HTTPS mock은 reviewer/사용자 토큰 분리·신원 불일치·클러스터 격리·응답 제한·
CA/프록시/리다이렉트 거절·회로 차단을 검증합니다. 가상 토큰을 사용하므로 실제 API
서버의 서명/삭제 동작을 검증한 것이 아닙니다. 공식 근거 링크는 대응 영문 문서에 있습니다.

## 네이티브 프로필과 HTTP/HOP1

kubernetes_tokenreview 프로필을 자체 키·API relay와 함께 설정할 수 있습니다.
CA PEM·reviewer는 별도 네이티브 환경 참조이며 owner 문서/UI에 값을 넣지 않습니다.
참조형 JSON 예제는 다음과 같습니다.

```json
{
  "kubernetes_tokenreview": {
    "connection": {
      "api_origin": "https://kubernetes.example.test/",
      "issuer": "https://issuer.example.test",
      "cluster_id": "example-cluster",
      "audience": "orders-workload",
      "namespaces": ["blue"],
      "timeout_ms": 500
    },
    "ca_pem_env": "HOPAE_KUBERNETES_CA_PEM",
    "reviewer_token_env": "HOPAE_KUBERNETES_REVIEWER",
    "token_prefix": "k8s:"
  }
}
```

profile realm은 cluster_id와
같아야 합니다. 필수 2–32자 접두사는 :로 끝나며 표시된 토큰만 TokenReview로 보내고
API 요청 전에 접두사를 제거합니다. 자체 키가 해당 접두사를 차지할 수 없고 relay를
혼합하면 다른 명시적 접두사가 필요합니다. 미표시·잘못된·실패한 Kubernetes 자격은
다른 원천으로 전달하지 않습니다. 네트워크 조건을 원격 호출 전에 검사하고 선택적
제한 Lua 조건을 이후 적용합니다. 접두사를 포함한 전체 자격은 최대 4096 bytes,
바인딩 신원 식별자는 최대 128자입니다.

HTTP/HOP1은 같은 런타임·게시 fence·현재 앱 step-up 검사를 사용합니다. workload,
서비스·정규 native subject·AAL 0을 반환하고 기계 근거로 사람 step-up을 만족하지
않습니다. 한강의 신뢰 네이티브 호패→품계 파서는 workload AAL 0만 허용하고 사람
등급·비정규 subject·중복 metadata·network 단독 신원을 거절합니다. 콘솔 0.1.7은
TokenReview·issuer·cluster·audience·허용 namespace·접두사를 기존 owner 편집/게시 경로와 함께 표시합니다.
HTML처럼 보이는 값도 text이며 viewer는 읽기 전용입니다.

소유 HTTPS/HTTP/HOP1 시나리오는 자체/워크로드 혼합, 자격 라우팅 격리, 원천/사용자
오류 구분, 사람 step-up 거절, 원격 TokenReview 대기 중 프로필 회수를 검증합니다.
TLS 원천은 mock입니다. 실제 클러스터 서명/삭제·분산 fence·장기 스트림 신원 회수·
품계 매핑 권한·워크로드 receipt·전체 성능 검증이 남았습니다. 컴파일된 기능을 배포해도
내부 운영 프로필은 native-only로 유지할 수 있습니다.

## 현재 바인딩 객체 검사와 실제 API 검증

connection.namespaces는 필수이며 서로 다른 DNS-label namespace 1–128개를 지정합니다.
원격 호출 전에 검사하고 다른 namespace는 사용자 거절로 처리합니다. 실제 음성
TokenReview는 authenticated/audiences를 생략하고 user:{}를 반환할 수 있으며 error 진단이
있어도 원천 장애가 아닙니다. 비어 있거나 모순된 양성 user는 원천 오류입니다.

성공 review 뒤 같은 CA/API/전체 기한으로 ServiceAccount·Pod PartialObjectMetadata를
인증된 GET으로 확인합니다. 각각 16 KiB 제한이며 전체 Pod spec·Secret은 읽지 않습니다.
누락·UID/name/namespace 변경·null이 아닌 deletionTimestamp는 즉시 거절하고 통신/권한/
형식 오류는 거절하며 원천 회로에 반영합니다. 반환 전에 바인딩 사실을 확인하고 lease는
인증 시작부터 1초에 제한합니다. native metadata 조회이며 고속 watch 인덱스는 아닙니다.

소유 kind Kubernetes v1.37.0에서 TokenReview만 쓸 때 Pod 삭제 전파가 약 9.8초였고
현재 객체 검사 후 동일한 강제 삭제 fixture는 약 0.12초에 회수됐습니다. fixture 관찰이며
fleet 지연 보장이 아닙니다. 실제 서명·서명 변조·issuer/audience/namespace·unbound 거절·
reviewer 최소 권한·Pod/ServiceAccount 삭제·동명 Pod 재생성을 검증했습니다. 정상 종료·
분할·스트림·다른 클러스터 버전은 배포 검증이 남습니다. 근거 1초 자체가 원천 캐시를
제한하지 않으며 metadata 검사가 바인딩 객체 회수를 보완합니다.

```sh
python3 tools/kubernetes_real_cluster.py \
  --driver target/debug/examples/qualify_kubernetes_tokenreview \
  --state-dir /private/owned-kind-qualification
```

도구는 고정된 소유 kind 클러스터·비공개 kubeconfig에 제한하며 고유 fixture namespace/
RBAC를 만들고 제거합니다. 자격은 출력·인자에 넣지 않습니다. Python PyYAML·클러스터
내 kubectl이 필요하고 운영 설정은 바꾸지 않습니다.

기존 workload 설정은 업그레이드 전에 connection.namespaces를 명시해야 합니다.
누락 시 다른 namespace를 허용하는 대신 시작을 거절합니다. Kubernetes RBAC는
metadata 전용 권한이 아닌 객체 GET을 인가합니다. 네이티브는 partial metadata만
요청하지만 reviewer 권한은 Pod/ServiceAccount GET으로 검토해야 합니다.


## 네이티브 인증 근거 유효기간

HTTP·HOP1의 기계 인증 응답은 x-hopae-evidence-ttl-ms로 응답 생성 시 남은
검증 근거 수명을 최대 1000ms로 전달합니다. 만료된 근거는 신원 헤더 없이 503을
반환합니다. 인증된 응답 메타데이터이며 판단 캐시·서명 receipt·클라이언트 인증
주장이 아닙니다. 한강은 교환 시작 시각에 묶어 통신/처리 시간이 수명을 늘리지
않도록 합니다. 향후 인증된 갱신/구독으로 근거를 교체하지 않는다면 서비스·워크로드
스트림도 기한에 종료해야 합니다.

초기 구현은 인증 후 최대 1초에 회수 poll 스케줄링 간격을 더한 시점에 장기 기계
스트림을 닫습니다. 한강은 이제
auth.renew_native_evidence로 선택형 네이티브 재인증을 제공합니다. 명시적 유효 TTL과
같은 신원/종류/AAL/service가 필요하며 실패·늦은 갱신은 거절합니다. 개별 자격 회수
구독과 실제 클러스터 원천의 지속 가용성은 미구현입니다. 이번 수명 검증은
기존 운영 이미지를 전환하지 않으며 장기 워크로드 인증 완료를 의미하지 않습니다.
