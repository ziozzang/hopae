# Kubernetes 워크로드 인증

<!-- translation-status: source=../KUBERNETES_WORKLOAD.md source-rev=1 status=current -->

[문서](README.md) · [English](../KUBERNETES_WORKLOAD.md)

네이티브 라이브러리 auth_gateway::kubernetes::Connector를 구현했습니다. Pod에
바인딩된 ServiceAccount JWT를 고정된 신뢰 Kubernetes TokenReview API로 검증합니다.
루트 프로필·HTTP/HOP1 dispatch·콘솔·receipt 발급·운영 활성화는 아직 연결하지
않았습니다. 오프라인 JWT 서명 검증기나 실제 클러스터 검증을 완료한 것은 아닙니다.

소유자는 HTTPS API origin, 기대 HTTPS issuer, cluster 식별자, workload audience,
1–1000ms 기한, CA 묶음과 별도 reviewer 자격증명을 제공합니다. Config에는 비밀값이
없습니다. 지정 CA만 신뢰하고 리다이렉트·환경 프록시는 사용하지 않습니다. endpoint는
/apis/authentication.k8s.io/v1/tokenreviews로 고정합니다. 클라이언트 JWT는 spec.token에,
reviewer는 Authorization 헤더에 전달합니다. reviewer는 TokenReview create만 필요한
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
신원을 바꿉니다. 근거는 서비스 범위와 토큰 만료/검증 완료 후 1초 중 이른 기한에
제한합니다. 토큰·Pod labels는 근거에 포함하지 않으며 신뢰 시각은 네이티브 호출자가
제공합니다. 결과 캐시는 없고 매 호출 TokenReview를 요청합니다. 풀 연결·최대 64개
요청을 사용하고 원천 오류 3건이면 취소 안전한 회로를 30초간 엽니다. 사용자 거절은
원천 실패가 아니며 reviewer 401/403·TLS/응답 형식/크기 오류·모순된 양성 증명은
원천 실패입니다. 인증 거절의 error 진단도 사용자 거절로 처리해 회로를 열지 않습니다.

네트워크·body 전체는 지정 기한과 응답 64 KiB로 제한합니다. 응답 bytes는 zeroize하며
API가 돌려주는 spec.token은 타입 파싱에서 무시합니다. 인증/응답 자료를 로깅하지
않습니다. reviewer·CA 변경은 소유자가 connector를 재컴파일하고 이전 것을 회수해야
합니다. 파일 자동 회전·프로필 revision fence는 후속 연계 대상입니다.

Kubernetes는 deletion pending 객체를 문서의 삭제 유예 동안 인정할 수 있습니다.
호패 근거 1초 제한이 API 원천의 이 창을 없애지는 않습니다. 조기 회수에는 별도
삭제/revision fence가 필요합니다. watch·장기 스트림 회수·품계 신원 연관 검증·프로필
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
