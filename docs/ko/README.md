# 문서

<!-- translation-status: source=../README.md source-rev=14 status=current -->

[English](../README.md)

영어가 기준 언어입니다. `ko/` 아래의 한국어 문서는 영문 원문의 완역이며, 같은
변경에서 함께 갱신합니다. [프로젝트 README](../../README.ko.md)에 제품의 목적과
상태가 있습니다.

## 프로젝트

- [개발 프로세스](PROCESS.md) — 역할, 단계 게이트, 적대적 검토, 시나리오 기반 TDD, 릴리스, 보안 규칙
- [문서 체계](DOCUMENTATION.md) — 구성, 언어 규칙, 문체 지침, 필수 문서, 검증
- [로드맵](ROADMAP.md) — 제품 형태, 마일스톤, 시나리오 번호 범위
- [아키텍처 결정 기록 · 영문](../adr/) — 번호가 붙은 결정. [ADR-0001](../adr/0001-record-architecture-decisions.md)부터 시작합니다.
- [시나리오 명세 · 영문](../../scenarios/README.md) — 번호 체계, 상태, 테스트 이름 규칙
- [변경 이력 · 영문](../../CHANGELOG.md)

## 제품

- [아키텍처](ARCHITECTURE.md) — 구성 요소, 신뢰 경계, 요청 흐름, 데이터 모델, 저장소, 크레이트 구조, 장애 시 동작
- [게이트웨이 계약](GATEWAY_CONTRACT.md) — 버전이 붙은 verify 프로토콜, 신원 헤더, 쿠키, 핸드오프, 캐시와 무효화 의미론, 제안하는 게이트웨이 변경
- [위협 모델](THREAT_MODEL.md) — 자산, 행위자, 진입점, 흐름별 STRIDE, 완화책
- [설정 참조](CONFIG.md) — 모든 키, 기본값, 제약, 명령줄과 종료 코드
- [운영](OPERATIONS.md) — 실행, 상태 디렉터리, 인스턴스 잠금, 백업, 키 교체, 로그, 상태 확인, 카운터, 장애 동작
- [관리](ADMIN.md) — 관리 콘솔과 `/v1` API(M4-min, 명세됨): 콘솔 호스트와 라우트, 부여와 역할, 페이지, 엔드포인트, 감사 이벤트, 제한
- [주체 디렉터리](SUBJECT_DIRECTORY.md) — 콘솔과 정책 기관을 위한 주체 해석, 검색, 생명주기 피드, 대조 스냅숏
- [그룹](GROUPS.md) — 로컬·LDAP·OIDC 그룹, 제공자 동기화 규칙, 그룹 API, Pumgye를 위한 서명된 멤버십 투영
- [서비스 자격 증명](SERVICE_CREDENTIALS.md) — 관리 리스너의 기계 호출자를 위한 경로 범위·읽기 전용·mTLS 바인딩 자격 증명(Pumgye 정책 v2)
- [인증 설명](AUTHENTICATION_EXPLAIN.md) — URL과 주체에 대해 인증 검사가 무엇을 왜 답할지, 부작용 없이
- [배포 템플릿](../../deploy/README.md) — 강화된 Docker Compose 서비스와 게이트웨이 라우트 예시

그 밖의 참조 문서(제공자, 세션, 관리)는 마일스톤이 완료될 때마다
추가됩니다. [로드맵](ROADMAP.md)이 의도한 형태를 설명합니다.

- [Hangang 네이티브 통합](HANGANG_NATIVE.md) — HOP1 검증과 콘솔 위임.

- [인증 프로필 게시](AUTH_PROFILE_PUBLICATION.md) — 영속 소유권과 스냅샷 게시 제안 계약.

- [LDAP 인증](LDAP_AUTHENTICATION.md) — 직접 자격 검증 provider와 수명주기 제안 계약.

- [2차 인증 확장](SECOND_FACTOR_EXTENSIONS.md) — 네이티브 OTP와 외부 API·Lua 경계.

- [WebAuthn 패스키](WEBAUTHN.md) — 포털 패스키 등록, 단계 상승, 관리, 복구 코드(기본값 꺼짐).

- [Kubernetes 워크로드 인증](KUBERNETES_WORKLOAD.md) — 네이티브 Pod-bound TokenReview 연결기; 프로필·전송 연계 예정.

- [네이티브 관측형 paired projection](OBSERVED_PROJECTION.md) — 명시적 소스 시계 예산, 원자적 재생 방지와 재시작 보존.

- [Workload observed 프로토콜 선언](WORKLOAD_OBSERVED_PROTOCOL.md) — additive RPC/epoch와 갱신 불가 원천/replay 계약, 서버 활성화 제외.

- [네이티브 Workload receipt owner](WORKLOAD_NATIVE_OWNER.md) — 선택적 실제 발급/관측, 후속 Workload 체인은 별도 게이트.
- [Workload observed 자격 증명 출력](WORKLOAD_OBSERVED_PROJECTION.md) — 명시적 출력 scope·contract3·공유 paired replay와 통합 한계.
