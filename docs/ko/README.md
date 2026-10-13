# 문서

<!-- translation-status: source=../README.md source-rev=8 status=current -->

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
- [배포 템플릿](../../deploy/README.md) — 강화된 Docker Compose 서비스와 게이트웨이 라우트 예시

그 밖의 참조 문서(제공자, 세션, 관리)는 마일스톤이 완료될 때마다
추가됩니다. [로드맵](ROADMAP.md)이 의도한 형태를 설명합니다.

- [Hangang 네이티브 통합](HANGANG_NATIVE.md) — HOP1 검증과 콘솔 위임.

- [인증 프로필 게시](AUTH_PROFILE_PUBLICATION.md) — 영속 소유권과 스냅샷 게시 제안 계약.

- [LDAP 인증](LDAP_AUTHENTICATION.md) — 직접 자격 검증 provider와 수명주기 제안 계약.
