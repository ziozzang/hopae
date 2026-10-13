# Hopae

<!-- translation-status: source=README.md source-rev=6 status=current -->

[문서 목차](docs/ko/README.md) · [로드맵](docs/ko/ROADMAP.md) · [릴리스 노트](CHANGELOG.md) · [English](README.md)

**제로 트러스트 게이트웨이를 위한 단일 바이너리 ID 제공자(identity provider)입니다. Rust로 작성했습니다.**

Hopae(호패)라는 이름은 조선시대에 국가가 발급한 신분패에서 따왔습니다. OAuth/OIDC
제공자나 이메일로 사용자를 로그인시키고, 세션을 유지하며, 게이트웨이의 "이 요청은
누구의 것인가?"라는 질문에 답해 게이트웨이가 검증된 신원 정보를 업스트림 요청에
주입할 수 있게 합니다. [Hangang](https://github.com/ziozzang/hangang)
게이트웨이의 외부 인증 확인(external authentication check)을 중심으로
패키징하며, 그런 확인 요청을 전달할 수 있는 어떤 게이트웨이 뒤에서도 사용할 수
있도록 유지합니다.

> **상태: 마일스톤 M1(수직 슬라이스)과 M4-min 관리 콘솔(사용 가능), 미릴리스.**
> 버전 0.1.0은 아직 발행하지 않았습니다. 현재 동작하는 범위는
> [현재 동작하는 것](#현재-동작하는-것)에, [아직 없는 것](#아직-없는-것)은
> 설계일 뿐입니다. [로드맵](docs/ko/ROADMAP.md)을 참고하세요.

## 동작 흐름

1. 브라우저가 세션 없이 게이트웨이의 보호된 라우트를 요청합니다.
2. 게이트웨이의 포워드 인증 확인이 Hopae에 묻고, Hopae는 자체 호스트에서
   동작하는 로그인 포털로 리디렉션하라고 답합니다. 이 포털 역시 같은 게이트웨이의
   라우트 하나입니다.
3. 사용자가 제공자나 이메일로 로그인하면 Hopae가 세션을 만들고 애플리케이션으로
   되돌려 보냅니다.
4. 이후 모든 요청마다 게이트웨이가 다시 Hopae에 묻고, 검증된 신원 헤더를 받아
   업스트림 요청에 주입하며, 클라이언트가 보낸 복사본은 제거합니다.

표준 OAuth 배포와 거의 같지만, 라우팅과 헤더 주입·제거는 게이트웨이가 이미
맡고 있으므로 Hopae는 포털, 제공자, 세션, 정책만 제공합니다.

## 현재 동작하는 것

기반은 완결된 경로 하나입니다. **Google 로그인, 서버 측 세션, Hangang 포워드
인증**이며, 그 위에 최소한의 관리 콘솔이 있습니다.

- **로그인** — Google에 대한 OpenID Connect(PKCE를 쓰는 인가 코드 흐름, ID 토큰 검증, 디스커버리와 키 캐시). 제공자는 JSON 설정 파일에 정의합니다. 비밀 값 변수가 없는 제공자는 치명적 오류가 아니라 비활성화됩니다.
- **세션** — SQLite에 저장하는 서버 측 세션, 브라우저에 묶인 호스트별 핸들 쿠키, 애플리케이션별로 설정 가능한 유휴·절대 타이머와 클라이언트 IP/User-Agent 바인딩, 로그아웃, 검증된 이메일에 의한 명시적 계정 연결.
- **게이트웨이 연동** — [게이트웨이 계약](docs/ko/GATEWAY_CONTRACT.md)의 verify 엔드포인트(`/_hopae/verify`). 로테이션이 가능한 호출자 키 인증, 실패 시 차단(fail closed) 응답, 게이트웨이가 주입할 신원 헤더, 브라우저에 묶인 핸드오프를 통한 등록된 호스트 간 교차 도메인 SSO.
- **운영** — `hopae --check` 사전 점검(등록할 라우트 조각과 redirect URI를 출력), 단일 인스턴스 잠금, 스키마 마이그레이션 전 백업, 우아한 종료, 트랜잭션 방식 감사 이벤트를 갖춘 구조화 이벤트 로그, `/healthz`. [운영](docs/ko/OPERATIONS.md)을 참고하세요.
- **관리 콘솔(M4-min)** — 자체 보호 게이트웨이 라우트를 통해 접근하는 선택적 세 번째 리스너. 사용자 목록·검색, 사용자 비활성화·활성화, 세션 하나 또는 전부 종료, 로그인 기록과 감사 기록 조회, 애플리케이션·제공자·저장소·빌드 상태 확인을 위한 페이지와 JSON API를 제공합니다. 관리자는 `hopae admin grant` 또는 `admin.users[]`로 부여합니다. 콘솔 신선도는 제공자가 지원하면 제공자가 검증하는 재인증이고, 그렇지 않으면(Google) Hopae 로그인 경과 시간입니다. [관리](docs/ko/ADMIN.md)를 참고하세요.
- **패키징** — 정적 바이너리와 [`deploy/`](deploy/)의 강화된 Docker Compose 템플릿.

운영 환경에서는 호출자 키를 보내는 게이트웨이(Hangang 변경 HC-3)가 필요합니다.
수정되지 않은 게이트웨이는 호출자 인증을 끈 개발 용도로만 쓸 수 있습니다. 계약의
호환성 표를 참고하세요.

- **네이티브 TOTP(main 소스)** — 암호화 등록·결합 브라우저 단계 상승, 원자 자격 교체·상승 핸드오프, 현재 설정 세대 검사 및 서비스 자격의 AAL 0 유지. Keyring과 명시적 인증등급 규칙이 필요합니다. [2차 인증](docs/ko/SECOND_FACTOR_EXTENSIONS.md). 내부 MFA 배포·복구·키 수명주기·외부 MFA API·Lua 어댑터는 후속입니다.

## 아직 없는 것

여기 있는 것은 모두 계획이며 구현되지 않았습니다. [로드맵](docs/ko/ROADMAP.md)을
참고하세요.

- 다른 제공자(카카오, 네이버, 이메일 매직 링크, 이메일과 비밀번호), 추가 2차 인증 요소·외부 MFA API·Lua 어댑터.
- 블랙리스트와 IP별 한도를 넘는 제한, 여러 인스턴스를 위한 공유 상태(PostgreSQL, Redis/Valkey), 전체 제공자·애플리케이션 관리, 복구 및 내부 MFA 검증.
- Lua 훅, 웹훅, Prometheus 메트릭, 설정 다시 로드, 서명된 자가 업데이트.

## 빠른 시작

빌드(Rust 1.96 이상)하거나 컨테이너 이미지를 사용하고, 설정 파일을 작성한 뒤
실행하기 전에 점검합니다.

```sh
cargo build --release --locked
export HOPAE_GATEWAY_KEY=change-me                    # 게이트웨이와 공유하는 호출자 키
export HOPAE_PROVIDER_GOOGLE_CLIENT_SECRET=change-me  # Google OAuth 클라이언트 비밀 값
target/release/hopae --check --config deploy/hopae.example.json
target/release/hopae run     --config deploy/hopae.example.json
```

`--check`는 다른 곳에 등록해야 할 것을 출력합니다. 게이트웨이 라우트 `auth` 조각,
반환 origin, 제공자 redirect URI(`<portal.public_url>/callback/google`)입니다.
그다음 게이트웨이에 포털 라우트와 보호할 라우트를 등록하고(예시는
[`deploy/hangang-routes.example.json`](deploy/hangang-routes.example.json)),
브라우저로 보호된 호스트를 엽니다. 강화된 컨테이너 배포는
[`deploy/README.md`](deploy/README.md)를 따르세요.

## 문서

- [문서 목차](docs/ko/README.md)
- [게이트웨이 계약](docs/ko/GATEWAY_CONTRACT.md) — verify 프로토콜, 헤더, 쿠키, 라우트 조각
- [설정 참조](docs/ko/CONFIG.md) — 모든 키, 기본값, CLI 명령
- [관리](docs/ko/ADMIN.md) — 관리 콘솔, API, 관리자 부여, 신선도
- [운영](docs/ko/OPERATIONS.md) — 실행, 상태, 백업, 키 교체, 로그, 상태 확인, 장애 동작
- [개발 프로세스](docs/ko/PROCESS.md) — 역할, 단계 게이트, 시나리오 기반 TDD, 릴리스와 보안 규칙
- [문서 체계](docs/ko/DOCUMENTATION.md) — 구성, 번역 규칙, 문체, 필수 문서
- [아키텍처 결정 기록(ADR) · 영문](docs/adr/)
- [시나리오 명세 · 영문](scenarios/)
- [로드맵](docs/ko/ROADMAP.md)

## 기여

모든 변경은 [개발 프로세스](docs/ko/PROCESS.md)를 따릅니다. 설계 기록, 적대적
검토, 시나리오 명세, 실패하는 테스트, 그다음에 구현입니다. 영문 문서가 기준이며,
한국어 번역은 같은 변경에서 함께 갱신합니다.

## 라이선스

[MIT](LICENSE) © 2026 Jioh Jung

[Hangang 네이티브 통합](docs/ko/HANGANG_NATIVE.md)은 프로바이더·세션 권한을 유지하며 제한된 지속 검증 연결과 관리 메뉴를 제공합니다.

## 서비스 권한 소유권

[품계(Pumgye)](https://github.com/ziozzang/pumgye)가 서비스별 역할·권한·정보등급과
사용자/네트워크 배정을 소유합니다. 호패의 네이티브 검증은 신원과 인증 수준을
제공하고, Hangang은 독립 품계 서버에 권한 판단을 위임하고 수문장 네트워크 근거와 결합해 집행합니다.
인증 성공만으로 서비스 권한을 부여하지 않습니다. 미배정 사용자는 guest이며
auth-proxy가 보호 요청을 거부합니다. 프로바이더·사용자·세션은 계속 호패 소유이고,
네이티브 콘솔 관리 권한은 서비스 접근 권한과 구분합니다.
