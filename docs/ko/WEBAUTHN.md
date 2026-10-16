# WebAuthn 패스키

<!-- translation-status: source=../WEBAUTHN.md source-rev=7 status=current -->

[문서 목차](README.md) · [English](../WEBAUTHN.md)

패스키(WebAuthn 자격 증명)는 Hopae의 피싱 저항 2차 인증 요소입니다. 사용자는
포털에서 패스키를 등록하고, 애플리케이션의 단계 상승 규칙이 AAL 2를 요구할 때
사용하며, 포털의 보안 페이지에서 관리합니다. 결정 기록은
[ADR-0017](../adr/0017-webauthn-passkeys.md)이고, 이 페이지는 운영자와 통합자를
위한 참조 문서입니다.

## 상태

1차 구현이 소스에 있으며 **기본값은 꺼짐**입니다. 설정에 `webauthn` 객체가 없으면
아래의 모든 경로가 `404`로 응답하고, WebAuthn 행을 하나도 쓰지 않으며, 기존 배포는
이전과 똑같이 동작합니다. 실환경 종단 간 검증(G8)과 적대적 검토(G2, G7)는 남아
있으며 ADR은 `Proposed` 상태입니다.

구현됨: 패스키 등록과 단계 상승, 보안 개요, 패스키 목록·이름 변경·삭제, 포털 보안
확인, 복구 코드, 마지막 요소 규칙, 서명 카운터 역행 처리, 명령줄 관리자 초기화와 조회,
AAL 3 분류(기록만).

2단계에서 조건부 UI를 쓰는 비밀번호 없는 로그인과 네이티브 Human 소유자 출처를
추가했습니다. 구현하지 않음: 콘솔의 인증 요소 관리와 콘솔 운영자에 대한 패스키 요구.
AAL 3 내보내기는 아래에 설명합니다.
[로드맵](ROADMAP.md#m5--확장-지점050)을 보십시오.

## 목표와 비목표

목표: 사용자가 패스키(Touch ID, Face ID, Windows Hello, Android 화면 잠금 같은
플랫폼 인증기, 비밀번호 관리자 패스키, USB·NFC·블루투스 보안 키)를 추가하고, 하나로
애플리케이션의 AAL 2 규칙을 충족하며, 기기를 잃어버렸을 때 복구 코드로 복구하고,
마지막 요소를 삭제해 스스로를 잠그는 일이 없도록 합니다.

비목표: 1차 인증 요소로서의 패스키(비밀번호 없는 로그인), 선택적인 고보증 허용 목록을
넘어서는 증명 기반 기기 정책, 배포 간 자격 증명 동기화, 게이트웨이 계약이나 피어의
변경.

## 설정

```json
{
  "webauthn": {
    "rp_id": "auth.example.test",
    "rp_name": "Example sign-in",
    "high_assurance": {
      "attestation_ca_files": ["/etc/hopae/webauthn/vendor-root.pem"],
      "aaguids": ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    }
  }
}
```

| 키 | 기본값 | 의미 |
| --- | --- | --- |
| `webauthn` | 없음 | 패스키를 켭니다. 인증된 게이트웨이 호출자(`gateway.allow_unauthenticated_caller = false`)와 `https` 포털이 필요합니다. |
| `webauthn.rp_id` | `portal.public_url`의 호스트 | 신뢰 당사자(RP) ID. 포털 호스트이거나 레이블 경계에서 그 상위 도메인이어야 하며, IP 리터럴이나 단일 레이블은 안 됩니다. **나중에 바꾸면 등록된 모든 패스키를 쓸 수 없게 됩니다.** |
| `webauthn.rp_name` | `Hopae` | 인증기가 보여 주는 이름. 1–64자. |
| `webauthn.high_assurance.attestation_ca_files` | 없음 | 인증기 제조사 루트의 PEM 파일. `aaguids`와 함께 "보안 키(고보증)" 등록을 켭니다. |
| `webauthn.passwordless` | `false` | 로그인 페이지에서 비밀번호 없는 패스키 로그인을 제시합니다. |
| `webauthn.high_assurance.aaguids` | 없음 | AAL 3으로 분류될 수 있는 AAGUID. `attestation_ca_files`와 함께 필수. 최대 64개. |

허용 origin은 언제나 정확히 포털 origin이며 설정할 수 없습니다. `hopae --check`는
키를 검증하고 CA 파일을 읽으며 실제 RP ID를 보고합니다.

## 페이지와 경로

모든 경로는 포털 리스너에 있고, HTTPS와 살아 있는 포털 세션을 요구하며, `webauthn`이
없으면 `404`로 응답하고, `cache-control: no-store`를 보냅니다. 모든 POST는 포털
핸들에 묶인 CSRF 토큰과 정확한 `Origin`을 요구합니다.

| 경로 | 용도 |
| --- | --- |
| `GET /security` | 개요: 패스키, 인증 앱, 복구 코드, 복구 필요 배너. |
| `GET /security/passkeys` | 이름, 종류(동기화 또는 기기 귀속), 생성·마지막 사용 시각이 있는 목록과 이름 변경·삭제 폼. |
| `GET /security/passkeys/new`, `POST /security/passkeys/new` | 등록 의식(설정된 경우 증명된 보안 키는 `?kind=high_assurance`). |
| `POST /security/passkeys/rename`, `POST /security/passkeys/remove` | 이름 변경(살아 있는 세션)과 삭제(최근 2차 요소, 마지막 요소는 불가). |
| `GET /security/verify`, `POST /security/verify/passkey`, `POST /security/verify/totp`, `POST /security/verify/recovery` | 보안 확인: 2차 요소를 증명하고 인증 요소 관리를 위해 포털 세션을 상승시킵니다. |
| `GET /security/recovery-codes`, `POST /security/recovery-codes` | 상태와 (재)생성. 코드는 한 번만 표시됩니다. |
| `GET /stepup?txn=…` | 사용자에게 패스키가 있으면 패스키를 먼저 제시하고 인증 앱, 외부 요소, 복구 코드 경로를 링크합니다. 요소가 하나도 없는 사용자는 `/security`로 안내합니다. |
| `POST /stepup/webauthn` | 패스키로 애플리케이션 단계 상승을 완료합니다. |
| `GET /assets/webauthn.js` | 포털의 유일한 스크립트([ADR-0017](../adr/0017-webauthn-passkeys.md) 결정 3). |

의식을 실행하는 페이지는 `script-src 'self'`, `require-trusted-types-for 'script'`,
포털 origin으로 제한한 `Permissions-Policy`를 보냅니다. 다른 모든 페이지는 무스크립트
정책을 유지합니다. JavaScript가 없으면 페이지가 그 사실을 알리고 다른 방법을
링크합니다.

### 브라우저와 인증기 참고

- 의식은 버튼을 눌러 시작합니다(Safari와 iOS는 사용자 동작을 요구).
- 등록은 기본적으로 사용자 확인과 비상주 자격 증명을 요청합니다. 항상 발견 가능한 패스키를 만드는 플랫폼(iCloud 키체인, Google 비밀번호 관리자)도 동작합니다.
- `excludeCredentials`에 사용자의 기존 패스키를 넣어 같은 인증기를 두 번 등록하지 않게 합니다. 브라우저가 이를 알리면 페이지가 설명합니다.
- 알려진 제공자(예: iCloud 키체인, Google 비밀번호 관리자, Windows Hello, 1Password, Bitwarden, YubiKey)이면 AAGUID로 패스키 이름을 정하고, 아니면 "패스키" 또는 "보안 키"로 정합니다. 사용자는 이름을 바꿀 수 있습니다.
- 첫 패스키를 만든 뒤에는 복구 코드 만들기로 이동합니다. 복구 코드를 사용한 뒤에는 모든 보안 페이지가 새 요소를 요구합니다.
- 단계 상승에는 여전히 5분 이내의 1차 로그인이 필요합니다(TOTP 규칙). 더 오래된 세션은 먼저 제공자 재인증을 거칩니다.
- 취소되거나 시간이 지난 요청(`NotAllowedError`), 이미 등록된 인증기(`InvalidStateError`), RP ID 불일치(`SecurityError`), 미지원 환경에는 각각 영어와 한국어 메시지가 있습니다.

## 보증 수준

| 증거 | 세션 효과 | 기록 등급 |
| --- | --- | --- |
| 사용자 확인이 있는 패스키 어설션 | `aal` 2, 요소 `webauthn` | `aal2` |
| 고보증 자격 증명(설정된 CA로 증명, 허용 목록 AAGUID, 백업 불가)을 사용자 확인과 함께, 백업되지 않은 상태로 어설션 | `aal` 2, 요소 `webauthn` | `aal3`(기록만) |
| 복구 코드 | `aal` 변경 없음(1), 요소 `recovery`, 재등록 필요 | — |

AAL 3은 `apps[].max_emitted_aal = 3`인 애플리케이션에만, 세션의 현재 상승이 고보증
패스키인 동안 제시합니다. 다른 모든 애플리케이션과 저장된 수준은 2입니다
([ADR-0018](../adr/0018-aal3-emission.md)과 그 문서의 피어 변경 목록). 복구 항목은
AAL 2 단계 상승 규칙을 결코 충족하지 않습니다.

`3`인 단계 상승 규칙(`apps[].step_up[].require.aal`)이나 `admin.require_aal`은 같은
근거로만 충족되며 패스키 사용으로만 갱신됩니다. 그런 규칙에서 단계 상승 페이지는
사용자의 기기에 묶인 고보증 키만 제시하고 다른 방법은 보여 주지 않습니다. 그런 키가
없는 사용자에게는 고보증 보안 키가 필요하다고 알리고 보안 설정으로 안내하며(`403`),
인증 앱과 외부 요소 경로는 트랜잭션을 거부합니다. 3을 요구한다고 3이 제시되지는
않습니다. 제시는 여전히 `max_emitted_aal`이 정합니다([ADR-0018](../adr/0018-aal3-emission.md#aal-3-requirements)).

## 비밀번호 없는 로그인

`webauthn.passwordless = true`이면 로그인 페이지가 제공자 옆에 패스키를 제시합니다
([ADR-0017](../adr/0017-webauthn-passkeys.md) 결정 16):

- 패스키 입력란(`autocomplete="username webauthn"`)은 브라우저 자동 완성에 저장된 패스키를 보여 줍니다(조건부 중개: Chrome, Edge, Safari, Firefox). "패스키로 로그인" 버튼은 모달 요청을 엽니다(보안 키, 하이브리드 전송의 휴대전화).
- 사용자 이름이나 비밀번호를 묻지 않으며 패스키의 사용자 핸들이 계정을 정합니다. 모르는 패스키, 다른 계정의 자격 증명, 비활성 사용자, 잘못된 서명 등 모든 실패는 같은 메시지를 돌려줍니다.
- 세션은 요소 `webauthn`, 제공자 `hopae.passkey`(`x-hopae-provider`)인 AAL 2이며, 그 패스키가 활성인 동안 유지되고 다른 세션처럼 단일 로그인으로 모든 애플리케이션에 이어집니다.
- 의식은 로그인 트랜잭션, 브라우저의 바인딩 쿠키와 주소에 묶이며 주소당 분당 최대 30개입니다. 제시할 수 없으면 패스키가 없을 때처럼 동작합니다(제공자가 하나면 바로 사용).
- 비밀번호 없는 로그인이 켜진 동안 등록하는 패스키는 발견 가능하게 요청합니다(`residentKey: preferred`). 그 전에 보안 키에 등록한 패스키는 아닐 수 있습니다.
- 제한: 애플리케이션의 `max_auth_age` 재인증은 패스키로 완료할 수 없습니다(로그아웃 후 다시 로그인). 네이티브 Human 소유자 경로는 패스키 세션을 거부합니다.

## 네이티브 Human 소유자 경로

패스키 상승은 확립 자격 증명을 `session_webauthn_provenance`(마이그레이션 12)에
기록합니다. [네이티브 TOTP 출처](HUMAN_TOTP_PROVENANCE.md)에 대응합니다. 네이티브
Human 소유자와 서명된 영수증은 기록이 현재인 동안 그런 AAL 2 핸들을 받습니다: 같은
세션 세대와 요소 항목, 여전히 활성인 패스키, 바뀌지 않은 설정 세대. 영수증은 여전히
AAL 2만 담고 요소 종류는 담지 않으므로 Hangang과 Pumgye는 바꿀 필요가 없습니다.
마이그레이션 전에 상승한 세션은 이 경로에서만 계속 거부됩니다.

## 데이터

마이그레이션 `0011_webauthn`은 `webauthn_credentials`, `webauthn_challenges`,
`recovery_codes`, `session_webauthn_elevations`와 널 허용 열
`users.webauthn_user_handle`, `users.factor_recovery_required_at`을 추가합니다.
기존 행은 바뀌지 않습니다. 다른 모든 마이그레이션과 마찬가지로 이전 바이너리는
마이그레이션된 저장소를 열지 않습니다(되돌리려면 마이그레이션 전 백업을 복원).

## 실패 동작

- 저장소를 쓸 수 없음: 모든 페이지와 의식이 안전하게 실패합니다(`503`).
- 챌린지가 만료·소비되었거나 다른 세션·핸들·브라우저에 묶임: 의식을 거부하고 페이지가 새 시도를 제공합니다.
- 서명·origin·RP ID·사용자 확인 실패: 거부, 챌린지 소비, `factor.webauthn_failed` 기록.
- 유효한 서명 뒤 카운터 역행: 자격 증명 폐기, 그것으로 상승한 세션 종료, `factor.webauthn_clone_suspected` 기록.
- 마지막 요소 삭제: 설명과 함께 거부.

## 관리

```text
hopae admin factors list <user-id-or-email>
hopae admin factors reset <user-id-or-email>
```

`reset`은 사용자의 모든 패스키, TOTP 등록, 사용하지 않은 복구 코드를 폐기하고 모든
세션을 종료하며 `admin.factor_reset`을 기록합니다. 사용자는 새로 로그인한 뒤 다시
등록합니다.

콘솔은 사용자의 인증 요소를 나열하고(`GET /v1/users/{id}/factors`: AAGUID에서 얻은
인증기 이름, 백업 상태, 마지막 사용 시각과 함께 `pk_` ID로 보이는 패스키, 인증 앱,
남은 복구 코드), 전부·패스키 하나·인증 앱·복구 코드를 초기화하며 제거한 요소가 보증한
세션을 끝냅니다([관리](ADMIN.md#인증-요소-관리)).

## 이벤트

`factor.webauthn_registered`, `factor.webauthn_used`, `factor.webauthn_renamed`,
`factor.webauthn_revoked`, `factor.webauthn_failed`,
`factor.webauthn_clone_suspected`, `factor.recovery_codes_generated`,
`factor.recovery_code_used`, `admin.factor_reset`. 자격 증명 ID는 `factor_id`
(`pk_`와 SHA-256의 16자리 16진수)로만 나타납니다.

## 테스트

저장소, 신뢰 당사자, 프로세스 수준 테스트는 `webauthn-authenticator-rs`의
소프트웨어 인증기(소프트웨어 패스키와 증명하는 소프트웨어 토큰)를 사용합니다:
등록, 어설션, 잘못된 origin과 RP ID, 재사용과 만료, 브라우저 바인딩, 카운터 역행,
마지막 요소 거부, 복구 코드 1회 사용, AAL 도출, 기본값이 꺼진 설정. 시나리오
480–487이 사례를 매핑합니다.

`tools/browser-qual/run.sh`는 실제 Chrome에서 DevTools 프로토콜과 WebAuthn 가상
인증기로 로컬 스택(모의 제공자, TLS 종단과 verify 기반 게이트웨이 역할을 하는
스크립트)에 대해 페이지를 검증합니다: 등록, 중복·거부된 요청, 단계 상승, 이름
변경과 삭제, 복구 코드, 조건부 중개를 쓰는 비밀번호 없는 로그인, 390 px 한국어
페이지, 스크립트 오류 없음. 아무것도 내려받지 않으며 Chrome이 든 이미지가 있는
Docker, Node.js, 기존 `playwright-core`가 필요합니다. 실제 Hangang 게이트웨이와
하드웨어 인증기는 G8의 남은 부분입니다.

## 관련 페이지

- [ADR-0017](../adr/0017-webauthn-passkeys.md), [ADR-0008](../adr/0008-second-factor-extension-point.md)
- [2차 인증 확장](SECOND_FACTOR_EXTENSIONS.md), [위협 모델](THREAT_MODEL.md), [설정](CONFIG.md)
