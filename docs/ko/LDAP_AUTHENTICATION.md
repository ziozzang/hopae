# LDAP 인증 provider

<!-- translation-status: source=../LDAP_AUTHENTICATION.md source-rev=23 status=current -->

[문서](README.md) · [English](../LDAP_AUTHENTICATION.md)

## 상태와 연결 위치

구현 제안 계약이며 활성화된 provider가 아닙니다. 현재 Provider trait은 OAuth
redirect/callback을 표현하고 Registry는 OIDC만 생성합니다. LDAP는 별도 자격 제출
adapter로 같은 transaction·신원 해석·session·handoff·재인증·회수 서비스에 연결합니다.
OAuth callback을 흉내 내거나 HOP1/API relay에 비밀번호를 전달하지 않습니다.
redirect interface 옆에 명시적인 direct-credential provider interface를 추가하고
선택 화면에 함께 표시합니다. LDAP가 OAuth code exchange를 구현할 필요는 없습니다.

## 인증 흐름

브라우저는 설정된 provider를 선택하고 호패 HTTPS portal에만 username/password를
제출합니다. 먼저 transaction·브라우저 바인딩·CSRF·return 범위를 검증합니다.
디렉토리 작업 전에 빈 username/password를 거부합니다. 기존 IP/계정 throttling,
제한된 connector semaphore와 lookup/TLS/bind 전체 기한을 적용합니다. 비밀번호를
저장·로그·반환하거나 비동기 재시도 queue에 넣지 않습니다. 디렉토리 장애는 자격 오류가
아니라 unavailable이며 새 명시적 로그인 선택 없이 다른 provider로 우회하지 않습니다.

읽기 전용 디렉토리 신원으로 고정 base DN·설정된 attribute·escape한 filter value의
제한된 subtree search를 수행합니다. 정확히 한 entry를 요구하고 0개·여러 개·referral은
인증하지 않습니다. entryUUID/objectGUID 같은 설정된 불변 신원 attribute를 namespace
subject로 사용하며 변경 가능한 DN·username·email을 영구 신원으로 사용하지 않습니다.
DN 변경은 신원을 유지하고 불변 ID가 다른 재생성 username은 이전 권한을 상속하지 않습니다.

찾은 DN으로 별도의 TLS 연결에서 bind하여 비밀번호를 검증합니다. 사용자 bind 연결을
다른 사용자나 lookup pool에 재사용하지 않습니다. 실패·취소·protocol 오류는 연결을
폐기합니다. 검색 성공만으로 인증하지 않습니다. service/user credential 전송 전에
명시적 CA/이름을 검증한 기밀 TLS를 요구하며 인증서 우회나 필수 StartTLS의 평문
downgrade를 허용하지 않습니다. StartTLS/LDAPS는 별도 명시적 설정이며 자동 fallback이 아닙니다.

## 신원·세션·혼합 provider

성공한 bind는 설정된 디렉토리 namespace의 Human 신원, AAL 1, 로컬 인증 시간을
만들고 기존 transaction 서비스로 일반 호패 session/handoff를 생성합니다. OIDC
provider auth_time이나 MFA를 주장하지 않습니다. 재인증은 새 password bind를 요구하며
검색 cache나 기존 세션으로 만족하지 않습니다. email은 기본적으로 비권위 근거입니다.
OIDC/자체/API 신원 연결에는 별도 검증된 관계가 필요하며 email 일치로 추정하지 않습니다.

품계는 서비스 권한을 소유합니다. LDAP group은 명시적 mapping이 필요한 근거이며
관리자 grant로 자동 승격하지 않습니다. 호패는 provider를 혼합하고 Hangang은 네이티브
전송으로 audience·권한을 집행합니다. 디렉토리 비활성/삭제는 제한된 reconciliation
lease로 로컬 세션을 회수해야 합니다. polling·webhook·디렉토리 장애 동작을 명시하며
변경 feed 없이 즉시 원격 회수를 약속하지 않습니다. 비밀번호 변경도 별도 검증된
수명주기 신호 또는 주기적 세션 재검증이 필요합니다.

## 설정과 릴리즈 검증

설정은 endpoint·TLS mode·CA/server name·base DN·불변 subject attribute·escape
username filter template·service-bind 비밀 참조·attribute 허용 목록·시간/결과 제한·
회수 lease를 담습니다. 호패가 DB 게시를 소유하며 위임 관리자가 미선언 비밀 참조나
임의 사설 endpoint를 넣지 못하게 합니다. 디렉토리 비밀은 콘솔 응답에 포함하지 않습니다.

kind=ldap 활성화 전에 생성한 CA와 소유한 OpenLDAP 서버로 선택/form/session/handoff
전체 흐름을 검증합니다. 빈 비밀번호·잘못된 이름/신뢰 root·평문 downgrade·잘못된
자격·중복 검색·referral·filter/DN 특수 문자·취소·사용자 간 연결 재사용·username
재생성·계정 비활성·비밀번호 변경·미할당 서비스 권한·provider 간 연결·circuit 회복을
검증합니다. 실제 Hangang/호패 요청을 실행하고 동시성 지연은 로컬 디렉토리 처리량과
분리해 검증합니다. 운영 디렉토리가 검증에 제공된다고 가정하지 않습니다.

## 참고 자료

- [OpenLDAP 보안](https://www.openldap.org/doc/admin26/security.html): 빈 비밀번호 simple bind는 비인증 접근일 수 있습니다.
- [OpenLDAP TLS](https://www.openldap.org/doc/admin26/tls.html): 인증서 검증과 TLS 방식.
- [RFC 4513](https://datatracker.ietf.org/doc/html/rfc4513): LDAP 인증과 TLS 보안.

## 구현된 인터페이스 기초 계층

`provider::credentials::CredentialProvider`는 OAuth begin/callback과 분리된
직접 비밀번호 검증을 정의하고 향후 세션 연결에 기존 ProviderIdentity 형태를
반환합니다. PasswordInput은 Secret을 빌리며 serialization/clone 구현이 없고
Debug에서 username과 password를 모두 숨깁니다. 생성자는 비밀번호를 trim하지
않고 빈 자격·username 제어 문자·과대 입력을 거부합니다. 오류는 잘못된 자격·
provider 장애·비활성 provider를 구분합니다. LDAP TLS/search/bind·자체 비밀번호
hash·portal form·세션 발급은 아직 구현하지 않았습니다. 신원/assurance 요건은
해당 경로 검증까지 connector·portal 구현 계약입니다.

## 구현된 디렉토리 커넥터

`provider::ldap::LdapProvider`는 ldap3/rustls로 직접 자격 interface를 구현합니다.
LDAPS 또는 명시적 필수 StartTLS, 절대 경로의 제한된 일반 CA 파일, endpoint 인증서
검증을 요구하며 credential은 환경변수 참조입니다. semaphore 64개와 전체 기한
1–2000ms로 연결·서비스 bind·stream 검색·별도 사용자 bind를 제한합니다. 고정
attribute filter에 username을 escape하고 단일 결과·단일 제한된 텍스트 불변 신원
attribute를 요구하며 referral을 거부합니다. scope 종료/취소에서 연결 driver를
abort하고 사용자 bind 연결은 pool에 넣지 않습니다. 변환 parser panic은 unavailable로
처리하고 email 권위나 provider auth_time을 반환하지 않습니다. binary objectGUID·
BER frame의 엄격한 크기 제한·영속 서비스 lookup pool은 추가 구현/검토가 필요합니다.

소유한 OpenLDAP fixture로 TLS bind 성공·반복 entryUUID·잘못된 비밀번호·미등록/
중복 사용자·filter 주입·잘못된 CA 거부를 검증합니다. 임시 credential/인증서를
만들고 container를 제거합니다. `docker build -t hopae/owned-openldap:bookworm
tests/fixtures/ldap` 후 `python3 tools/owned_ldap_smoke.py`로 재현합니다. fixture는
명시적 ignored connector 통합 테스트를 실행하며 일반 unit test는 Docker를 요구하지
않습니다. 커넥터 일부 검증이며 portal 선택/form·세션 발급·회수·circuit 수명주기·
전체 성능·운영 LDAP provider 배포를 증명하지 않습니다.

## 커넥터 circuit

LDAP는 API verifier relay와 같은 공유 단조 시간·generation admission lease를
사용합니다. 연속 backend 실패 3회면 30초간 circuit을 열고 회복에는 half-open
probe 하나만 허용합니다. 취소는 lease drop으로 실패를 기록합니다. 잘못된 사용자
자격과 미등록/모호한 검색 결과는 정상 디렉토리 응답으로 다루며 TLS/연결/검색 장애·
서비스 bind 오류·손상 결과는 unavailable입니다. semaphore 포화는 즉시 거부하며
용량 압박을 디렉토리 실패로 계산하지 않습니다. 실제 OpenLDAP 테스트로 일반 자격
거부는 circuit을 닫힌 상태로 유지하고 잘못된 CA 실패 3회는 여는 것을 확인합니다.
프로세스 로컬 circuit이며 provider registry 게시·영속 quarantine·관리 회복은
이 구현에 포함하지 않습니다.

## 필수 StartTLS 검증

소유한 디렉토리 fixture는 LDAPS와 명시적인 필수 StartTLS 양쪽에서 자격 시나리오를
실행합니다. 별도 거부 peer가 첫 protocol operation이 StartTLS임을 확인하고
unavailable ExtendedResponse를 보낸 뒤 후속 bind 없이 연결이 닫히는지 검증합니다.
거부 시 평문 인증으로 우회하지 않습니다. 인증서·잘못된 사용자·circuit 검사를 두
설정에서 실행합니다. portal registry의 LDAP 활성화나 세션 회수·고부하 성능을
증명하는 검사는 아닙니다.

## 불변 subject 인코딩

subject_encoding의 기본 text와 binary_hex를 지원합니다. subject에는 소문자
attribute namespace와 인코딩 접두사를 포함합니다. 예시는 `t:entryuuid:<value>`
또는 `b:objectguid:<raw-byte-hex>`입니다. GUID endian 재해석 없이 원래 byte를
인코딩합니다. 텍스트/바이너리 값과 다른 attribute 이름이 충돌하지 않습니다.
대소문자 구분 없이 attribute 발생 한 번·값 하나를 요구합니다. 텍스트는 제어 문자
없이 128byte, 바이너리는 64byte까지이며 누락·모호함·과대 값은 차단합니다.
ldap3의 텍스트 map에 노출된 유효한 UTF-8도 binary 인코딩은 원래 byte를 유지합니다.

unit test로 모호함·인코딩 격리를 검증하고 실제 소유한 OpenLDAP의 UTF-8이 아닌
바이너리 attribute를 TLS 두 방식에서 정확한 인코딩으로 확인했습니다. Active
Directory 호환성이나 사용자 수명주기 검증은 아닙니다. 이번 prototype subject
형식 변경 전에 운영 LDAP 신원은 없었습니다.

## Provider 저장 준비

migration 0004는 하나의 트랜잭션에서 기존 provider 데이터를 보존하면서 별도
ldap 종류를 추가합니다. 새 종류가 없는 v4 주장 DB는 foundation 검사에서 거부합니다.
LDAP는 비밀번호 factor이며 MFA를 의미하지 않습니다. 선택 화면·transaction·세션
연결까지 설정과 registry 활성화는 제한합니다. 내부 배포에는 적용하지 않았습니다.

provider 소유권·비밀 참조 유지와 반복 이전을 검증하고 테이블 교체 후 실패를 만들어
원래 테이블과 이전 버전 복원을 확인합니다. 기존 사용자/세션/관리자 이전 검사도
통과했습니다. v3 바이너리는 v4 DB를 열지 못하므로 향후 복구에는 이미지 교체뿐
아니라 일관된 이전 전 DB 백업이 필요합니다.

## 직접 인증 결과 경계

authenticate_password wrapper는 커넥터 결과를 검증하고 principal을 Human,
AAL을 1, 인증 시간 출처를 HopaeCompletion으로 고정합니다. 로컬 완료 시간을
기록하며 provider auth_time·verified/authoritative email 주장을 거부하고
subject/claim 크기와 제한된 검증 이후 provider ID·종류·활성 상태를 확인합니다.
결과 형태로 MFA를 주장할 수 없습니다. 자격 오류 종류는 유지하고 잘못된 결과는
unavailable로 처리합니다.

위조 provider 시간·검증 도중 비활성화 및 실제 LDAP 결과의 LDAPS/StartTLS 경계
통과를 검증합니다. 세션 입력 준비이며 세션 생성·portal CSRF/transaction 구현이
아닙니다. 향후 세션 생성 트랜잭션 내부의 provider 활성 상태 fence도 필요합니다.

## Raw claim 제한

직접 비밀번호 인증 결과의 raw_claims는 빈 JSON object여야 합니다. 임의 metadata·
credential echo·assurance 주장은 검증된 세션 입력 객체를 만들기 전에 거부합니다.
향후 디렉토리 attribute에는 OIDC raw-claim 컨테이너 대신 별도 typed 허용 목록이
필요합니다. 자격 정보 객체·AAL 주장·null·array 거부와 실제 LDAP 커넥터의 두 TLS
방식 통과를 검증합니다. portal/세션 발급은 미구현이며 결과 경계 계약이지 전체 로그인
흐름의 완성을 의미하지 않습니다.

## 설정·직접 자격 레지스트리 준비

ProviderEntry의 typed ldap 설정을 비밀번호 값 없이 policy 스냅샷과 DB 가져오기에
보존합니다. OIDC client_id는 OIDC에 필수이며 LDAP는 OIDC 자격 정보와 암시적 계정
연결을 거부합니다. key tree에 LDAP 필드를 등록하고 환경 경고는 bind 참조 누락을
표시합니다. 비활성 provider의 자격 정보는 읽지 않습니다.

Registry는 직접 자격 provider와 redirect provider를 분리합니다. 저장된 활성 LDAP
행은 TLS 커넥터를 컴파일하고 손상·비활성·삭제 행은 비활성 자격 provider로 조회됩니다.
실제 OpenLDAP 검사에서 레지스트리 조회 후 안정된 subject 인증을 두 TLS 방식으로
검증합니다. ID가 OIDC preset과 같거나 저장 설정에 max_age가 있어도 LDAP 재인증
capability는 Unsupported/None입니다. CLI의 LDAP portal 활성화 제한은 유지하며
선택/form/transaction/세션 연결과 운영 배포가 필요합니다.

## 공통 세션 완료 단계 준비

세션 서비스의 provider 인증과 공통 신원·세션·handoff 완료 단계를 분리했습니다.
기존 OIDC callback은 state/binding·provider 검증·freshness 검사 후 이 private
단계를 사용합니다. 신원 충돌 처리·일회 transaction 소비·provider fence·재인증·
handoff 발급을 유지합니다. 직접 자격 경로에는 별도 인증된 transaction 바인딩과
portal route가 필요하며 이 분리만으로 LDAP 로그인 endpoint가 생기지 않습니다.

최종 소스의 전체 target gate가 통과했습니다. 라이브러리 413건·시나리오 365건과
기존 OIDC callback/비활성 경쟁 검사를 포함합니다. 명시적 ignored LDAP fixture와
시나리오 40건은 별도 검증 범위입니다. 정상 업그레이드의 오래된 버전 기대값은 현재
스키마로 바꾸었고 손상된 v3 DB는 이전 전에 거부하며 버전 3을 유지합니다.

## 직접 인증 transaction 바인딩 저장

TransactionBinding은 빈 OAuth placeholder 대신 선택적인 nonce·PKCE 값을 유지합니다.
직접 로그인 challenge는 일회 digest·provider·불변 portal 바인딩을 유지하면서 OAuth
전용 열에 NULL을 저장할 수 있습니다. 기존 redirect 인증은 실제 nonce/verifier를
유지합니다. 저장 테스트로 OAuth 필드 부재와 브라우저 바인딩 교체 거부를 확인하고
라이브러리·OIDC callback 회귀 검사도 통과했습니다. 저장 준비 단계이며 LDAP 활성화
전 portal의 직접 challenge 생성·CSRF·비밀번호 완료 경로가 필요합니다. 이미 nullable인
열이라 추가 운영 스키마 이전은 없고 이 변경이 LDAP 로그인 endpoint를 켜지는 않습니다.

## 세션 서비스의 직접 challenge 준비

ProviderLookup에 redirect와 분리된 credential 조회를 추가했습니다. begin_password는
살아 있는 로그인 transaction을 읽고 브라우저 cookie 형식·IP 바인딩·기존 바인딩을
검사하며 DB의 선택 provider 종류·활성·삭제 상태와 재인증의 원래 provider를 확인합니다.
OAuth 필드가 NULL인 임의 challenge digest와 불변 portal 바인딩을 만들며 준비 단계에서
비밀번호 검증은 호출하지 않습니다. 알려진 직접 provider는 자격 값 없이 거부 진단에
포함합니다.

실제 소유한 store 시나리오로 cookie 누락·provider 비활성 거부, 거부 시 미바인딩,
challenge 조회·OAuth 필드 부재·두 번째 바인딩 충돌을 검증했습니다. 라이브러리와
네이티브 회귀 검사를 통과했습니다. 활성화 전 portal CSRF/form route와 자격 완료·
세션 발급 연결이 필요합니다.

## 직접 자격 세션 완료

OAuth callback 없이 비밀번호 challenge를 완료하는 세션 경로를 추가했습니다.
자격 검증 전에 challenge 형식·일회 상태·만료·목적·provider ID·OAuth 필드 부재·
portal/app 바인딩·client IP를 확인합니다. 직접 인증 결과를 검증하고 이후 살아 있는
provider 종류/설정을 재검사하여 공통 신원·세션·handoff 완료를 AAL 1·로컬 시간으로
수행합니다. 잘못된 자격은 invalid_credentials 오류이며 세션을 만들지 않고 portal의
필수 throttling 정책 아래 challenge 재시도가 가능합니다.

실제 소유한 store와 제어된 테스트 커넥터로 잘못된 자격 재시도·세션/handoff 발급·
로컬 인증 시간·AAL 1·backend 재호출 없는 replay 거부·검증 중 provider 비활성화 시
추가 세션 미생성을 확인했습니다. 서비스 수준 테스트이며 실제 LDAP 브라우저 로그인
전체 흐름은 아닙니다. 라이브러리/네이티브 회귀와 Clippy를 통과했습니다. portal의
form/CSRF/throttling 연결·설정 커넥터 epoch fence·원격 LDAP 회수·운영 활성화는 남았습니다.

## 자격 검증 전 브라우저 불일치

직접 완료 store 시나리오에서 유효한 challenge를 다른 portal cookie로 제출합니다.
자격 커넥터 호출이나 추가 세션 생성 없이 거부하고 challenge를 소비하는지 검증합니다.
잘못된 자격 재시도·성공·replay·provider 비활성 사례도 같은 시나리오에서 유지합니다.
Clippy가 통과했습니다. 서비스 바인딩 경계 검증이며 HTTP CSRF·비밀번호 form 연결은
운영 활성화 전에 별도로 필요합니다.

## 비밀번호 form 템플릿 준비

영어·한국어 portal PasswordForm 템플릿을 추가했습니다. provider 비밀번호 경로에
POST로 challenge·CSRF hidden 필드와 라벨이 있는 username/current-password 입력,
일반 거부 문구를 사용합니다. 모델에 비밀번호 값 필드가 없으므로 재시도에 값을 다시
채우거나 노출하지 않습니다. 기존 script 없는 템플릿 정책 아래 provider 표시명을
HTML escape합니다. 두 언어·라벨·POST 바인딩·password value 속성 부재를 검사합니다.
HTTP route나 provider 선택기에 아직 연결하지 않았고 CSRF·throttling·자격 제출·
운영 LDAP 활성화는 남았습니다.

## Portal 자격 adapter

PortalServices에 OAuth callback과 분리된 borrowed PasswordSubmission을 추가했습니다.
adapter는 PasswordInput을 검증하고 직접 세션 완료를 호출하여 기존 handoff/handle
응답을 반환합니다. 실패는 장애와 자격 거부를 구분합니다. PasswordSubmission에는
Debug·serialization 구현이 없고 호출 전 HTTP Origin/CSRF·시도 제한이 계약입니다.
실제 store 서비스 시나리오에서 adapter를 통과한 handoff 응답을 확인했습니다.
portal 검사와 Clippy가 통과했습니다. HTTP route·HTTPS 집행·CSRF/throttle handler·
선택 화면 연결은 아직 활성화하지 않았습니다.

## 비밀번호 HTTP endpoint·시도 제한

POST `/login/{provider}/password`는 신뢰된 요청 문맥을 준비하고 HTTPS와 기존 Login
Origin/CSRF guard를 요구하며 중복/누락 자격 필드를 거부하고 제한된 시도 admission
후 PortalServices.password를 호출합니다. 제한된 form만 받아 기존 handoff 응답이나
일반 실패를 반환합니다. handler는 비밀번호를 URL이나 응답에 넣지 않습니다.

정규 IP당 단조 시간 1분에 CSRF-valid 제출 10회를 허용하며 최대 4096개 IP window를
유지합니다. IPv4-mapped IPv6는 별도 quota를 얻지 못합니다. 포화 시 활성 window를
내보내지 않고 만료 항목만 정리하며 lock 손상은 차단합니다. 초과는 Retry-After 60의
429입니다. 프로세스 로컬 상태이며 영속/replica 공유 제한은 아닙니다. 넓은 배포 전
계정별·cluster 전체 제어가 필요합니다. 일반 세션 검증에는 이 limiter를 사용하지 않습니다.

실제 router와 제어된 서비스로 평문·Origin 누락·모호한 필드가 자격 호출 전에 거부되고
제출 10개만 서비스에 도달함을 검증했습니다. portal 61건이 통과했습니다. 선택기와
최초 비밀번호 form은 아직 연결하지 않았고 LDAP 설정 활성화 제한도 유지합니다.
내부 배포 및 실제 디렉토리/브라우저 전체 흐름 검증은 남아 있습니다.

## 최초 비밀번호 form dispatch

PortalServices.prepare_password와 adapter가 실제 세션 서비스 challenge를 준비하고
provider 표시명과 Secret metadata를 반환합니다. 기존 provider 선택 POST는 등록된
credential provider를 이 경로로 분기하여 Origin/CSRF 검사 후 HTTPS를 요구하고
새 Login CSRF token의 PasswordForm을 렌더링합니다. redirect provider는 기존
begin_provider를 사용합니다. 실제 store adapter 시나리오에서 준비 후 자격 완료를
수행하고 실제 router와 제어된 서비스로 자격 검증 없이 바인딩 form 렌더링을 확인합니다.
portal 62건과 Clippy가 통과했습니다.

직접 provider를 최초/재인증 선택 목록에 포함하고 단일 provider redirect를 처리하는
작업은 남아 있으며 설정 활성화 제한도 유지합니다. 소스 연결이며 내부 LDAP 배포나
실제 디렉토리 브라우저 전체 검증은 아닙니다. 분산/계정 시도 제한과 커넥터 epoch
fence도 필요합니다.

## 혼합 provider 선택기 연결

Session ProviderLookup에 활성 credential provider 목록을 추가했습니다. 일반/재인증
선택기는 redirect provider와 이를 합치고 살아 있는 디렉토리 행·종류를 확인하며 저장된
표시명·순서와 ID 중복 방지를 유지합니다. 직접 provider 재인증은 자신의 살아 있는
provider만 제공합니다. portal adapter는 설정된 직접 커넥터를 form dispatch 대상으로
처리하고 단일 provider의 OAuth 자동 redirect에서는 제외합니다. 선택 시 OAuth URL
대신 바인딩된 비밀번호 form을 사용합니다.

실제 store 직접 provider 시나리오에서 선택 항목과 표시명을 확인했습니다. 라이브러리
419건·OIDC 36건과 엄격한 Clippy가 통과했습니다. 실제 브라우저/디렉토리 검증·커넥터
epoch fence·디렉토리 응답의 엄격한 크기 제한·회수 작업 전에는 LDAP 설정 활성화를
제한합니다. 이번 선택기 연결은 내부 운영에 아직 배포하지 않았습니다.

## 동시 비밀번호 admission 검증

32개 thread를 동기화하여 IPv4와 IPv4-mapped IPv6 제출을 섞고 하나의 IP 한도에서
정확히 10개만 허용되는지 확인했습니다. 상태 lock 손상 시 panic이나 quota 재개 대신
차단되는 것도 검증했습니다. 용량·만료·단조 시간 window 검사도 통과했습니다. admission
불변조건 검증이며 분산 quota 구현이나 전체 스택 처리량 benchmark는 아닙니다.

## 자격증명 제출 전 설정 최신성 확인

직접 비밀번호 인증 완료 경로는 자격증명을 제출하기 전에 현재 DB의 LDAP 설정과
커넥터가 컴파일한 타입 설정을 비교합니다. 불일치하면 백엔드를 호출하지 않고
거부합니다. 타입 파싱은 기본값을 포함하며 endpoint, TLS 모드, CA 경로,
bind 비밀 참조, 디렉터리 속성, timeout이 일치해야 합니다. 인증 후 DB 설정을
다시 비교하는 기존 검사도 유지합니다.

실제 저장소 시나리오는 설정 변경 시 올바른 비밀번호도 커넥터에 전달되지 않음을
확인합니다. 소유한 LDAPS·StartTLS 테스트는 커넥터 설정 일치를 확인하며,
집중 테스트와 엄격한 Clippy가 통과했습니다. CA 파일 내용이나 해석된 비밀값의
fingerprint, 동시 설정 변경에 대한 최종 DB commit fencing, LDAP 운영 활성화
검증은 아직 포함하지 않습니다.

## 새 세션 생성의 쓰기 트랜잭션 검사

LDAP·비밀번호 직접 인증 완료는 확인한 provider 종류와 DB 설정을 세션 생성에
전달합니다. SQLite 쓰기 트랜잭션은 세션·핸들·로그인 이벤트를 넣기 전에
provider가 존재하고 활성 상태이며 삭제되지 않았는지, 종류와 파싱한 JSON 설정이
일치하는지 확인합니다. 저장소 회귀 테스트는 오래된 설정에서 쓰기가 전혀 발생하지
않고 일치한 설정에서 생성됨을 확인합니다.

새 세션 생성의 마지막 조회 이후 경합을 차단합니다. 신원 해석은 여전히 별도
트랜잭션입니다. 기존 세션 재사용·재인증 설정 검사, 실제 비밀·CA 교체,
BER 프레임 크기 상한은 남아 있습니다. 이러한 활성화 조건을 완료하기 전까지
운영 설정에서 LDAP 활성화는 계속 제한합니다.
