# LDAP 인증 provider

<!-- translation-status: source=../LDAP_AUTHENTICATION.md source-rev=8 status=current -->

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
