# Hangang 네이티브 검증과 콘솔 위임

<!-- translation-status: source=../HANGANG_NATIVE.md source-rev=6 status=current -->

[English](../HANGANG_NATIVE.md) · [문서](README.md)

콘솔 패키지 0.1.4는 실제 DB 문서에서 서비스·realm·자체 key 개수/relay·issuer
namespace·relay 접두사·Lua 조건·자격 미제시 시 session 대체를 표로 표시합니다.
JSON 편집은 로컬 미리보기만 갱신하고 저장은 기존 revision 확인 소유자 publication을
사용합니다. 미리보기는 서버 검증이 아닙니다. 조회 전용 사용자는 편집·저장할 수 없고
표시 값은 text node로 처리합니다. 표에 실제 자격 값을 넣지 않습니다. 영문·한국어
안내는 DB가 bootstrap보다 우선하고 혼합 라우팅이 결정적임을 설명하며 네이티브
권한 검사를 바꾸지 않습니다.

프로바이더와 OIDC 상태/코드 교환·비밀값·사용자·세션·네이티브 관리 권한은 Hopae에 유지합니다.
선택적인 통합 모드에서는 콘솔 권한을 Hangang에 위임합니다.
Hangang에는 콘솔 shell과 요청 집행, 프로바이더와 독립된 전송/결과 처리를 연결합니다.
네이티브 로그인·로그아웃 진입에는 Lua가 필요하지 않습니다.

## HOP1 검증

선택적인 `listen.native_gateway`는 다른 리스너와 구분된 literal loopback TCP 주소를
사용하며 원격 주소는 아래 mTLS 설정이 필요합니다. 비인증 caller 모드는 거부하며 기존 HTTP gateway도 유지합니다.
프레임은 HOP1 4바이트·big-endian u64 요청 ID·u32 본문 길이로 시작합니다.
최대 payload는 128 KiB입니다. ID 0 핸드셰이크는 최대 4096바이트 caller key,
응답은 1/0 한 바이트입니다. 이후 요청 ID는 양수이며 연결마다 증가해야 합니다.
요청은 u16 헤더 수, 각 u16 이름 길이·u32 값 길이와 바이트를 담습니다.
응답은 앞에 u16 HTTP 상태, 뒤에 u32 본문 길이·본문을 추가합니다.
중복 쿠키와 원시 헤더/본문을 보존합니다. 최대 헤더 64개·블록 64 KiB·이름 128바이트·
값 16 KiB·본문 64 KiB입니다.

프레임 내부 caller-key 헤더를 거부하고 인증된 키를 주입해 기존 검증 라우터를 호출합니다.
caller 검사·경로 정규화·세션/앱/바인딩/인증 강도·동시성/기한·결과 렌더링을 유지합니다.
잘못된 버전·크기·키·프레임·재사용 ID는 연결을 종료합니다. 핸드셰이크 2초·idle 읽기 30초·
쓰기 5초와 최대 연결 256개를 적용합니다. Hangang `auth.native`는 지속 연결 풀을 준비하고
기존 HTTP 결과 처리를 공유합니다. 포화 시 즉시 거부, 취소 시 소켓 폐기, 장애 시 HTTP
fallback이나 불확실한 요청의 재시도를 하지 않습니다. 세션 검사를 생략하지 않으며
이 구현만으로 identity 100k QPS를 주장하지 않습니다.

## 신뢰된 콘솔 패키지

`python3 tools/build_console_plugin.py`로 생성한 `plugins/hopae`를 검토한 manifest 해시,
고정 관리자 origin, `delegate_actor:true`, 전용 `token_env`와 함께 설치합니다.
상태·페이지별 사용자/세션/이벤트·사용자 활성/비활성·전체/개별 세션 회수를 제공합니다.
native 테마와 host 인증을 사용하며 패키지에 백엔드 키나 Hangang credential을 주지 않습니다.

`admin.hangang_delegation:{key_env:"HOPAE_CONSOLE_DELEGATION_KEY"}`를 명시적으로 설정합니다.
설정 예제:

```json
{"key_env":"HOPAE_CONSOLE_DELEGATION_KEY"}
```

전용 키는 32–4096바이트이며 검증 caller key와 분리합니다. loopback 요청에서만 HMAC-SHA256
작업자 ID/이름·시각 10초 창·nonce·정확한 메서드/경로·본문/handle 해시·클라이언트 IP/UA를
확인합니다. 알 수 없는 필드·중복·위변조·쿼리를 거부합니다. state_dir의 제한된 영속 nonce
DB는 재시작 후 재사용도 거부하며 포화/장애 시 fail-closed입니다.

### 브라우저 세션 방식

Hopae 관리자 origin을 Hangang 콘솔 origin에 맞추고 host 패키지 `delegation_cookie`를
Hopae handle 이름으로 지정합니다. `/_hopae/`는 native forward-auth로 연결하고 로그인
링크는 `/_hopae/login?return=/ui/`를 사용합니다. 인증은 Hopae 프로바이더에서 수행합니다.
서명된 Hangang 작업자와 별도로 유효한 Hopae admin handle/grant를 모두 요구합니다.
Hangang admin 역할만으로 Hopae grant를 만들지 않습니다. IP/UA는 신뢰된 transport/relay에서
생성해야 하며 플러그인 JS에서 받지 않습니다. 평문 adapter 직접 접근을 제한합니다.

### 명시적인 세션 연결 방식

선택적인 sessions_file은 절대 경로의 0600 regular file이며 symlink를 허용하지 않습니다.
최대 128개 actor_id·actor_name·user_id·Hopae handle·client_ip·선택적 user_agent를 담습니다.
기존 Hopae admin 세션을 연결하며 이 파일은 credential을 포함하므로 공개하면 안 됩니다.
파일 교체로 연결을 회수할 수 있습니다. 세션을 자동 생성하거나 계정 DB를 복사하지 않으며,
세션 만료 시 새로 연결합니다. 브라우저 방식에는 이 파일이 필요하지 않습니다.

## 권한과 감사

등록된 조회와 제한된 {id} 변경만 기존 관리자 경로로 변환합니다. 페이지 조회는 cursor/limit만
받고 native cursor를 검증합니다. 신뢰 헤더를 재구성한 후 기존 peer·host·handle·grant·
freshness·인증 강도·CSRF를 검사하며 역할·트랜잭션 actor fence·self-target도 유지합니다.
패키지에 프로바이더 비밀값이나 raw handle을 반환하지 않습니다.
변경 감사에는 Hopae 작업자/세션과 delegated_issuer·delegated_actor·delegated_operation을
기록하고 Hangang도 영속 의도/결과를 별도로 남깁니다. 부모 권한을 전후 확인하지만
별도 서비스에서 이미 수락된 변경은 완료될 수 있으며 원자적 회수를 주장하지 않습니다.
불확실한 변경은 실제 상태 확인 후 재시도해야 합니다.

## 검증

코덱 절단·추가 바이트·크기, 실제 SQLite 세션의 HTTP/native parity, 로그인/로그아웃 확인,
세션 회수·키 거부·caller 주입·ID 재사용·풀 취소/재연결/포화·쿠키 중복을 검증합니다.
실제 프로바이더 로그인에서 위임 조회/변경·self-target·작업자 감사·grant 회수·브라우저
handle·페이지 조회를 검증하며 개인정보·영속 nonce·위험 파일도 검사합니다.
광범위한 자동 적용 전에는 환경별 네트워크 제한·프로바이더/grant 설정·전체 부하와 복구 검증이
추가로 필요합니다.

네이티브 릴리즈는 Linux amd64/arm64 정적 빌드와 macOS Intel/Apple Silicon을 검증하며
검토된 콘솔 패키지를 포함합니다. Hopae의 서명된 supervised 자동 updater는 현재 구현되지 않았으며
릴리즈 패키지가 그 기능을 의미하지 않습니다.

SQLite 잠금 재시도는 절대 monotonic 기한으로 제한하며 OS sleep 초과가 추가 재시도로
누적되지 않게 합니다. panic을 포함한 작업 종료 뒤 handler와 기본 busy 상태를 복구합니다.

## 통합 콘솔 권한 (명시적 선택)

Hopae의 `admin.hangang_delegation.authority: "hangang"`과 host binding의
`delegation_authority: "hangang"`을 맞추고 `delegation_cookie`·`sessions_file`은
제거합니다. 이 모드는 추가 Hopae 관리자 로그인 대신 Hangang의 활성 관리자
세션·역할을 따릅니다. 검토된 패키지는 host 인증 메타데이터에 따라 별도 로그인·
로그아웃을 숨깁니다. 기본 `native` 모드와 독립 Hopae 경로는 기존 grant를 유지합니다.
통합 모드는 Hangang 인증 정책을 따르며 로컬 Hangang 로그인에 Hopae 네이티브
grant/AAL/freshness 정책을 추가로 적용하지 않습니다. `me`는 Hangang 권한임을
표시하고 네이티브 로그인 시각/AAL을 임의로 만들지 않습니다.

서명 요청에는 `authority: "hangang"`이 명시되어야 합니다. native 요청을 통합 권한으로
재해석하지 않습니다. host는 dispatch·응답 공개 전 Hangang 계정을 다시 검증합니다.
Hopae는 루프백 peer·전용 HMAC 키·정확한 허용 method/path/body·영속 일회성 nonce·
5초 미만의 proof만 허용합니다. 변경 트랜잭션은 키와 proof·외부 actor/session 바인딩을
다시 검사합니다. 외부 actor는 issuer 기반 합성 user ID와 요청별 합성 session ID로
표현하고 실제 Hangang ID/이름/issuer도 감사에 기록합니다. Hopae 사용자/세션/grant
행은 생성하지 않습니다. self-target 검사는 외부 issuer ID를 기준으로 하며 Hopae
사용자로 위장하지 않습니다. 서로 다른 권한 주체가 이미 수락한 변경의 원자적 회수는
보장할 수 없습니다.

Hangang의 선택적인 `--hopae-sso`는 ID/PW 아래에 SSO 버튼을 추가합니다. Google/OIDC
비밀값·로그인은 Hopae가 유지합니다. 불변 Hopae ID를 기존 활성 Hangang 계정에
명시적으로 연결하며 Hangang의 현재 역할을 적용합니다. 요청마다 Hopae 쿠키·클라이언트
바인딩을 확인하고, 불투명 browser bearer의 parent API 직접 인증을 거부합니다.
private parent lease는 5초, 재사용은 최대 1초입니다. 계정/grant를 자동 생성하지 않습니다.
구성·콜백/CSRF·재시작·로그아웃 동작은 Hangang `CONSOLE_PLUGINS.md`를 참고합니다.

## 인증 게이트웨이 구현 상태

OIDC 외부 HTTP client는 provider별 origin 서킷을 제한된 크기로 유지하며 복제된 fetcher가 상태를 공유합니다. 백엔드 장애 3회 후 30초 동안 차단하고 half-open 요청 하나로 복구를 확인합니다. 전송 오류/타임아웃·불완전하거나 크기를 초과한 응답·HTTP 429·HTTP 5xx를 백엔드 장애로 셉니다. 일반적인 HTTP 400/401/403 인증 거부는 장애로 세지 않습니다. 취소된 요청도 장애를 기록하고 probe를 해제합니다. 세대에 연결된 복제 불가능 permit으로 오래된 완료가 새로운 서킷을 닫지 못하게 하며, 버려진 probe도 만료됩니다. provider client당 origin은 최대 16개이며 포화·오염된 상태는 거부합니다. 경로·질의 문자열·자격 정보·인증 코드는 서킷 key에 들어가지 않습니다. HTTP/TLS client 초기화 실패 시에도 제한 없는 fallback으로 보내지 않고 요청을 차단합니다.

실제 discovery·JWKS·token·user-info 요청 경로에 적용됩니다. 캐시된 discovery/JWKS는 기존의 엄격한 유효 기한을 따르며 서킷이 인증을 승인하거나 credential 유효성을 연장하지 않습니다. 서킷은 프로세스 로컬 상태이고 provider client 재생성 시 초기화됩니다. 전용 콘솔 제어·영속 quarantine·분산 조정은 남아 있습니다.

인증 게이트웨이 코어는 namespace가 있는 사람/서비스/워크로드/네트워크 신원과 제한된 Any/All 근거 결합을 정의합니다. 만료·중복·미등록·충돌 근거를 거부하며 다른 realm의 같은 subject 문자열도 합치지 않습니다. 공개 요청의 주장으로 근거를 생성할 수 없습니다. 이 타입은 기반 구현이며 실제 connector나 새로운 로그인 방식으로 연결된 것은 아닙니다. LDAP·자체 비밀번호·API 릴레이/introspection·네트워크 신원·명시적 provider 간 연결·서비스에 묶인 자격 변환은 구현 작업으로 남아 있습니다. 현재 동작하는 외부 인증 connector는 다중 OIDC입니다.

## 네이티브 원격 mTLS 리스너

`listen.native_gateway_tls`는 절대 경로의 PEM `certificate`·`key`·`client_ca`를 받습니다. 루프백 밖의 `listen.native_gateway`에는 이 설정이 필수이며 `0.0.0.0`에도 인증된 원격 리스너를 열 수 있습니다. TLS 파일별 크기는 1 MiB로 제한하고 readiness 이전에 읽습니다. 빈 client CA 또는 잘못된 인증서/key는 시작을 거부합니다. 서버는 설정한 client CA로 검증되는 인증서를 요구하고 ALPN `hop1`을 협상하며 TLS early data를 끕니다. 기존 gateway caller-key 핸드셰이크도 필수로 유지하므로 TLS가 호출 권한을 대신하지 않습니다.

기존 최대 256개 연결 안에서 TLS 핸드셰이크를 3초로 제한합니다. 지속 연결은 300초 후 종료하고 프레임·검증 제한을 유지합니다. 전환을 위해 literal 루프백의 평문 연결만 허용합니다. Hangang 원격 TLS client 설정과 배포 검증은 후속 작업이며 서버 측 변경만으로 원격 Hangang 사용이 가능해진 것은 아닙니다.

[서비스 인증 게이트웨이](AUTH_GATEWAY.md)에 선택적 API 키/network 런타임과 남은 connector/권한 작업을 기록했습니다.

## 요청 바인딩 최종 전달 후보

tools/service_stack_smoke.py --grpc --resource-catalog --native-resource
--durable-restart로 실제 호패/품계/수문장 debug 프로세스와 HTTP origin을 사용해
한강 auth.native_resource 옵션을 검증했습니다. 임시 발급자/신뢰·실제 원천 검증
설정은 테스트가 소유합니다. origin에 합성한 /api/secure 경로와 비어 있지 않은
본문이 API 자격 없이 도착합니다. pin/발급자/audience 오류와 본문 예산 초과는
origin 전달 전에 거부하며 설정 복원·네트워크/권한/등급/AAL/서비스 거부·장애·
영속 권한/인증 회수를 통과했습니다. 옵션 없는 기존 gRPC 자원 검사도
통과했습니다. 로컬 후보 기능 검증이며 서명 릴리즈·Kubernetes/운영 반영·
서명 권한/변환·처리량은 별도 검증입니다.

## 실제 게이트웨이 라우팅 소유자 검증

격리 네 프로세스 검사는 --grpc --resource-catalog --native-resource와 함께
--route-owner를 지원합니다. 비공개 한강 관측 리스너와 품계 고정 mTLS 클라이언트를
설정해 실제 참조/대상 해시를 전달하고 판정 전후에 소유자 scope/IP를 확인합니다.
잘못된 서버 신원·호출 자격은 origin 효과 없이 거부하며 복구도 통과합니다. 선택적인
--legacy-pumgye-binary로 격리된 품계만 이전 호환 실행 파일로 교체해 조회 확인
누락이 게이트웨이 집행을 조용히 낮추지 못하는지 확인합니다.

전체 디버그 네 서버 검사가 영속 권한/프로필 회수·원천 장애와 함께 통과했고 기존
비소유자 모드도 통과했습니다. 키·신원·상태는 모두 비공개 임시 디렉토리의 합성
자원입니다. 로컬 소스 기능 검사이며 정적 릴리스·K8s·운영 적용·서명 권한/투영/
replay·처리량 검증은 아닙니다.

## 네이티브 인증 변환 계획 조회

`ProjectionPlans/Observe`는 필수 mTLS 게이트웨이 gRPC 리스너를 공유하며,
허용된 게이트웨이 호출자 자격을 요구합니다. 네이티브 컴파일 계획의 서비스,
대상, 리소스, 작업, 최소 AAL, 리비전만 반환합니다. 비밀 참조나 자격을
조회하거나 반환하지 않습니다. 캐시 TTL은 0이며 접근 권한을 부여하지 않습니다.
품계의 서명 권한 발급에는 별도의 인증된 소유자 클라이언트와 최종 회수 검사가
아직 필요합니다.

시작 시 ArcSwap 리더를 확보하며 요청은 메모리에서만 처리합니다. 공용 동시
요청 제한과 요청/응답 512/1024바이트 전송 제한을 적용합니다. 저장 전에 기존
스냅샷 조회를 차단하고, 정확한 롤백은 재개하며, 성공한 교체는 이전 스냅샷을
회수합니다. 커밋 결과가 불확실하면 영속 상태를 다시 읽을 때까지 차단합니다.
소유자 및 핸들러 테스트로 이 경계를 검증합니다. 실제 mTLS 소켓에서도 계획
없음 거부, 네이티브 등록, 조회 성공, 잘못된 호출자 거부, 동일 연결에서 회수 후
거부를 확인했습니다. 이것만으로 프로세스 간 권한 발급이나 인증 변환 검증이
완료된 것은 아닙니다.

격리 검사는 `--native-resource`와 함께 `--projection-owner`를 지원합니다.
격리 네이티브 계획과 품계의 고정 mTLS 계획 클라이언트를 설정하여 실제 네 서버의
최종 전달·라우팅 소유자 조회·영속 권한/프로필 회수·원천 장애를 통과했습니다.
잘못된 호패 서버 이름과 호출 자격은 origin 효과 없이 거부하며 복구도 통과합니다.
이 모드는 구버전 품계 바이너리와 함께 사용할 수 없습니다. 네이티브 계획 검증이며
서명 투영 허가나 업스트림 자격 발급 검증은 아닙니다.

`--permit-issuance`는 `--route-owner`와 `--projection-owner`를 모두 요구합니다.
독립된 격리 품계 허가 용도 키를 만들고 게이트웨이 설정을 명시적으로 리비전 1에서
시작합니다. 시드는 격리 환경에만 두고 경로에는 공개 핀만 넣습니다. 실제
`ProjectionPermits/Issue`와 게이트웨이 검증, 잘못된 공개키/발급자/키 세대의 거부와
복구를 검사합니다. 호패 paired replay 소비나 업스트림 자격 투영 검사는 아닙니다.

로컬 허가 발급 전체 검사는 실제 최종 URI/본문 라우팅, 독립 서명 핀, 복구,
영속 회수/원천 장애를 통과했습니다. 서명 근거 발급과 게이트웨이 검사이며 수신
소비와 업스트림 자격 투영은 남아 있습니다. 허가 없는 기존 계획 소유자 모드는
호환성 검사로 별도로 실행합니다.

한강 b326f03은 이 모드에서 로컬 허가 서명 검사 후 품계 b4b7f18의
`ProjectionPermits/Validate`를 필수 호출합니다. 동일한 동시 요청 제한/mTLS 채널과
원래 경과 시간 예산을 공유하며 검증된 더 짧은 소유자 만료를 적용합니다. 실제 네
서버의 허가/비허가 모드 모두 영속 회수·신뢰/원천 장애 거부를 통과했습니다.
호패 수신 paired replay와 자격 투영은 남아 있으며 이 재검증은 소비가 아닙니다.
