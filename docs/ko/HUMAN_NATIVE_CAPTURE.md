# Native Human current capture (비공개 선행 경계)

이 소스는 실제 native 인증, Engine Allow, 비공개 current-owner 결과를 연결합니다. Human RPC·SDK assertion·서명 receipt·품계 grant·projection·한강 dispatch는 활성화하지 않습니다. 기존 ordinary verify와 공개 provider/session 인터페이스는 호환성을 유지합니다. 클라이언트 헤더로 capture를 켤 수 없으며 crate 내부의 owning adapter extension만 요청할 수 있습니다. 일반 요청에는 추가 current-owner SQL을 실행하지 않습니다. BOOTTIME을 지원하지 않거나 읽기에 실패하면 이 추가 경로만 거부합니다.

Gateway는 caller 검사·parse·await 전에 원래 BOOTTIME admission을 잡습니다. 원래 native verify budget과 1초 미만의 상한을 적용하고 millisecond 양자화 오차도 보수적으로 차감합니다. 큐 대기·parse·스케줄링 정지·suspend·후속 observation은 기한을 새로 시작할 수 없습니다. 기존 caller-key 검사와 실제 parser를 거쳐 native session Engine을 실행합니다. Service credential이나 Workload attempt를 Human으로 승격하지 않습니다. 제시한 handle digest, URL, canonical path, method, host/port, caller slot, route, client IP, user agent를 묶습니다. 현재 session parser에는 최종 body/허용 헤더 digest가 없으므로 **이 비공개 candidate는 그 최종 요청 digest에 묶인 상태가 아닙니다**. 후속 owning Human RPC에서 실제 wire로 이 경계를 검증해야 서명 proof로 진행할 수 있으며 빈 body로 가정하지 않습니다.

Ordinary 최종 Allow 분기만 정확한 HandleView와 원래 native 유효기한을 보존합니다. Authz Refresh에서는 처음 조회한 오래된 행 대신 실제 갱신한 identity snapshot과 예상 authorization version을 유지합니다. Terminate 정책은 그대로입니다. 로그인 redirect·handoff redemption·entry route·거부·step-up 요청은 candidate를 만들지 않습니다. Owner의 실제 Store directory/session 구현을 사용하므로 외부에서 조립한 Identity나 대체 session trait가 양성 인증 근거를 공급할 수 없습니다.

## 원래 primary 인증과 TOTP

Schema 9는 `session_primary_provenance`를 추가하며 기존 session에 증거를 채워 넣지 않습니다. 실제 SessionService는 adapter 검증 전에 정확한 compiled provider Arc와 prepared owner를 잡습니다. 실제 password 검증 또는 OIDC completion 성공 경로만 복제 불가능한 비공개 verified primary command를 만듭니다. 기존 session 생성·실제 재인증과 같은 SQLite transaction에서 원래 provider incarnation/config generation, identity-user 관계, 순수한 publication fence를 확인하고 원래 primary factor와 인증 metadata를 기록합니다. 검증 도중 provider/config 변경이나 ABA가 있으면 qualified record를 붙일 수 없습니다. Provenance 삽입 실패 시 session·handle·login consumption 변경도 rollback됩니다. 앞선 user/identity 해석은 기존처럼 별도 transaction이므로 실패 후 orphan user가 남을 수 있습니다.

Primary 기록은 확립 당시 credential generation을 유지합니다. TOTP가 session generation을 올려도 원래 primary 기록과 auth_time을 바꾸지 않습니다. 실제 qualified primary 재인증만 더 높은 generation으로 기록을 교체할 수 있습니다. Legacy 또는 unqualified primary 재인증은 auth_time이 같은 초로 내림되는 경우에도 같은 transaction에서 기존 primary 기록을 삭제합니다. Legacy session, 삭제된 연결, provider 변경 전 session, 이전 configuration generation은 ordinary 호환성을 유지하지만 현재 Registry를 빌려 qualified가 될 수 없습니다. 실제 native 재인증이 필요합니다. Google 강제 재인증의 기존 Unsupported 선언은 바뀌지 않습니다.

Handle AAL2에는 기존 native TOTP association의 원래 enrollment ID/revision, session generation, factor index/time, config generation이 모두 필요하며 primary 기록도 현재 상태여야 합니다. 더 최근의 External/Recovery/WebAuthn factor로 오래된 TOTP를 fresh하게 만들지 않습니다. 모든 해당 freshness rule을 qualified factor로 다시 확인하고 원래 기한으로 candidate를 제한합니다. 다른 session이 enrollment counter만 증가시켰다는 이유로 enrollment owner를 폐기하지 않습니다. Provenance와 candidate에는 seed·password·OTP code·원문 cookie·provider secret을 저장하거나 직렬화하지 않습니다. Owned 테스트의 enrollment 준비는 암호화한 fixture seed 설치이며 실제 암호 검증·elevation·portal handle 회전·앱 handoff를 실행합니다. Enrollment UI 검증 완료를 뜻하지 않습니다.

## Current 검사와 검증 범위

하나의 bounded SQLite read transaction에서 handle/session/user/identity 관계, primary 기록, provider incarnation/config generation, 필요한 TOTP association을 함께 검사합니다. Handle touch로 기존 기한을 연장하지 않습니다. Native wall callback은 이 read 전에 실행하며 이후에는 실제 BOOTTIME backend와 보존한 publication/retirement fence만 확인합니다. 다른 동시 검사가 candidate를 폐기하면 반환 전에 이를 확인합니다. 서로 다른 owner나 원격 서비스를 원자적으로 묶은 권한 증명은 아니며 각 검사 시점의 관측입니다. Joined read transaction 안에 callback이나 network 교환을 추가하지 않습니다.

결과는 직렬화·공개 생성자가 없는 내부 타입입니다. 후속 소비자는 current owner와 원래 age fence를 다시 확인해야 합니다. 이 단계에는 발급한 Human observation record, durable proof/replay protocol, 외부 grant가 없습니다. SQL current read는 정확성 기반이며 원천 기반 immutable memory snapshot·membership/follower gate·처리량 검증은 후속입니다. 로컬 session 검사만으로 원격 LDAP 계정의 즉시 회수나 실제 Google 계정 수용을 주장하지 않습니다. Password form은 여전히 LDAP를 사용하며 자체 password DB가 아닙니다. 관측하지 못한 특권 same-generation publisher 교체, 임의 DB rollback, live VM clone, 공유 ledger fencing은 검증하지 않았습니다.

테스트는 실제 production OIDC discovery/JWKS/RS256·nonce/PKCE·native SessionService, owned OpenLDAP LDAPS와 필수 StartTLS, 실제 TOTP elevation과 native handoff, Engine Allow, Gateway caller/parser capture를 실행합니다. 회수·primary ABA/config generation 거부·실제 primary 재인증·SQL rollback·Refresh 예상 상태·deadline/cancel/suspend/clock 실패·동시 retirement도 검사합니다. 로컬 OIDC issuer는 명시적 `allow_private_endpoints`의 loopback HTTP이며 TLS 검증 해제나 공개 provider 실계정 수용이 아닙니다. Owned LDAP 테스트는 별도로 준비해 실행하며 full-suite의 ignored 결과만으로 검증됐다고 하지 않습니다. 운영 반영, 최종 Human wire/full-chain, 전체 혼합 신원 목표는 별도 gate로 남습니다.


## 실제 컴파일 material 소유권

선택 설정 `human_material_key_env`는 gateway caller key와 별개인 source-domain 전용 키의 환경 변수 이름입니다. 안전하게 생성한 32바이트를 canonical padding 없는 base64url 43글자로 설정합니다. 키는 시작 시 한 번만 읽습니다. 미설정·잘못된 값·전부 0인 키는 일반 인증을 유지하되 추가 Human qualification을 거부합니다. raw key, 비키 해시, 프로세스 난수 fallback은 없습니다. 같은 authoritative domain의 replica는 동일한 전용 키와 provider secret/CA material을 사용해야 합니다. 키 교체는 기존 material owner를 회수하며 실제 native primary 재인증이 필요합니다.

스키마 9의 `human_provider_material_owners`는 삭제하지 않는 단조 증가 tombstone입니다. 실제 usable provider compiler가 소비한 OIDC 설정/secret 또는 LDAP 설정/password/검증한 CA 바이트에 keyed MAC을 적용합니다. CA는 bounded 단일 read이며 TLS roots와 MAC이 같은 immutable 바이트를 사용합니다. 비밀번호·키·CA 본문은 ledger에 저장하지 않습니다. primary provenance는 원래 material revision을 유지합니다. 동일 env 이름·CA 경로의 내용 교체 및 A→B→A는 이전 primary를 새 owner로 승격하지 못합니다. 키/material/provider/config가 실제로 같은 Store 재시작은 revision을 유지하고 여전히 유효한 durable native session을 다시 검사할 수 있습니다. 프로세스의 private Checked는 이전할 수 없으며 모든 재시작에 재인증을 강제한다고 주장하지 않습니다.

컴파일 전에 같은 SQLite read transaction에서 provider rows/incarnation, config generation, material ledger를 캡처합니다. 게시 writer transaction은 원래 owner와 예상 material revision을 CAS로 검사합니다. 동시에 같은 준비를 한 경우 예상한 정확히 한 번의 전이만 공유하며, ABA 뒤 MAC이 같아진 상태는 거부합니다. 오래된 준비본은 새 owner를 덮어쓰지 못합니다. no-op import/동일 material 준비는 revision을 올리지 않습니다. 삭제·되감기·용량 및 revision 소진은 거부하며 writer 안에 env/file/network callback을 실행하지 않습니다. 메모리와 SQLite 사이의 검사는 point-in-time이며 원격 원자성 주장이 아닙니다. 서로 다른 replica의 out-of-band secret을 조정하는 분산 desired-material authority가 아니므로 운영자가 동일 material을 유지해야 합니다. 임의 DB restore·독립 ledger clone·fencing 없는 live clone 보호는 미검증입니다.

실제 컴파일된 CLI child process로 같은 설정 파일·Store에서 정상 종료 후 재시작을 검사합니다. config generation은 같은 상태에서 동일 material의 owner 유지, 같은 참조 secret 변경·ABA 및 전용 키 교체의 owner 회수를 확인합니다. 동일 material Store reopen 뒤 원래 native primary 재검사는 별도의 실제 native 로그인 테스트로 확인합니다.
