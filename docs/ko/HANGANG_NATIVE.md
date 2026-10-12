# Hangang 네이티브 검증과 콘솔 위임

<!-- translation-status: source=../HANGANG_NATIVE.md source-rev=1 status=current -->

[English](../HANGANG_NATIVE.md) · [문서](README.md)

프로바이더와 OIDC 상태/코드 교환·비밀값·사용자·세션·관리 권한은 Hopae에 유지합니다.
Hangang에는 콘솔 shell과 요청 집행, 프로바이더와 독립된 전송/결과 처리를 연결합니다.
네이티브 로그인·로그아웃 진입에는 Lua가 필요하지 않습니다.

## HOP1 검증

선택적인 `listen.native_gateway`는 다른 리스너와 구분된 literal loopback TCP 주소를
사용합니다. 비인증 caller 모드는 거부하며 기존 HTTP gateway도 유지합니다.
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
