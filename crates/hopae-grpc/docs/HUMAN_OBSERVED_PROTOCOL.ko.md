# Human 관측 SDK와 추가 프로토콜

이 문서는 wire/SDK 경계이며 타입 자체로 Human원천이나 라우트를 활성화하지 않습니다.
별도 검증된 선택적 네이티브 원천/RPC어댑터가 이 규약을 사용합니다. 권한·contract4·
Root활성화는 별도 후속 작업입니다. SDK전용 테스트 피어는 가상 서명자이며 실제
Engine/세션/공급자 RPC검증은 별도로 기록합니다. 기존 Service/Workload와 해시벡터는 보존합니다.

HumanFinalRequest는 v2메타데이터만 전송합니다. SDK는 실제 완전한 본문에서
해시/길이를 계산하고 고정 scope/헤더매니페스트/예약이름을 사용합니다.
본문16MiB, Verify헤더64KiB는 그대로이며 송수신프레임128KiB입니다.
헤더64개/이름128바이트/값16384바이트이며 각 헤더 framing6바이트까지 합계65536에
포함합니다. 실제 HTTP이름/값과 예약 x-hopae-gateway-key도 검증합니다.
H1 bind_actual은 실제 본문을 한 번 해시하고 private필드의 계산된 메타데이터만
반환합니다. 기존 digest출력은 같으며 호출자 digest발급 준비 API는 없습니다.

epoch는 hobs1:<nonce32>:<authority40>:s:<원천scope리비전>:a:<앱세대>입니다.
TimeReply6은 source_revision입니다. kind1/AAL1·2·3(3은 옵트인한 애플리케이션만, Hopae ADR-0018)/human1:+소문자64hex만
허용합니다. 사용자리비전과 credential세대는 각각 양수이나 원천리비전이나
서로 같을 필요가 없습니다. 사용자 전체에 적용하는 전역floor는 없습니다.

실제 본문으로 만든 IssuePrepared와 공개문맥/증명/기대digest로 만든
ObservationRequest는 별도 private필드 타입입니다. 후자는 발급에 사용할 수 없고
독립 ObserveTime호출 이후에만 opaque관측을 만듭니다. 서명만으로 현재 권한을
만들지 않습니다. mTLS·키·issuer·authority·scope·명시적 clockrates를 고정합니다.
앱과 실제 세션의 연결은 후속 네이티브 원천 책임이며 헤더에서 승격하지 않습니다.

refresh는 기존 원래 입장수명을 늘리지 않고 증명 보존수명은 따로 유지합니다.
clock실패/교체시 폐기와 현재 소유자 fence가 필요합니다. 신규 민감 DTO의 Debug는
가립니다. 실제 H0→공개SDK→Pum→같은 원장→Root전체검증 전 완료를 주장하지 않습니다.

## 인증된 원천 scope 보고

TimeReply10 scope_sha256은 호출자 입력이 아니라 정확한 원천 증명 레코드의
고정 scope지문입니다. 서비스/대상/앱/라우트·리비전/목적지/헤더정책·정렬된 슬롯을
도메인 분리해 묶습니다. 예약이름은 검증하지만 인코딩하지 않습니다. 이는 라우트
소유권·권한 또는 악성 PEP가 실제 본문을 전송했다는 증명이 아닙니다.
클라이언트는 설정 지문을 시작시 한 번 캐시합니다. 예약필터만 달라도 같은 정규
지문이 중복되면 시작을 거부하여 보고가 정확히 한 설정만 선택하게 합니다. 발급은 준비된 정확한 scope만
허용하며 같은 서비스/대상의 다른 허용 scope로 대체할 수 없습니다.
관측 전용 준비 API는 그대로이고 인증된 ObserveTime보고가 허용된 고정 scope를
선택합니다. 증명/해시/시간과 서비스·대상까지 맞아야 opaque관측을 만듭니다.
누락·잘못된·미설정 지문은 거부합니다. Observation.scope()는 검증된 불변 설정
메타데이터이며 권한이 아닙니다. refresh는 다른 허용 scope가 있어도 지문 변경을
거부합니다. 이후 네이티브 권한 소유자는 자신의 리소스/라우트/계획과 현재 소유자를
별도로 검증해야 합니다. 기존 Service/Workload메시지는 바꾸지 않습니다.
