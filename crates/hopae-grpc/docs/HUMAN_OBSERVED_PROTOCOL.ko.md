# Human 관측 SDK와 추가 프로토콜

이 단계는 순수 wire/SDK 메커니즘입니다. 운영 Human핸들러·원천레코드·서명소유자·
권한·contract4·Root활성화는 없습니다. 인증된 테스트 피어도 가상 서명자이며 실제
네이티브 Human증명이 아닙니다. 기존 Service/Workload와 해시벡터는 보존합니다.

HumanFinalRequest는 v2메타데이터만 전송합니다. SDK는 실제 완전한 본문에서
해시/길이를 계산하고 고정 scope/헤더매니페스트/예약이름을 사용합니다.
본문16MiB, Verify헤더64KiB는 그대로이며 송수신프레임128KiB입니다.
헤더64개/이름128바이트/값16384바이트이며 각 헤더 framing6바이트까지 합계65536에
포함합니다. 실제 HTTP이름/값과 예약 x-hopae-gateway-key도 검증합니다.
H1 bind_actual은 실제 본문을 한 번 해시하고 private필드의 계산된 메타데이터만
반환합니다. 기존 digest출력은 같으며 호출자 digest발급 준비 API는 없습니다.

epoch는 hobs1:<nonce32>:<authority40>:s:<원천scope리비전>:a:<앱세대>입니다.
TimeReply6은 source_revision입니다. kind1/AAL1또는2/human1:+소문자64hex만
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
