# gRPC 게이트웨이 인증 확인

<!-- translation-status: source=../GRPC.md source-rev=2 status=current -->

[문서 목차](README.md) · [English](../GRPC.md)

`listen.grpc_gateway`는 HTTP·HOP1과 같은 인증 처리 경로를 사용하는
`hangang.hopae.v1.Authentication/Verify`를 제공한다. 절대 경로의 인증서·키·
클라이언트 CA를 `listen.native_gateway_tls`에 설정한다. 루프백에서도 mTLS와
게이트웨이 자격이 필수이고 다른 리스너와 주소가 달라야 한다. HOP1 리스너는
선택 사항이다. 관리자 상태에는 실제 바인딩한 주소를 표시한다.

단일 `authorization: Bearer <게이트웨이 호출 키>`를 RPC 메타데이터로 전달한다.
요청 ID와 반복 헤더에 기존 계약의 요청 문맥을 담는다. 대소문자와 관계없이
내장 `x-hopae-gateway-key` 헤더는 거부하고 전송 계층이 검증한 키만 주입한다.
기존 인증 처리 경로가 다시 자격과 문맥을 검사한다.

응답은 기존 인증 상태·반복 헤더·본문을 포함한다. gRPC 전송 성공이 인증 허용을
뜻하지 않으며 리다이렉트·오류까지 인증 계약에 따라 해석해야 한다. 공급자·팩터·
세션·서비스 변환·서킷 브레이커는 계속 호패가 소유한다. 전송 실패를 허용으로 처리하면 안 된다.

공용 런타임은 연결 2,048개, 연결당 스트림 64개, 메타데이터 8KiB,
TLS 파일 크기와 요청 시간 1초를 제한한다. gRPC 전체 처리량은 4,096개이며
기존 인증 경로의 제한도 적용된다. 입력·출력 protobuf는 128KiB 이내이고
내부에서 HOP1 헤더·본문 제한을 재사용한다. 압축은 활성화하지 않으며
종료는 기존 애플리케이션 드레인을 따른다. 빌드에는 protoc가 필요하다.

실제 K8s gRPC 배포·한강 gRPC 클라이언트·릴리즈와 운영 반영은 후속 검증 대상이다.

## 관측형 projection 출력 스키마

`ObservedCredentialProjection.Project`는 추가된 생성 계약이며, SDK에 있다는
사실만으로 실제 리스너가 제공한다고 볼 수 없습니다. 계약 2는 Pumgye 관측형
permit 질의를 사용하며 기존 엄격 시간 계약 1과 분리됩니다. `chain_sha256`은
디코딩·재인코딩 전의 정확한 `permission_query` 바이트에 대한 SHA-256입니다.
매 시도마다 새 `request_id`를 쓰고 내부 질의 및 응답의 상관값과 일치시킵니다.

고정된 인증 projection 소유자는 독립된 `hproj1:<32자리 소문자 hex 시작 세대>`
시계와 소유자 세대, 현재 시각, 남은 기간을 보고합니다. 남은 기간은 비밀값 처리와
최종 콜백 이후의 실제 BOOTTIME 잔여 기간을 내림한 값이어야 합니다. 인증·permit·
출력의 절대 만료값을 비교하면 안 됩니다. 수신자는 RPC 전후 BOOTTIME 표본으로
전송 지연·반올림·명시적 시계 오차를 보수적으로 차감하고, 원래 전제조건의 기한과
교차한 뒤 최종 요청·설정·소유자 검사를 거쳐야 합니다. 미지원 시 기존 경로로
전환하지 않고 거부합니다. 두 projection 응답의 기본 Debug는 비밀값을 숨깁니다.

네이티브 관측형 구현과 명시적 시계 오차 설정은
[네이티브 관측형 paired projection](OBSERVED_PROJECTION.md)을 참고한다.

## 실제 네 프로세스 관측 경로 검증

`tools/service_stack_smoke.py --observed`는 실제 인증·품계 permit·호패 출력
소유자를 사용하는 경로를 선택한다. 현재 바이너리와 전체 연결 옵션을 지정한다.

```sh
python3 tools/service_stack_smoke.py \
  --gateway-binary /path/to/hangang --hopae-binary /path/to/hopae \
  --pumgye-binary /path/to/pumgye --sumunjang-binary /path/to/sumunjang \
  --grpc --resource-catalog --native-resource --route-owner \
  --projection-owner --permit-issuance --credential-projection \
  --observed --durable-restart
```

임시 신원·키·DB를 생성하고 변환된 자격증명 전달과 기존 자격증명 제거,
최종 경로·본문 일치, 거부 요청의 백엔드 미도달, 잘못된 키·소유자 서버,
권한·네트워크·guest 거부, 실제 재시작 후 회수 유지 등을 검사한다.
`--keep-workdir`는 진단용 비공개 테스트 상태·로그를 보관한다. 확인 후 해당
디렉터리를 보호·정리해야 한다. 기능 성공은 처리량·독립 호스트 시계·복원·복제·
Kubernetes·운영 배포 검증을 의미하지 않는다.
