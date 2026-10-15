# gRPC gateway verification

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/GRPC.md)

`listen.grpc_gateway` adds `hangang.hopae.v1.Authentication/Verify` using the
same authoritative caller/parse/verify/render pipeline as HTTP and HOP1. Configure
`listen.native_gateway_tls` with absolute certificate, key and client CA paths.
The listener requires mTLS even on loopback and authenticated gateway callers.
It may be used with or without the HOP1 listener and must have a distinct address.
The authenticated administrator status reports its actual bound address.

RPC metadata must contain exactly one `authorization: Bearer <gateway caller key>`.
The request contains a correlation ID and repeated name/byte-value headers carrying
the existing gateway contract. Embedded `x-hopae-gateway-key` is rejected, including
mixed case. The credential is installed by the transport after validation and
rechecked by the existing verification pipeline. Original request context remains
subject to the gateway contract's validation; no arbitrary caller identity is trusted.

Replies carry the existing verification status, repeated response headers and bounded
body. A successful gRPC transport response is not an authentication allow: callers
must interpret the verification status and contract, including redirects and errors.
Provider, factor, session, projection and circuit breaker logic remain in Hopae.
The gRPC client must not turn transport failures into authentication success.

The shared runtime provides mandatory mTLS, at most 2,048 connections, 64 concurrent
streams per connection, 8 KiB metadata headers, bounded TLS files and a 1-second
transport request timeout. Global gRPC admission is 4,096; the shared verification
pipeline also retains its own admission and budget. Protobuf decode/encode bounds
are 128 KiB, with HOP1 header/body bounds applied inside the handler. Compression
is disabled. Timeout does not preempt blocking code. Shutdown uses the existing
application drain deadline.

Build requires `protoc`. The native scenario suite qualifies real mTLS gRPC calls
against the existing session engine. Hangang gRPC clients, actual Kubernetes gRPC
rollout and released/production binaries remain separate adoption gates.

### Observed projection output schema (not activated)

`ObservedCredentialProjection.Project` is an additive generated contract. Its
presence in the SDK does **not** mean a native listener serves it. Contract 2 uses
an observed Pumgye permit query; the strict contract 1 endpoint remains separate.
`chain_sha256` is SHA-256 of the exact bounded `ProjectionRequest.permission_query`
bytes, before decoding or re-encoding. A fresh outer `request_id` must equal the
query correlation and the reply correlation.

The authenticated fixed projection owner reports its own `hproj1:<32 lowercase
hexadecimal startup-generation>` clock, `owner_now_ms`, current owner generations,
and `remaining_ms`. The remaining duration must be rounded down from actual
BOOTTIME duration **after** credential work and final callbacks. Authentication,
permit and output absolute clock values must never be compared. Consumers sample
BOOTTIME before/after the RPC, conservatively subtract transit and rounding under
explicit clock-rate assumptions, intersect their original prerequisite deadlines,
and recheck native request/configuration/owner fences before dispatch. Missing
observed support refuses without legacy fallback. Default Debug redacts credential
bytes for both strict and observed projection replies.

### 관측형 projection 출력 스키마 (미활성)

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
