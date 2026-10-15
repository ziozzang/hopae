# gRPC gateway verification

<!-- doc-rev: 2 -->

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

## Observed projection output schema

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

The native observed implementation and explicit clock-rate configuration are
described in [Native observed paired projection](OBSERVED_PROJECTION.md).
