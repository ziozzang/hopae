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
