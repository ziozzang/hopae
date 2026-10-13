# Hopae LDAP wire-size patch

Vendored from the crates.io ldap3 0.12.1 source already resolved by Cargo.lock.
Upstream MIT and Apache-2.0 licenses are retained. src/protocol.rs and response dispatch in src/conn.rs are modified.
Before lber parsing, validate the outer LDAP sequence and definite-length header,
reject lengths wider than four octets, and cap the entire declared frame at 64 KiB.
The check covers both LDAPS and StartTLS, and rejects oversized headers before
waiting for their body. This fork is scoped to Hopae credential lookup/bind usage;
large generic LDAP entries are intentionally refused. Fragmented valid frames and
coalesced small frames remain supported. An iterative preflight also caps traversal contexts at 32 and elements at 4096,
rejecting child lengths outside their parent and indefinite nested lengths before
recursive parsing. A semantic gate validates LDAP message arity/classes/IDs, nonnegative bounded
integers, result fields/UTF-8/referrals, search entry attributes/binary values and
control wrappers before upstream infallible parsers receive a tag. Unsupported
operations (including intermediate/sync replies) are refused for credential-only
use. Single-operation/search response dispatch rejects wrong-operation replies
as I/O errors rather than panicking. Each single response must match the
request operation (a success ExtendedResponse cannot stand in for BindResponse).
Each credential search is also capped at eight response frames before enqueueing,
bounding the unbounded-channel/aggregate collector despite an ignored server
size limit. At 64 KiB per frame this limits queued search payload to 512 KiB per
operation; object overhead and other connection state are additional. Opaque control-value parsers and GSSAPI/SASL
features outside this credential scope are not qualified or enabled by Hopae.
The AD extended-response outer-OID workaround remains accepted after shape checks.

Run patch tests with `cargo test --manifest-path vendor/ldap3/Cargo.toml --no-default-features --features tls-rustls-ring --lib hopae_frame_tests`.
When updating ldap3, review the complete upstream diff and reapply/qualify this patch.
