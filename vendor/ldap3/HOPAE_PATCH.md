# Hopae LDAP wire-size patch

Vendored from the crates.io ldap3 0.12.1 source already resolved by Cargo.lock.
Upstream MIT and Apache-2.0 licenses are retained. Only src/protocol.rs is modified.
Before lber parsing, validate the outer LDAP sequence and definite-length header,
reject lengths wider than four octets, and cap the entire declared frame at 64 KiB.
The check covers both LDAPS and StartTLS, and rejects oversized headers before
waiting for their body. This fork is scoped to Hopae credential lookup/bind usage;
large generic LDAP entries are intentionally refused. Fragmented valid frames and
coalesced small frames remain supported. This does not bound parser recursion or
harden all malformed nested BER structures; that review remains necessary.

Run patch tests with `cargo test --manifest-path vendor/ldap3/Cargo.toml --no-default-features --features tls-rustls-ring --lib hopae_frame_tests`.
When updating ldap3, review the complete upstream diff and reapply/qualify this patch.
