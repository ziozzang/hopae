# Service authentication gateway

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/AUTH_GATEWAY.md) · [Native integration](HANGANG_NATIVE.md)

The first runtime connector authenticates service API keys with optional IP
conditions. It is opt-in through `authentication_gateway`; existing OIDC/session
routes keep their behavior when this configuration is absent. The same caller
key, bounded concurrency and forwarded-request validation apply before API
credentials are read, over both HTTP and HOP1.

```json
{"authentication_gateway":{"authority_id":"example","profiles":[{"service_id":"orders","host":"orders.example.test","ports":[443],"realm":"partner","api_keys":[{"token_env":"HOPAE_ORDERS_API_KEY","subject":"scheduler"}],"networks":["192.0.2.0/24"],"session_fallback":false}]}}
```

Each profile must match a configured application's ID, exact host and ports.
Scopes cannot overlap. The referenced credential must contain 32–1024 printable
ASCII bytes; use a generated secret. Only the environment reference is public
configuration. Startup checks reject unavailable/invalid/duplicate credentials.
Optional key `expires_at` is an absolute Unix millisecond timestamp. Observed
expiration cannot be reversed by a wall-clock rollback within the process;
persisted cross-restart expiration watermarks remain future work.

The runtime keeps SHA-256 credential indexes and compiled IPv4/IPv6 prefix trees
in memory, with bounded profiles, credentials and network nodes. Queries do not
access SQLite, call providers or store credentials. This version is file-owned
and compiled at startup: changing references, expiry or networks requires
restart. Database-owned publication, rotation APIs, management UI and distributed
invalidation remain implementation work.

A profile selects a presented Bearer credential. Missing credentials are denied
unless `session_fallback:true` explicitly permits the existing session engine.
Invalid, duplicate, malformed, expired or network-disallowed credentials never
fall back to a browser session. Network conditions use the authenticated
forwarded client address, not a new caller-supplied identity claim. Reserved
login/logout paths retain their existing session behavior.

Successful authentication emits an opaque `s_…` subject derived from principal
kind, authority/issuer, realm and configured subject. It emits
`x-hopae-principal-kind: service` and `x-hopae-aal: 0`; it does not invent a human
account, verified email or MFA. Replies contain no credential and use
`Cache-Control: no-store`. Authentication is not a service permission grant:
Hangang/Pumgye must enforce the service matrix. Parent support for typed
non-human assurance and credential consumption/translation is a follow-up; do
not treat this connector as a completed end-to-end service authorization flow.

LDAP, local human passwords, remote API relay/introspection, Any/All composition
with actual connector relationships, upstream credential translation, full
credential lifecycle and full-stack 100k QPS qualification remain open. Existing
OIDC circuits protect provider network calls; this in-memory API-key connector
has no remote backend to circuit-break.
