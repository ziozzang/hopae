# Service credentials for the admin listener

<!-- doc-rev: 1 -->

[Documentation](README.md) · [한국어](ko/SERVICE_CREDENTIALS.md)

Machine callers of the admin listener — first Pumgye policy v2, which reads
the signed membership projection and the subject lifecycle feed (Hangang ADR
0021) — authenticate with a **route-scoped, read-only service credential**
instead of an administrator session or a delegation key. A service credential
is useful only together with the client certificate it is bound to, only
toward this instance's audience, only on its exact read routes, and never on
a route that changes state.

## Prerequisites and configuration

- The console is enabled (`admin.public_url`, `listen.admin`) and the admin
  listener uses mutual TLS (`listen.admin_tls`: `certificate`, `key`,
  `client_ca`). A service token presented on a plain admin listener is refused
  (`403 service_transport_required`).
- `admin.service_audience` (optional, 1–256 visible ASCII characters): the
  audience callers must name; default the console origin, for example
  `https://hopae-admin.example.test`.
- Store schema version 15 (migration `0015_service_credentials`, applied at
  start). Back up the store before upgrading, as for every migration.

The client certificate is issued by a CA in `client_ca`; Hopae additionally
pins it per credential by the SHA-256 of its SubjectPublicKeyInfo and/or an
exact subject alternative name (DNS or URI, for example a SPIFFE ID).

## Behavior

A request carries:

```http
POST /v1/subjects/lifecycle HTTP/1.1
Host: hopae-admin.example.test
Authorization: Bearer hsc1.pumgye-v2.<43 characters>
X-Hopae-Audience: https://hopae-admin.example.test
X-Hopae-Admin-Request: 1
Content-Type: application/json

{"cursor": null, "limit": 100}
```

Checks, in order (the first failure answers):

| Check | Refusal |
| --- | --- |
| The connection is the admin mTLS listener with a verified client certificate | `403 service_transport_required` |
| One `Authorization` header with a well-formed `hsc1.<id>.<secret>`; the credential exists; the secret's digest equals the current or the next digest (constant time); not revoked; not expired | `401 service_credential_rejected` (one answer for every case) |
| The client certificate matches the credential's SPKI pin and/or SAN | `403 service_binding_mismatch` |
| Exactly one `x-hopae-audience`, equal to this instance's audience and allowed by the credential | `403 service_audience_mismatch` |
| `METHOD /path` is in the credential's allowlist **and** is a grantable read route (never a mutation, whatever the store says) | `403 service_route_forbidden` |
| The credential's token bucket has a token | `429 rate_limited` with `retry-after` |

Then the request runs as the read it targets, with the console's JSON API
rule (`content-type: application/json`, `x-hopae-admin-request: 1`), that
read's own per-actor bucket and its `admin.read` audit record. A service
credential is never combined with a delegation (`x-hopae-delegation`) and
never reads a browser cookie. The TLS peer is the client: forwarding headers
are not trusted on this path, and the addressed `Host` must be the console
host.

Grantable routes (no other route can be stored by the CLI):

| Route | Purpose |
| --- | --- |
| `POST /v1/groups/projection/snapshot`, `POST /v1/groups/projection/changes` | Signed membership projection ([groups](GROUPS.md)) |
| `POST /v1/subjects/lifecycle`, `POST /v1/subjects/lifecycle/snapshot` | Subject lifecycle feed and reconcile snapshot ([subject directory](SUBJECT_DIRECTORY.md)) |
| `POST /v1/subjects/resolve`, `POST /v1/subjects/search`, `POST /v1/subjects/groups` | Subject directory reads |
| `POST /v1/groups/search`, `POST /v1/groups/get` | Group reads |
| `POST /v1/explain/authentication` | [Authentication explain](AUTHENTICATION_EXPLAIN.md) |
| `GET /v1/status` | Status |

The preset `pumgye-v2` grants exactly the first four.

### Secrets, rotation and revocation

A token is `hsc1.<id>.<secret>`: the id (3–48 lowercase letters, digits and
inner `-`) and 32 random bytes in base64url. Only
`SHA-256("hopae:service-credential:v1\0" || id || 0x00 || secret)` is
stored; the secret is shown once by the CLI. Because the secret has 256 bits
of entropy, a fast domain-separated hash is sufficient (no password hashing).

Rotation without downtime: `rotate` issues a **next** secret (both current and
next are accepted; records show `credential_slot: next`); deploy it to the
caller; `promote` makes it current and the old secret stops working. A second
`rotate` is refused while one is pending. `revoke` keeps the row as a
tombstone (the id is never reused) and refuses every later change.

## Management API, console and observability

| Command | Effect |
| --- | --- |
| `hopae admin service-credentials create <id> (--preset pumgye-v2 \| --route "METHOD /path"…) [--audience A…] (--client-spki-sha256 HEX \| --client-san SAN)… [--expires-in-days 90] [--rate-per-minute 120] [--burst 30] [--note TEXT] --config <path>` | Create and print the token once (stdout); refused for a non-grantable route, no mTLS binding, a lifetime above 400 days, rate 1–6,000/min and burst 1–1,000 outside bounds, an existing id |
| `hopae admin service-credentials rotate <id>` | Issue and print the next secret |
| `hopae admin service-credentials promote <id>` | Next becomes current |
| `hopae admin service-credentials revoke <id>` | Revoke (tombstone) |
| `hopae admin service-credentials list` | Id, state, routes, audiences, binding, expiry, rotation, rate; never a secret or digest |

Each change commits with a required `admin.service_credential` event
(`attrs.change` = `created`, `rotated`, `promoted`, `revoked`;
`attrs.credential_id`; `attrs.actor = cli`). Each answered read writes its
`admin.read` with `attrs.actor = service:<id>`, `attrs.credential_id` and
`attrs.credential_slot`. Refusals are logged at warning level with the
refusal code and path (never the token) and counted in
`hopae_admin_service_credentials_total{result}` (`accepted`,
`accepted_next` or the refusal code).

## Limitations and compatibility

- Credentials live in the store and are managed by the CLI (safe while an
  instance runs); there is no HTTP management API for them, so an
  administrator session cannot mint one.
- The rate limit is per process; several instances each grant the configured
  rate.
- Certificate revocation (CRL/OCSP) of client certificates follows
  `client_ca` handling; revoke the service credential to cut a caller off at
  once.
- Schema 15 follows 0014; a branch that adds another 0015 must renumber.

## Examples, verification and related pages

```sh
hopae admin service-credentials create pumgye-v2 --preset pumgye-v2 \
  --client-san spiffe://cluster.example.test/ns/world/sa/pumgye \
  --client-spki-sha256 "$(openssl x509 -in pumgye.pem -pubkey -noout \
     | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1)" \
  --config /etc/hopae/hopae.json > /run/secrets/pumgye-hopae-token
```

Pumgye's `token_env` then holds the token, its TLS client identity is the
pinned certificate and it sends `x-hopae-audience`. Scenario
[318](../scenarios/318-service-credentials.md) specifies the behavior; threat
model TM-75 to TM-77. Related: [administration](ADMIN.md),
[groups](GROUPS.md), [subject directory](SUBJECT_DIRECTORY.md),
[threat model](THREAT_MODEL.md).
