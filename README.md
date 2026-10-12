# Hopae

<!-- doc-rev: 5 -->

[Documentation](docs/README.md) · [Roadmap](docs/ROADMAP.md) · [Release notes](CHANGELOG.md) · [한국어](README.ko.md)

**A single-binary identity provider for zero-trust gateways, written in Rust.**

Hopae (`호패`) is named after the Joseon-era state-issued identity tag. It signs
people in through OAuth/OIDC providers or email, keeps their sessions, and
answers a gateway's "who is this request from?" question so that the gateway
can inject verified identity into upstream requests. It is packaged around the
[Hangang](https://github.com/ziozzang/hangang) gateway's external
authentication check, and it stays usable behind any gateway that can forward
such a check.

> **Status: milestone M1 (vertical slice) plus the M4-min management console
> (available), unreleased.** Version 0.1.0 is not cut yet. What works today is
> described under [What works today](#what-works-today); everything under
> [Not yet](#not-yet) is design only. See the [roadmap](docs/ROADMAP.md).

## How it fits

1. A browser requests a protected route on the gateway without a session.
2. The gateway's forward-authentication check asks Hopae; Hopae answers with a
   redirect to its login portal, which runs on its own host and is itself a
   route on the same gateway.
3. The user signs in with a provider or email; Hopae creates a session and
   redirects back to the application.
4. On every following request the gateway asks Hopae again, receives verified
   identity headers, injects them into the upstream request and strips any
   copies the client sent.

This is close to a standard OAuth deployment; the difference is that the
gateway already owns routing, header injection and stripping, so Hopae
provides only the portal, providers, sessions and policy.

## What works today

The base is one complete path: **Google sign-in, server-side sessions and
Hangang forward-authentication**, with a minimal management console on top of
it.

- **Sign-in** — OpenID Connect against Google (authorization code flow with PKCE, ID-token validation, discovery and key caching). Providers are defined in the JSON configuration file; a provider whose secret variable is missing is disabled, not fatal.
- **Sessions** — server-side sessions stored in SQLite, per-host handle cookies bound to the browser, configurable idle and absolute timers and client IP/User-Agent binding per application, logout, and explicit account linking by verified email.
- **Gateway integration** — the verify endpoint (`/_hopae/verify`) of the [gateway contract](docs/GATEWAY_CONTRACT.md): caller-key authentication with rotation, fail-closed answers, identity headers for the gateway to inject, and cross-domain single sign-on between registered hosts through a browser-bound handoff.
- **Operations** — `hopae --check` preflight (prints the route fragment and redirect URIs to register), single-instance lock, backup before a schema migration, graceful shutdown, structured event log with transactional audit events, `/healthz`. See [operations](docs/OPERATIONS.md).
- **Management console (M4-min)** — an optional third listener, reached through its own protected gateway route, with pages and a JSON API to list and search users, disable and enable a user, end one or all sessions, browse the login history and the audit trail, and read the status of applications, providers, store and build. Administrators are granted with `hopae admin grant` or `admin.users[]`; console freshness is a provider-verified reauthentication where the provider supports it and Hopae login age otherwise (Google). See [administration](docs/ADMIN.md).
- **Packaging** — a static binary and a hardened Docker Compose template in [`deploy/`](deploy/).

Production use needs a gateway that sends the caller key (Hangang change HC-3);
an unmodified gateway works for development only with caller authentication
turned off. See the compatibility matrix in the contract.

## Not yet

Everything here is planned, not shipped; see the [roadmap](docs/ROADMAP.md).

- Other providers (Kakao, Naver, email magic link, email and password), second factors, step-up enforcement.
- Blacklists and throttling beyond the per-IP bounds, shared state for several instances (PostgreSQL, Redis/Valkey), managing providers and applications from the console, Hopae's own second factor for administrators.
- Lua hooks, webhooks, Prometheus metrics, configuration reload, signed self-update.

## Quick start

Build (Rust 1.96 or newer) or use the container image, write a configuration
file, and check it before running:

```sh
cargo build --release --locked
export HOPAE_GATEWAY_KEY=change-me                    # the caller key shared with the gateway
export HOPAE_PROVIDER_GOOGLE_CLIENT_SECRET=change-me  # Google OAuth client secret
target/release/hopae --check --config deploy/hopae.example.json
target/release/hopae run     --config deploy/hopae.example.json
```

`--check` prints what to register elsewhere: the gateway route `auth`
fragment, the return origins and the provider redirect URI
(`<portal.public_url>/callback/google`). Then register the portal route and
your protected routes on the gateway (examples in
[`deploy/hangang-routes.example.json`](deploy/hangang-routes.example.json)) and
open a protected host in a browser. For a hardened container deployment follow
[`deploy/README.md`](deploy/README.md).

## Documentation

- [Documentation index](docs/README.md)
- [Gateway contract](docs/GATEWAY_CONTRACT.md) — the verify protocol, headers, cookies and route fragments
- [Configuration reference](docs/CONFIG.md) — every key, default and CLI command
- [Administration](docs/ADMIN.md) — the management console, its API, administrator grants and freshness
- [Operations](docs/OPERATIONS.md) — running, state, backups, key rotation, logs, health, failure behavior
- [Development process](docs/PROCESS.md) — roles, phase gates, scenario-based TDD, release and security rules
- [Documentation system](docs/DOCUMENTATION.md) — layout, translation rules, style, required documents
- [Architecture decision records](docs/adr/)
- [Scenario specifications](scenarios/)
- [Roadmap](docs/ROADMAP.md)

## Contributing

Every change follows the [development process](docs/PROCESS.md): a design
record, an adversarial review, a scenario specification, a failing test, then
the implementation. English documents are canonical; Korean translations are
updated in the same change.

## License

[MIT](LICENSE) © 2026 Jioh Jung

[Native Hangang integration](docs/HANGANG_NATIVE.md) adds bounded persistent verification and trusted console menus while retaining Hopae provider/session authority.

## Service authorization ownership

[Pumgye (품계)](https://github.com/ziozzang/pumgye) owns service-scoped roles,
permissions, information classes and user/network assignments. Hopae's native
verification establishes identity and assurance; Hangang's embedded Pumgye gate
then enforces access with Sumunjang network evidence. Successful authentication
alone does not grant service access: unassigned users remain guest and the
auth-proxy refuses protected requests. Hopae retains provider, user and session
ownership; native console grants remain distinct from service permissions.
