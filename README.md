# Hopae

<!-- doc-rev: 1 -->

[Documentation](docs/README.md) · [Roadmap](docs/ROADMAP.md) · [Release notes](CHANGELOG.md) · [한국어](README.ko.md)

**A single-binary identity provider for zero-trust gateways, written in Rust.**

Hopae (`호패`) is named after the Joseon-era state-issued identity tag. It signs
people in through OAuth/OIDC providers or email, keeps their sessions, and
answers a gateway's "who is this request from?" question so that the gateway
can inject verified identity into upstream requests. It is packaged around the
[Hangang](https://github.com/ziozzang/hangang) gateway's external
authentication check, and it stays usable behind any gateway that can forward
such a check.

> **Status: in design.** No release exists yet. The documents linked below
> define how the project is built; product documents appear as each milestone
> lands. See the [roadmap](docs/ROADMAP.md).

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

## Planned scope

Sections marked *in design* describe intent, not shipped behavior.

- **Sign-in providers** *(in design)* — OIDC/OAuth 2.0 (Google first), Kakao,
  Naver, email magic link, email and password.
- **Sessions** *(in design)* — server-side sessions, logout everywhere, optional
  Redis/Valkey shared cache for multi-instance deployments.
- **Gateway integration** *(in design)* — a forward-authentication endpoint that
  returns verified identity headers for the gateway to inject, with path-scoped
  protection and login/logout entry points.
- **Abuse controls** *(in design)* — login history, blacklists, login-attempt
  throttling and lockout.
- **Management** *(in design)* — a web console and management API for users,
  sessions, providers, policies and audit.
- **Extension points** *(in design)* — Lua hooks, login-notification webhooks,
  and a pluggable second-factor mechanism (TOTP, WebAuthn, and others).
- **Lifecycle** *(in design)* — signed self-update from GitHub releases.

## Documentation

- [Documentation index](docs/README.md)
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
