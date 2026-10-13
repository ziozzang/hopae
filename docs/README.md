# Documentation

<!-- doc-rev: 10 -->

[한국어 목차](ko/README.md)

English is the reference language. Korean pages under `ko/` are full
translations of their English sources and are updated in the same change. The
[repository README](../README.md) states the product's purpose and status.

## Project

- [Development process](PROCESS.md) — roles, phase gates, adversarial review, scenario-based TDD, releases, security rules
- [Documentation system](DOCUMENTATION.md) — layout, language rule, style guide, required documents, validation
- [Roadmap](ROADMAP.md) — product shape, milestones, scenario ranges
- [Architecture decision records](adr/) — numbered decisions; start with [ADR-0001](adr/0001-record-architecture-decisions.md)
- [Scenario specifications](../scenarios/README.md) — numbering, status, test naming
- [Changelog](../CHANGELOG.md)

## Product

- [Architecture](ARCHITECTURE.md) — components, trust boundaries, request flows, data model, storage, crate layout, failure behavior
- [Gateway contract](GATEWAY_CONTRACT.md) — the versioned verify protocol, identity headers, cookies, handoff, cache and invalidation semantics, proposed gateway changes
- [Threat model](THREAT_MODEL.md) — assets, actors, entry points, STRIDE per flow, mitigations
- [Configuration reference](CONFIG.md) — every key, default and constraint, the command line and exit codes
- [Operations](OPERATIONS.md) — running, state directory, instance lock, backups, key rotation, logs, health, counters, failure behavior
- [Administration](ADMIN.md) — the management console and `/v1` API (M4-min, specified): console host and route, grants and roles, pages, endpoints, audit events, limits
- [Deployment template](../deploy/README.md) — hardened Docker Compose service and gateway route examples

Further reference pages (providers, sessions, management) are added as
milestones land. The [roadmap](ROADMAP.md) describes the intended shape.

- [Native Hangang integration](HANGANG_NATIVE.md) — HOP1 verification and delegated console.

- [Authentication profile publication](AUTH_PROFILE_PUBLICATION.md) — proposed durable ownership and snapshot publication contract.

- [LDAP authentication](LDAP_AUTHENTICATION.md) — proposed direct-credential provider and lifecycle contract.

- [Second-factor extensions](SECOND_FACTOR_EXTENSIONS.md) — native OTP and external API/Lua boundaries.

- [Kubernetes workload authentication](KUBERNETES_WORKLOAD.md) — native Pod-bound TokenReview connector; profile/transport integration pending.
