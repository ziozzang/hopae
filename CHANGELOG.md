# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning 2.0.0](https://semver.org/).

## Unreleased

### Added

- Development process, documentation system, ADR and scenario templates, and roadmap.
- Architecture design, gateway contract v1 (with proposed gateway changes HC-1 to HC-9), threat model v0, ADR-0002 to ADR-0013 (Proposed), and draft scenarios 001–014 for milestone M1.

### Security

- Design revised after adversarial design review pass 1: browser-bound cross-domain handoff, gateway caller key required in M1, explicit account linking by default, user-info subject consistency, per-handle assurance level with rotation on elevation, authorization version checked at every verify, canonical path for policy rules, explicit return-origin allowlist, transactional event outbox, verify deadline budget, full decision-cache key with an absolute freshness deadline.
- Design revised after adversarial design review pass 2: handoff codes carry issuance level and credential generation and are consumed on elevation; Redis never caches session state and allows carry generation provenance; credential destinations are exact registered hosts only; per-sink delivery rows with at-least-once delivery and bounded backlog; the `401` names the application URL as the document bootstrap; stable per-browser binding and portal cookies; explicit account-switch confirmation; provider deletion tombstones; caller-key rotation overlap; one reserved-parameter recognition rule.
