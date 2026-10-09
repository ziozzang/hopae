# Scenario specifications

Scenarios are the executable contract between a design and its tests. The
[development process](../docs/PROCESS.md#scenario-based-tdd) defines when they
are written and how they map to tests; [`000-template.md`](000-template.md) is
the template.

## Numbering

| Range | Area | Roadmap milestone |
| --- | --- | --- |
| 000 | Template | — |
| 001–099 | Core vertical slice: OIDC login, session, verify endpoint, portal, logout, path scope, header contract | M1 |
| 100–199 | Sessions and abuse controls: login history, blacklists, attempt throttling, shared cache, revocation | M2 |
| 200–299 | Providers: Kakao, Naver, email magic link, email and password, account linking | M3 |
| 300–399 | Management console and API | M4 |
| 400–439 | Lua hooks | M5 |
| 440–469 | Login-notification webhooks | M5 |
| 470–499 | Second-factor mechanism and factors | M5 |
| 500–599 | Lifecycle: signed self-update, configuration reload, release verification | M6 |
| 600–699 | Scale-out and operations: multi-instance, metrics, backup, key rotation | M7 |
| 900–999 | Cross-cutting security: cookie attributes, CSRF, response headers, crypto hygiene | all |

Allocate the next free number in the range. Numbers are never reused; a
withdrawn scenario keeps its file with status `withdrawn` and a reason.

## Status

| Status | Meaning | Set at |
| --- | --- | --- |
| `draft` | Being written; may change freely | G1–G3 |
| `approved` | Reviewed; tests may be written; coverage check enforces mapping | G3 exit |
| `implemented` | All mapped tests pass in `cargo test` | G6 |
| `verified-live` | Main flow and top abuse case ran against a live gateway and, where applicable, a real provider | G8 |
| `withdrawn` | No longer applies; reason recorded in the file | any |

## Test naming

Scenario `012`, case `012-3` → `fn s012_3_<slug>()`; abuse case `012-A2` →
`fn s012_a2_<slug>()`. Files live in `tests/scenarios/`. `make scenario-coverage`
enforces the mapping in both directions once a scenario is `approved`.
