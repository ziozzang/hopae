# Authentication explain API

<!-- doc-rev: 5 -->

[Documentation](README.md) · [한국어](ko/AUTHENTICATION_EXPLAIN.md)

`POST /v1/explain/authentication` answers, for a target URL and a subject,
what Hopae's authentication check would answer and why: which application
policy or service authentication profile applies, which providers and second
factors are available, the current, required and achievable assurance level,
which step-up rule decides and the freshness bound, as an ordered trace of
checks with stable reason codes and English and Korean messages. It is the
Hopae part of the explain and simulation flow of Hangang ADR 0019 and the
console of Hangang ADR 0020 (where it is called `/v1/admin/explain/authentication`;
on Hopae's admin listener the path is `/v1/explain/authentication`). It is HTTP
only, beside the rest of the [administration API](ADMIN.md).

## Prerequisites and configuration

- The management console is enabled; any granted role (`viewer` or `admin`)
  or a Hangang delegated console actor may call it. No configuration key.
- The request follows the console's JSON API rule (`content-type:
  application/json`, `x-hopae-admin-request: 1`, same-origin `Origin` and
  `sec-fetch-site` when present); see the [subject directory](SUBJECT_DIRECTORY.md#request-rule).

## Behavior

### Request

```json
{
  "url": "https://app.example.test/admin/reports",
  "navigation": "document",
  "session_id": "s_01J…",
  "subject": null,
  "client_ip": "192.0.2.10",
  "user_agent": null,
  "at": null,
  "hypothetical": {"aal": 2, "factors": ["totp"], "auth_age_seconds": 0, "provider_id": "mock", "auth_time_source": "hopae_completion"},
  "privacy_profile": "standard"
}
```

| Field | Meaning |
| --- | --- |
| `url` | The original URL the gateway would report (required, at most 2,048 bytes) |
| `navigation` | `document` (default) or `other` (a fetch or API call) |
| `session_id` | Evaluate this live session, as its handle on the URL's host would be evaluated |
| `subject` | Instead of a session: a user ID, a `human1:` subject, an `s_` service principal (resolved as by the [subject directory](SUBJECT_DIRECTORY.md)), or a Kubernetes workload as a SPIFFE ID (`spiffe://<td>/ns/<ns>/sa/<sa>`) or `system:serviceaccount:<ns>:<sa>` |
| `client_ip`, `user_agent` | The request's client; without `client_ip` the session binding and profile networks are reported as not evaluated |
| `at` | Unix seconds to evaluate at, at most 30 days from now (default now) |
| `hypothetical` | The session a sign-in would create: `aal` (1 or 2, default 1), `factors` (factor kinds such as `totp`, `webauthn`, `external`), `auth_age_seconds`, `provider_id` (default the subject's first linked provider, else the first enabled provider), `auth_time_source` (`hopae_completion` default, `provider_claim`) |
| `risk` | A hypothetical risk context ([ADR-0023](adr/0023-risk-based-step-up.md)): `context` (the claims the gateway would sign, as in the [contract](GATEWAY_CONTRACT.md#risk-context); absent: no context), `session_country`, `session_asn`, `user_countries` (what the session memory would know). Only for an application with `apps[].risk` |
| `privacy_profile` | `standard` or `strict`, for the subject's display data; raised to `admin.directory_privacy` when that is stricter |

`session_id` and `subject` are mutually exclusive; with neither the request is
anonymous. A malformed request is `400 invalid_request`.

### Evaluation

The evaluation calls the functions the live paths call, in the live order, on
the current configuration snapshot and service profile publication:

1. the gateway adapter's canonical path (`path_not_canonical`);
2. transport and return-target validation and the application
   (`insecure_transport`, `unknown_app`, `app_disabled`, `port_not_allowed`,
   `contract_violation`);
3. the reserved `/_hopae` namespace (`reserved_path`; the entry points are
   `not_applicable`);
4. a service authentication profile serving the host and port: publication in
   progress (`authority_unavailable`); a service principal's API-key path with
   the same expiry rule, network predicate and eligibility script as the live
   path (`service_principal_unknown`, `credential_expired`, `network_denied`,
   `eligibility_denied`, `eligibility_unavailable`); remote connectors
   (`remote_verifier`, `indeterminate`); step-up rules, which a service or
   workload principal at AAL 0 cannot satisfy (`machine_step_up`); a profile
   without session fallback refuses browser sessions
   (`service_credential_required`); a service principal on a host without a
   profile (`service_profile_absent`); for a Kubernetes workload subject, the
   workload connector's predicates in the live order — subject form and
   trust domain (`workload_subject_invalid`), network (`network_denied`),
   namespace and ServiceAccount allowlists
   (`workload_namespace_not_allowed`, `workload_service_account_not_allowed`),
   the legacy window (`workload_legacy_window_expired`), key freshness
   (`workload_keys_unavailable`) and the revocation index
   (`workload_revocation_stale`, `workload_service_account_absent`, or
   `workload_revocation_not_evaluated` without a watch); the token checks
   themselves need the real token (`workload_token_not_simulated`) and the
   trace reports the SPIFFE ID and, when the revocation index knows the
   ServiceAccount UID, the `wk2:` principal and wire subject;
5. for a session: termination, its live handle on the host (`handle_absent`),
   the lifetime state machine (`idle`, `absolute`, `clock_skew`), the binding
   policy (`binding_ip`, `binding_ua`, or `binding_not_evaluated`), the user's
   status and authorization version (`user_disabled`, `authz_change`);
6. the step-up rules (`step_up_required`; a document request with no second
   factor configured is refused with `step_up_unavailable`; an AAL 1 rule with
   `max_age` asks for a new sign-in, `reauth_required`) and the console
   freshness bound (`reauth_required`).

Nothing is written: no session, handle, login transaction, handoff code or
`last_seen_at` touch is created, a session found expired is not terminated and
the service runtime's observed-time floor is not advanced. The only record is
the `admin.read` audit event.

When the request would be sent to sign in (`login`), `after_login` evaluates
the same step-up and freshness checks on the session the sign-in would give:
the live session itself when the portal would hand it over (`basis:
"handoff"`, for `handle_absent`), else a hypothetical fresh sign-in (`basis:
"sign_in"`, shaped by `hypothetical`). A disabled user's sign-in is refused
(`user_disabled`); an unknown or deleted subject is `indeterminate`
(`subject_unknown`, `subject_deleted`).

### Answer

| Field | Meaning |
| --- | --- |
| `outcome` | `allow`, `login`, `step_up`, `reauth`, `deny`, `unavailable`, `indeterminate`, `not_applicable` |
| `status_code` | The status the gateway's answer carries (`200`, `302`, `401`, `403`, `503`), `null` when not determined |
| `reason` | `code` (`hopae.<reason>`), `message_key` (`hopae.explain.<reason>`), `message` |
| `application` | The application policy: lifetimes, binding, `on_authz_change`, `max_auth_age_seconds`, `step_up_rules`, `config_generation` |
| `service_profile` | The service profile: `service_id`, `realm`, `connectors`, `session_fallback`, `networks_restricted`, `client_ip_permitted`, `eligibility_script`, `revision` |
| `subject` | `input` (`session`, `subject`, `anonymous`) and the resolved `item` |
| `session` | The evaluated session: provider, `aal`, `handle_aal`, factors, `auth_time` and its source |
| `providers` | The configured providers in chooser order, with `enabled`, `reauth` capability and `linked` for the subject |
| `assurance` | `current_aal`, `required_aal`, `achievable_aal` and the configured second factors (`totp_configured`, `totp_enrolled`, `external`) |
| `step_up` | `matched_rules`, `deciding_rule` (index), `required_aal`, `verdict`; with risk rules also `risk`: `context`, `memory`, `missing`, `matched_rules`, `deciding_rule`, `action` (the trace has a `risk` check; risk step-up rules are added to the step-up rules evaluated) |
| `freshness` | `max_auth_age_seconds`, `auth_age_seconds`, `auth_time_source`, `provider_capability`, `fresh` |
| `after_login` | The post-sign-in evaluation described above, with its own `trace` |
| `trace` | Every check made: `check`, `result` (`pass`, `fail`, `skip`, `info`), `reason`, `detail` |
| `evaluated_at`, `config_generation`, `service_profile_revision`, `simulated` | The evaluated time and revisions; `simulated` is always `true` |

`message` is in the request's `accept-language` (English or Korean, English by
default); a console with its own catalogue uses `message_key`. The catalogue:

| Code | English message |
| --- | --- |
| `allowed` | The request would be allowed. |
| `unknown_app` | No application is registered for this host. |
| `app_disabled` | The application for this host is disabled. |
| `port_not_allowed` | The port is not one of the application's ports. |
| `insecure_transport` | Plain HTTP is refused while secure cookies are configured. |
| `contract_violation` | The target URL is not a valid return target. |
| `path_not_canonical` | The path is not canonical; the gateway refuses it. |
| `reserved_path` | The path is in the reserved /_hopae namespace. |
| `entry_point` | The path is a Hopae entry point, not an access decision. |
| `login_required` | There is no session: the request is sent to sign in. |
| `handle_absent` | The session has no handle on this host: the browser goes to the portal, which hands a live session over without a new sign-in. |
| `unknown_handle` | The session does not exist. |
| `session_terminated` | The session was terminated. |
| `idle` | An idle timeout has expired. |
| `absolute` | An absolute lifetime has expired. |
| `clock_skew` | A stored time lies in the future beyond the tolerance; the request is answered as unavailable. |
| `binding_ip` | The client address does not match the session's binding. |
| `binding_ua` | The user agent does not match the session's binding. |
| `binding_not_evaluated` | No client address was given, so the binding policy was not evaluated. |
| `user_disabled` | The user is disabled. |
| `authz_change` | The user's authorization changed since sign-in and this application ends such sessions. |
| `step_up_required` | A step-up rule requires a higher assurance level or a fresher second factor. |
| `step_up_unavailable` | A step-up is required but no second factor is configured, so the request is refused. |
| `risk_denied` | A risk rule denies requests in this network context. |
| `risk_context_missing` | The gateway sent no risk context and this application refuses requests without one. |
| `reauth_required` | The sign-in is too old for this path; the user must sign in again. |
| `subject_unknown` | The subject is not known to Hopae; a sign-in creates or links an account. |
| `subject_deleted` | The subject was deleted; a new sign-in creates a different subject. |
| `service_credential_required` | A service profile serves this host and port and does not fall back to browser sessions. |
| `service_profile_absent` | A service credential is presented but no service profile serves this host and port. |
| `service_principal_unknown` | The principal is not an API-key subject of this profile. |
| `credential_expired` | The service credential has expired. |
| `network_denied` | The client address is outside the profile's networks. |
| `network_not_evaluated` | No client address was given, so the profile's networks were not evaluated. |
| `eligibility_denied` | The profile's eligibility script refuses this principal. |
| `eligibility_unavailable` | The profile's eligibility script could not run now; the request is answered as unavailable. |
| `remote_verifier` | A remote connector verifies this credential at request time; its verdict cannot be simulated. |
| `machine_step_up` | Service and workload principals have AAL 0 and cannot satisfy a step-up rule. |
| `authority_unavailable` | Service authentication is being republished; requests are answered as unavailable. |
| `workload_subject_invalid` | The workload is not a SPIFFE ID of this trust domain or a system:serviceaccount name. |
| `workload_namespace_not_allowed` | The workload's namespace is not allowed by the service profile. |
| `workload_service_account_not_allowed` | The ServiceAccount is not in the profile's ServiceAccount allowlist. |
| `workload_service_account_absent` | The ServiceAccount does not exist in the current revocation index. |
| `workload_keys_unavailable` | The issuer's signing keys are unavailable or older than the staleness bound. |
| `workload_revocation_stale` | The revocation index is not current within its staleness bound. |
| `workload_legacy_window_expired` | The legacy Pod-bound subject compatibility window has ended. |
| `workload_revocation_not_evaluated` | No revocation watch is configured; deleted ServiceAccounts are refused only at token expiry. |
| `workload_token_not_simulated` | Token checks (signature, audience, lifetime, bound objects) need the real token and are not simulated. |

## Management API, console and observability

Errors: `400 invalid_request`, `403` from the console's authentication and
JSON API rule, `429 rate_limited` with `retry-after` (per actor: 30 requests
burst, one every two seconds), `503 store_unavailable`, `503
audit_unavailable`.

Every answer writes a required `admin.read` event first: `attrs.purpose =
explain.authentication`, `attrs.endpoint`, `attrs.query_sha256`, the outcome
in `attrs.status`, `attrs.host`, `attrs.port`, `attrs.navigation`,
`attrs.app`, the actor attributes, and the evaluated user and session in the
event's `user_id` and `session_id` columns. Answers carry
`cache-control: no-store`.

## Limitations and compatibility

- A session is evaluated through its newest live handle on the URL's host;
  the explain API never sees a handle value. For `handle_absent` the portal
  handle's level is assumed to be the session's.
- Credentials verified by remote connectors (API relay, Kubernetes
  TokenReview, composed credentials) are `indeterminate`.
- Per-request rate limits of the live path (login transactions, handoff
  failures) and store availability are not simulated.
- The time shift moves the evaluation clock only; configuration and state are
  current.

## Examples, verification and related pages

```sh
curl -sS https://hopae-admin.example.test/v1/explain/authentication \
  -H 'content-type: application/json' -H 'x-hopae-admin-request: 1' \
  -H 'accept-language: ko' -b '__Host-hopae=<redacted>' \
  -d '{"url":"https://app.example.test/admin","subject":"u_01HZY5W0000000000000000000"}'
```

Scenario [309](../scenarios/309-authentication-explain.md) compares explain
with the live verify endpoint on the same state for every session state it
covers. Related: [subject directory](SUBJECT_DIRECTORY.md),
[gateway contract](GATEWAY_CONTRACT.md), [administration](ADMIN.md),
[threat model](THREAT_MODEL.md) (TM-61).
