# WebAuthn passkeys

<!-- doc-rev: 5 -->

[Documentation](README.md) · [한국어](ko/WEBAUTHN.md)

Passkeys (WebAuthn credentials) are Hopae's phishing-resistant second factor.
Users register them on the portal, use them when an application's step-up rule
asks for AAL 2, and manage them on the portal's security pages. The decision
record is [ADR-0017](adr/0017-webauthn-passkeys.md); this page is the operator
and integrator reference.

## Status

First pass, in source, **off by default**. Without a `webauthn` object in the
configuration every route below answers `404`, no WebAuthn row is written and
existing deployments behave exactly as before. Live end-to-end verification
(G8) and the adversarial reviews (G2, G7) are pending; the ADR is `Proposed`.

Implemented: registration and step-up with passkeys, the security overview,
passkey list, rename and removal, the portal security confirmation, recovery
codes, the last-factor rule, sign-count regression handling, administrator reset
and listing from the command line, AAL 3 classification (recorded only).

Phase 2 adds passwordless sign-in with conditional UI and native Human owner
provenance. Not implemented: factor management in the console and a passkey
requirement for console operators; AAL 3 emission is described below. See the [roadmap](ROADMAP.md#m5--extension-points-050).

## Goal and non-goals

Goal: a user can add passkeys (platform authenticators such as Touch ID, Face ID,
Windows Hello and Android screen lock, password-manager passkeys, and security
keys over USB, NFC or Bluetooth), use one to satisfy an application's AAL 2 rule,
recover from a lost device with a recovery code, and never lock themselves out
by removing their last factor.

Non-goals: passkeys as a first factor (passwordless), attestation-based device
policy beyond the optional high-assurance allowlist, synchronizing credentials
between deployments, and any change to the gateway contract or to peers.

## Configuration

```json
{
  "webauthn": {
    "rp_id": "auth.example.test",
    "rp_name": "Example sign-in",
    "high_assurance": {
      "attestation_ca_files": ["/etc/hopae/webauthn/vendor-root.pem"],
      "aaguids": ["cb69481e-8ff7-4039-93ec-0a2729a154a8"]
    }
  }
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `webauthn` | absent | Enables passkeys. Requires authenticated gateway callers (`gateway.allow_unauthenticated_caller = false`) and an `https` portal. |
| `webauthn.rp_id` | the host of `portal.public_url` | The relying-party ID. May be the portal host or a parent domain of it on a label boundary; never an IP literal or a single label. **Changing it later makes every registered passkey unusable.** |
| `webauthn.rp_name` | `Hopae` | Name the authenticator shows. 1–64 characters. |
| `webauthn.high_assurance.attestation_ca_files` | none | PEM files of authenticator vendor roots. With `aaguids`, enables the "security key (high assurance)" registration. |
| `webauthn.passwordless` | `false` | Offer passwordless passkey sign-in on the sign-in page. |
| `webauthn.high_assurance.aaguids` | none | AAGUIDs that may be classed AAL 3. Required with `attestation_ca_files`. At most 64. |

The allowed origin is always exactly the portal origin; it is not configurable.
`hopae --check` validates the keys, reads the CA files and reports the effective
RP ID.

## Pages and routes

All routes are on the portal listener, require HTTPS and a live portal session,
answer `404` without `webauthn`, and send `cache-control: no-store`. Every POST
requires a CSRF token bound to the portal handle and an exact `Origin`.

| Route | Purpose |
| --- | --- |
| `GET /security` | Overview: passkeys, authenticator app, recovery codes, recovery-required banner. |
| `GET /security/passkeys` | List with name, kind (synced or device-bound), created and last-used times; rename and remove forms. |
| `GET /security/passkeys/new`, `POST /security/passkeys/new` | Registration ceremony (`?kind=high_assurance` for attested security keys when configured). |
| `POST /security/passkeys/rename`, `POST /security/passkeys/remove` | Rename (live session) and remove (recent second factor, never the last factor). |
| `GET /security/verify`, `POST /security/verify/passkey`, `POST /security/verify/totp`, `POST /security/verify/recovery` | Security confirmation: proves a second factor and elevates the portal session for factor management. |
| `GET /security/recovery-codes`, `POST /security/recovery-codes` | Status and (re)generation; codes are displayed once. |
| `GET /stepup?txn=…` | Offers a passkey first when the user has one, with links to the authenticator app, external factors and the recovery-code path; a user without any factor is sent to `/security`. |
| `POST /stepup/webauthn` | Completes an application step-up with a passkey. |
| `GET /assets/webauthn.js` | The only portal script ([ADR-0017](adr/0017-webauthn-passkeys.md) decision 3). |

Pages that run a ceremony send `script-src 'self'`, `require-trusted-types-for
'script'` and a `Permissions-Policy` limited to the portal origin; every other
page keeps the no-script policy. Without JavaScript the page says so and links
the other methods.

### Browser and authenticator notes

- The ceremony starts from a button press (Safari and iOS require a user gesture).
- Registration requests user verification and a non-resident credential by default; platforms that always create discoverable passkeys (iCloud Keychain, Google Password Manager) still work.
- `excludeCredentials` lists the user's existing passkeys, so the same authenticator is not registered twice; the browser reports this and the page explains it.
- The page names a passkey from its AAGUID when it is a known provider (for example iCloud Keychain, Google Password Manager, Windows Hello, 1Password, Bitwarden, YubiKey); otherwise "Passkey" or "Security key". Users can rename it.
- After the first passkey the user is taken to create recovery codes; after using a recovery code every security page asks for a new factor.
- A step-up still requires a primary sign-in at most five minutes old (the TOTP rule); an older session is sent through provider reauthentication first.
- Cancelled or timed-out prompts (`NotAllowedError`), an already registered authenticator (`InvalidStateError`), an RP ID mismatch (`SecurityError`) and missing support each have their own message in English and Korean.

## Assurance

| Evidence | Session effect | Recorded class |
| --- | --- | --- |
| Passkey assertion with user verification | `aal` 2, factor `webauthn` | `aal2` |
| High-assurance credential (attested to a configured CA, allowlisted AAGUID, not backup-eligible) asserted with user verification and not backed up | `aal` 2, factor `webauthn` | `aal3` (recorded only) |
| Recovery code | `aal` unchanged (1), factor `recovery`; re-enrollment required | — |

AAL 3 is not emitted in this release; the [ADR](adr/0017-webauthn-passkeys.md#aal-3-wire-analysis)
lists every reader that would have to change first. `x-hopae-aal` stays `1` or `2`.
A recovery entry never satisfies an AAL 2 step-up rule.

## Passwordless sign-in

With `webauthn.passwordless = true` the sign-in page offers a passkey beside the
providers ([ADR-0017](adr/0017-webauthn-passkeys.md) decision 16):

- The passkey field (`autocomplete="username webauthn"`) shows saved passkeys in the browser's autofill (conditional mediation: Chrome, Edge, Safari, Firefox); the "Sign in with a passkey" button opens the modal prompt (security keys, phones over hybrid transport).
- No username or password is asked for; the passkey's user handle names the account. Every failure — unknown passkey, another account's credential, disabled user, bad signature — returns the same message.
- The session is AAL 2 with factor `webauthn` and provider `hopae.passkey` (`x-hopae-provider`), lives while that passkey is active, and reaches every application by single sign-on like any other session.
- Ceremonies are bound to the sign-in transaction, the browser's binding cookie and its address; at most 30 per address per minute. When none can be offered, the page behaves as without passkeys (one provider is used directly).
- Passkeys registered while passwordless sign-in is on are requested discoverable (`residentKey: preferred`); passkeys registered earlier on a security key may not be.
- Limitations: an application's `max_auth_age` reauthentication cannot be completed with a passkey (the user signs out and in); the native Human owner path refuses passkey sessions.

## Native Human owner path

A passkey elevation records its establishing credential in
`session_webauthn_provenance` (migration 12), the counterpart of the
[native TOTP provenance](HUMAN_TOTP_PROVENANCE.md). The native Human owner and its
signed receipts accept such an AAL 2 handle while the record is current: same
session generation and factor entry, the passkey still active, the configuration
generation unchanged. Receipts still carry AAL 2 and no factor kind; Hangang and
Pumgye need no change. Sessions elevated before the migration stay refused on
this path only.

## Data

Migration `0011_webauthn` adds `webauthn_credentials`, `webauthn_challenges`,
`recovery_codes` and `session_webauthn_elevations`, and the nullable columns
`users.webauthn_user_handle` and `users.factor_recovery_required_at`. No
existing row changes; an older binary refuses to open the migrated store, as for
every migration (restore the pre-migration backup to roll back).

## Failure behavior

- Store unavailable: every page and ceremony fails closed (`503`).
- Challenge expired, consumed or bound to another session, handle or browser: the ceremony is refused and the page offers a new attempt.
- Signature, origin, RP ID or user-verification failure: refused, challenge consumed, `factor.webauthn_failed` recorded.
- Counter regression after a valid signature: credential revoked, the sessions it elevated terminated, `factor.webauthn_clone_suspected` recorded.
- Removal of the last factor: refused with an explanation.

## Administration

```text
hopae admin factors list <user-id-or-email>
hopae admin factors reset <user-id-or-email>
```

`reset` revokes every passkey, TOTP enrollment and unused recovery code of the
user, terminates every session and records `admin.factor_reset`. The user enrolls
again after a fresh sign-in.

## Events

`factor.webauthn_registered`, `factor.webauthn_used`, `factor.webauthn_renamed`,
`factor.webauthn_revoked`, `factor.webauthn_failed`,
`factor.webauthn_clone_suspected`, `factor.recovery_codes_generated`,
`factor.recovery_code_used`, `admin.factor_reset`. Credential IDs appear only as
`factor_id` (`pk_` plus 16 hex digits of their SHA-256).

## Testing

Store, relying-party and process-level tests use `webauthn-authenticator-rs`
software authenticators (a software passkey and an attesting software token):
registration, assertion, wrong origin and RP ID, replay and expiry, browser
binding, counter regression, last-factor refusal, recovery-code single use,
AAL derivation and the default-off configuration. Scenarios 480–487 map the
cases.

`tools/browser-qual/run.sh` qualifies the pages in a real Chrome over the
DevTools protocol with its WebAuthn virtual authenticator, against a local
stack (mock provider, the script as TLS terminator and verify-driven gateway):
registration, duplicate and refused prompts, step-up, rename and removal,
recovery codes, passwordless sign-in with conditional mediation, Korean pages at
390 px, and the absence of script errors. It downloads nothing; it needs Docker
with an image containing Chrome, Node.js and an existing `playwright-core`.
A live Hangang gateway and hardware authenticators remain the open part of G8.

## Related pages

- [ADR-0017](adr/0017-webauthn-passkeys.md), [ADR-0008](adr/0008-second-factor-extension-point.md)
- [Second-factor extensions](SECOND_FACTOR_EXTENSIONS.md), [Threat model](THREAT_MODEL.md), [Configuration](CONFIG.md)
