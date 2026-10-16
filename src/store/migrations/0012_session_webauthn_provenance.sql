-- Establishing WebAuthn proof metadata for the native Human owner path
-- (ADR-0017 phase 2). Mirrors session_totp_provenance: no key material,
-- no client data, no signature, no old-session backfill.
CREATE TABLE session_webauthn_provenance (
 session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 credential_generation INTEGER NOT NULL CHECK(credential_generation>0),
 credential_id BLOB NOT NULL CHECK(length(credential_id) BETWEEN 16 AND 1023),
 assurance TEXT NOT NULL CHECK(assurance IN ('aal2','aal3')),
 factor_index INTEGER NOT NULL CHECK(factor_index>=0),
 verified_at_ms INTEGER NOT NULL CHECK(verified_at_ms>=0),
 config_generation INTEGER CHECK(config_generation>0)
) STRICT;
