-- Establishing native TOTP proof metadata only; no secret, code or old-session backfill.
CREATE TABLE session_totp_provenance (
 session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 credential_generation INTEGER NOT NULL CHECK(credential_generation>0),
 enrollment_id TEXT NOT NULL,
 enrollment_revision INTEGER NOT NULL CHECK(enrollment_revision>0),
 factor_index INTEGER NOT NULL CHECK(factor_index>=0),
 verified_at_ms INTEGER NOT NULL CHECK(verified_at_ms>=0),
 config_generation INTEGER CHECK(config_generation>0)
) STRICT;
