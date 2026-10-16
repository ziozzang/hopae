-- Route-scoped, read-only service credentials for machine callers of the
-- admin listener (first consumer: Pumgye policy v2 reading the membership
-- projection and the subject lifecycle feed).
--
-- Numbered 0015: it follows 0014_groups. A store migrated by this file is
-- not downgraded by an older binary (the runner refuses a newer schema).
--
-- Secrets are never stored: `current_sha256` / `next_sha256` hold the
-- domain-separated SHA-256 of a 256-bit random secret (see
-- docs/SERVICE_CREDENTIALS.md). A revoked credential stays as a tombstone so
-- its id is never reused and the audit trail keeps resolving.
CREATE TABLE service_credentials (
    credential_id    TEXT PRIMARY KEY NOT NULL
                     CHECK (length(credential_id) BETWEEN 3 AND 48),
    -- JSON array of "METHOD /path" strings (exact match).
    routes           TEXT NOT NULL CHECK (length(routes) <= 4096),
    -- JSON array of audiences the bearer may be presented to.
    audiences        TEXT NOT NULL CHECK (length(audiences) <= 2048),
    -- mTLS binding: SHA-256 of the client certificate's SubjectPublicKeyInfo
    -- (lowercase hex) and/or an exact subject alternative name.
    client_spki_sha256 TEXT CHECK (client_spki_sha256 IS NULL OR length(client_spki_sha256) = 64),
    client_san       TEXT CHECK (client_san IS NULL OR length(client_san) BETWEEN 1 AND 512),
    current_sha256   TEXT NOT NULL CHECK (length(current_sha256) = 64),
    current_since    INTEGER NOT NULL,
    next_sha256      TEXT CHECK (next_sha256 IS NULL OR length(next_sha256) = 64),
    next_since       INTEGER,
    expires_at       INTEGER NOT NULL,
    rate_per_minute  INTEGER NOT NULL CHECK (rate_per_minute BETWEEN 1 AND 6000),
    burst            INTEGER NOT NULL CHECK (burst BETWEEN 1 AND 1000),
    note             TEXT CHECK (note IS NULL OR length(note) <= 256),
    created_at       INTEGER NOT NULL,
    revoked_at       INTEGER,
    revision         INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    CHECK (client_spki_sha256 IS NOT NULL OR client_san IS NOT NULL),
    CHECK ((next_sha256 IS NULL) = (next_since IS NULL))
) STRICT;
