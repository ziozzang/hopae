-- PostgreSQL schema, slice 2a (ADR-0020): login transactions and handoff
-- codes complete (SQLite migrations 0002 and 0003), plus the admission
-- history that rate limits transaction creation.
ALTER TABLE login_txns
    ADD COLUMN app_id                    TEXT NOT NULL DEFAULT '',
    ADD COLUMN return_target             TEXT NOT NULL DEFAULT '',
    ADD COLUMN bind_sha256               BYTEA CHECK (bind_sha256 IS NULL OR octet_length(bind_sha256) = 32),
    ADD COLUMN portal_bind_sha256        BYTEA CHECK (portal_bind_sha256 IS NULL OR octet_length(portal_bind_sha256) = 32),
    ADD COLUMN client_ip                 TEXT NOT NULL DEFAULT '',
    ADD COLUMN ua_sha256                 BYTEA,
    ADD COLUMN provider_id               TEXT,
    ADD COLUMN state_sha256              BYTEA,
    ADD COLUMN nonce                     TEXT,
    ADD COLUMN pkce_verifier             TEXT,
    ADD COLUMN portal_session_id         TEXT,
    ADD COLUMN conflicting_handle_sha256 BYTEA,
    ADD COLUMN pending_identity          TEXT,
    ADD COLUMN recovery_depth            INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN retry_bind_sha256         BYTEA,
    ADD COLUMN retry_used_at             BIGINT,
    ADD COLUMN reauth_max_age            INTEGER,
    -- Insertion order for eviction (SQLite's rowid).
    ADD COLUMN seq                       BIGINT GENERATED ALWAYS AS IDENTITY;
CREATE INDEX login_txns_state ON login_txns (state_sha256);
CREATE INDEX login_txns_expires ON login_txns (expires_at);

CREATE TABLE txn_admissions (
    ip TEXT NOT NULL,
    at BIGINT NOT NULL
);
CREATE INDEX txn_admissions_ip_at ON txn_admissions (ip, at);
CREATE INDEX txn_admissions_at ON txn_admissions (at);

ALTER TABLE handoff_codes
    ADD COLUMN host           TEXT NOT NULL DEFAULT '',
    ADD COLUMN return_target  TEXT NOT NULL DEFAULT '',
    ADD COLUMN return_path    TEXT NOT NULL DEFAULT '',
    ADD COLUMN client_ip      TEXT NOT NULL DEFAULT '',
    ADD COLUMN bind_sha256    BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000' CHECK (octet_length(bind_sha256) = 32),
    ADD COLUMN issued_aal     INTEGER NOT NULL DEFAULT 1 CHECK (issued_aal IN (1, 2)),
    ADD COLUMN cred_gen       BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN recovery_depth INTEGER NOT NULL DEFAULT 0;
CREATE INDEX handoff_codes_expires ON handoff_codes (expires_at);
CREATE INDEX events_ip_at_id ON events (client_ip, at, event_id);
