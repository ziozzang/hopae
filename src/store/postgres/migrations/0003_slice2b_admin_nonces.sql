-- PostgreSQL schema, slice 2b (ADR-0020): administrator grants (SQLite
-- migration 0003) and the shared replay ledger for nonces.
CREATE TABLE admin_grants (
    user_id      TEXT PRIMARY KEY REFERENCES users (user_id),
    role         TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    managed_by   TEXT NOT NULL CHECK (managed_by IN ('file', 'api')),
    source_email TEXT,
    granted_at   BIGINT NOT NULL,
    granted_by   TEXT NOT NULL,
    revoked_at   BIGINT,
    revoked_by   TEXT,
    note         TEXT
);
CREATE INDEX admin_grants_source_email ON admin_grants (source_email) WHERE source_email IS NOT NULL;

-- A nonce is admitted once per scope while live, on every replica.
CREATE TABLE replay_nonces (
    scope      TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 64),
    nonce      TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 256),
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (scope, nonce)
);
CREATE INDEX replay_nonces_expiry ON replay_nonces (scope, expires_at);
