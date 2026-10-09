-- Migration 0003: administrator grants, freshness provenance, console listings (ADR-0016).
CREATE TABLE admin_grants (
    user_id      TEXT PRIMARY KEY NOT NULL REFERENCES users (user_id),
    role         TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    managed_by   TEXT NOT NULL CHECK (managed_by IN ('file', 'api')),
    source_email TEXT,                   -- the address the grant was resolved from, if any; never re-resolved
    granted_at   INTEGER NOT NULL,
    granted_by   TEXT NOT NULL,          -- a user id, 'cli' or 'file'
    revoked_at   INTEGER,
    revoked_by   TEXT,
    note         TEXT
) STRICT;
CREATE INDEX admin_grants_source_email ON admin_grants (source_email) WHERE source_email IS NOT NULL;
ALTER TABLE sessions ADD COLUMN bound_ua_prefix TEXT;
ALTER TABLE sessions ADD COLUMN auth_time_source TEXT NOT NULL DEFAULT 'hopae_completion'
    CHECK (auth_time_source IN ('provider_claim', 'hopae_completion'));
ALTER TABLE login_txns ADD COLUMN reauth_max_age INTEGER;
DROP INDEX events_at;
DROP INDEX events_user_at;
DROP INDEX events_ip_at;
CREATE INDEX events_at_id ON events (at, event_id);
CREATE INDEX events_user_at_id ON events (user_id, at, event_id);
CREATE INDEX events_ip_at_id ON events (client_ip, at, event_id);
CREATE INDEX events_kind_at_id ON events (kind, at, event_id);
CREATE INDEX events_session_at_id ON events (session_id, at, event_id);
CREATE INDEX users_created_id ON users (created_at, user_id);
CREATE INDEX sessions_live_created ON sessions (created_at, session_id) WHERE terminated_at IS NULL;
CREATE INDEX sessions_live_user_created ON sessions (user_id, created_at, session_id) WHERE terminated_at IS NULL;
