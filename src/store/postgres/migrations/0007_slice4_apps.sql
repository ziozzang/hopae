-- ADR-0020 slice 4: the application mirror (SQLite schema 2), rebuilt from
-- the configuration on every start and copied by the SQLite migration.
CREATE TABLE apps (
    app_id          TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    hosts           TEXT NOT NULL DEFAULT '[]',
    ports           TEXT NOT NULL DEFAULT '[443]',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    session_policy  TEXT NOT NULL DEFAULT '{}',
    binding_policy  TEXT NOT NULL DEFAULT '{}',
    step_up         TEXT NOT NULL DEFAULT '[]',
    allowed_groups  TEXT NOT NULL DEFAULT '[]',
    on_authz_change TEXT NOT NULL DEFAULT 'refresh' CHECK (on_authz_change IN ('refresh', 'terminate')),
    gateway_ref     TEXT,
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL
);
