-- Migration 0002: the M1 data model (docs/ARCHITECTURE.md, "Data model").
-- Times are UTC seconds (INTEGER), except events.at which is seconds with a
-- millisecond fraction (REAL, ADR-0009). Digests are 32-byte BLOBs, JSON is
-- TEXT. Columns for later milestones exist now so later work adds rows only.

CREATE TABLE users (
    user_id             TEXT PRIMARY KEY NOT NULL,
    primary_email       TEXT,
    email_verified      INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    email_authoritative INTEGER NOT NULL DEFAULT 0 CHECK (email_authoritative IN (0, 1)),
    display_name        TEXT,
    username            TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    authz_version       INTEGER NOT NULL DEFAULT 1,
    groups              TEXT NOT NULL DEFAULT '[]',
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    last_login_at       INTEGER
) STRICT;
CREATE UNIQUE INDEX users_username ON users (username) WHERE username IS NOT NULL;

CREATE TABLE identities (
    provider_id         TEXT NOT NULL,
    subject             TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users (user_id),
    email               TEXT,
    email_verified      INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    email_authoritative INTEGER NOT NULL DEFAULT 0 CHECK (email_authoritative IN (0, 1)),
    name                TEXT,
    picture             TEXT,
    raw_claims          TEXT NOT NULL DEFAULT '{}',
    first_seen_at       INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    PRIMARY KEY (provider_id, subject)
) STRICT;
CREATE INDEX identities_user_id ON identities (user_id);
CREATE INDEX identities_email ON identities (email);

CREATE TABLE providers (
    provider_id           TEXT PRIMARY KEY NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('oidc', 'oauth2', 'email_link', 'password')),
    display_name          TEXT NOT NULL,
    enabled               INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    managed_by            TEXT NOT NULL CHECK (managed_by IN ('file', 'api')),
    deleted_at            INTEGER,
    sort_order            INTEGER NOT NULL DEFAULT 0,
    config                TEXT NOT NULL DEFAULT '{}',
    client_secret_env     TEXT,
    allowed_email_domains TEXT NOT NULL DEFAULT '[]',
    authoritative_domains TEXT NOT NULL DEFAULT '[]',
    auto_link             INTEGER NOT NULL DEFAULT 0 CHECK (auto_link IN (0, 1)),
    trust_email           INTEGER NOT NULL DEFAULT 0 CHECK (trust_email IN (0, 1)),
    created_at            INTEGER NOT NULL,
    updated_at            INTEGER NOT NULL
) STRICT;

CREATE TABLE apps (
    app_id          TEXT PRIMARY KEY NOT NULL,
    display_name    TEXT NOT NULL,
    hosts           TEXT NOT NULL DEFAULT '[]',
    ports           TEXT NOT NULL DEFAULT '[443]',
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    session_policy  TEXT NOT NULL DEFAULT '{}',
    binding_policy  TEXT NOT NULL DEFAULT '{}',
    step_up         TEXT NOT NULL DEFAULT '[]',
    allowed_groups  TEXT NOT NULL DEFAULT '[]',
    on_authz_change TEXT NOT NULL DEFAULT 'refresh' CHECK (on_authz_change IN ('refresh', 'terminate')),
    gateway_ref     TEXT,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    session_id          TEXT PRIMARY KEY NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users (user_id),
    provider_id         TEXT NOT NULL,
    auth_time           INTEGER NOT NULL,
    factors             TEXT NOT NULL DEFAULT '[]',
    aal                 INTEGER NOT NULL CHECK (aal IN (1, 2)),
    authz_version       INTEGER NOT NULL,
    cred_gen            INTEGER NOT NULL,
    snapshot            TEXT NOT NULL DEFAULT '{}',
    bound_ip            TEXT NOT NULL,
    bound_ua_sha256     BLOB,
    bound_country       TEXT,
    created_at          INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    terminated_at       INTEGER,
    terminated_reason   TEXT
) STRICT;
CREATE INDEX sessions_user_terminated ON sessions (user_id, terminated_at);

CREATE TABLE session_handles (
    handle_sha256       BLOB PRIMARY KEY NOT NULL CHECK (length(handle_sha256) = 32),
    session_id          TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    issued_aal          INTEGER NOT NULL CHECK (issued_aal IN (1, 2)),
    created_at          INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at          INTEGER,
    revoked_reason      TEXT
) STRICT;
CREATE INDEX session_handles_session ON session_handles (session_id);

CREATE TABLE login_txns (
    txn_sha256                BLOB PRIMARY KEY NOT NULL CHECK (length(txn_sha256) = 32),
    created_at                INTEGER NOT NULL,
    expires_at                INTEGER NOT NULL,
    app_id                    TEXT NOT NULL,
    return_target             TEXT NOT NULL,
    bind_sha256               BLOB,
    portal_bind_sha256        BLOB,
    client_ip                 TEXT NOT NULL,
    ua_sha256                 BLOB,
    provider_id               TEXT,
    state_sha256              BLOB,
    nonce                     TEXT,
    pkce_verifier             TEXT,
    portal_session_id         TEXT,
    purpose                   TEXT NOT NULL CHECK (purpose IN ('login', 'stepup', 'link', 'switch')),
    conflicting_handle_sha256 BLOB,
    pending_identity          TEXT,
    recovery_depth            INTEGER NOT NULL DEFAULT 0,
    retry_bind_sha256         BLOB,
    consumed_at               INTEGER,
    consumed_reason           TEXT
) STRICT;
CREATE INDEX login_txns_state ON login_txns (state_sha256);
CREATE INDEX login_txns_expires ON login_txns (expires_at);

-- return_path is derived from return_target (its URL path) and is what the
-- redemption statement compares against the presented path.
CREATE TABLE handoff_codes (
    code_sha256     BLOB PRIMARY KEY NOT NULL CHECK (length(code_sha256) = 32),
    session_id      TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    return_target   TEXT NOT NULL,
    return_path     TEXT NOT NULL,
    client_ip       TEXT NOT NULL,
    bind_sha256     BLOB NOT NULL,
    issued_aal      INTEGER NOT NULL CHECK (issued_aal IN (1, 2)),
    cred_gen        INTEGER NOT NULL,
    recovery_depth  INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    consumed_at     INTEGER,
    consumed_reason TEXT
) STRICT;
CREATE INDEX handoff_codes_session ON handoff_codes (session_id, consumed_at);
CREATE INDEX handoff_codes_expires ON handoff_codes (expires_at);

CREATE TABLE events (
    event_id    TEXT PRIMARY KEY NOT NULL,
    at          REAL NOT NULL,
    kind        TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'info')),
    reason      TEXT,
    user_id     TEXT,
    session_id  TEXT,
    app_id      TEXT,
    provider_id TEXT,
    client_ip   TEXT,
    ua_sha256   BLOB,
    ua_prefix   TEXT,
    request_id  TEXT NOT NULL,
    attrs       TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE INDEX events_at ON events (at);
CREATE INDEX events_user_at ON events (user_id, at);
CREATE INDEX events_ip_at ON events (client_ip, at);

CREATE TABLE event_deliveries (
    sink            TEXT NOT NULL,
    event_id        TEXT NOT NULL REFERENCES events (event_id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error      TEXT,
    updated_at      INTEGER NOT NULL,
    PRIMARY KEY (sink, event_id)
) STRICT;
CREATE INDEX event_deliveries_claim ON event_deliveries (sink, state, next_attempt_at);
