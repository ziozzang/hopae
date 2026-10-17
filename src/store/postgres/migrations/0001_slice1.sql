-- PostgreSQL schema, slice 1 (ADR-0020): users, identities, providers, the
-- Human user-ID reservation ledger, sessions, handles, login transactions,
-- handoff codes, events and deliveries. Column semantics equal the SQLite
-- schema (migrations 0002, 0003, 0004, 0010): times are integer UTC seconds
-- from the application clock, events.at is seconds with a millisecond
-- fraction, digests are 32-byte bytea, enumerations are CHECKed.

CREATE TABLE users (
    user_id             TEXT PRIMARY KEY,
    primary_email       TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_authoritative BOOLEAN NOT NULL DEFAULT FALSE,
    display_name        TEXT,
    username            TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    authz_version       BIGINT NOT NULL DEFAULT 1,
    groups              TEXT NOT NULL DEFAULT '[]',
    created_at          BIGINT NOT NULL,
    updated_at          BIGINT NOT NULL,
    last_login_at       BIGINT
);
CREATE UNIQUE INDEX users_username ON users (username) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX users_primary_email ON users (primary_email) WHERE primary_email IS NOT NULL;
CREATE INDEX users_created_id ON users (created_at, user_id);

-- Schema 10 reservation ledger: every user ID ever created, never reused.
CREATE TABLE human_user_ids (
    position BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    user_id  TEXT PRIMARY KEY
);
CREATE FUNCTION hopae_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Human user ID reservation is permanent' USING ERRCODE = 'P0001';
END $$;
CREATE TRIGGER human_user_ids_update BEFORE UPDATE OR DELETE ON human_user_ids
    FOR EACH ROW EXECUTE FUNCTION hopae_ledger_immutable();
CREATE FUNCTION hopae_user_reserve() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- The primary key refuses reuse across every replica (unique_violation).
    INSERT INTO human_user_ids (user_id) VALUES (NEW.user_id);
    RETURN NEW;
END $$;
CREATE TRIGGER human_user_identity_reserve BEFORE INSERT ON users
    FOR EACH ROW EXECUTE FUNCTION hopae_user_reserve();
CREATE FUNCTION hopae_user_id_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'User identity is immutable' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER human_user_identity_update BEFORE UPDATE OF user_id ON users
    FOR EACH ROW EXECUTE FUNCTION hopae_user_id_immutable();

CREATE TABLE identities (
    provider_id         TEXT NOT NULL,
    subject             TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users (user_id),
    email               TEXT,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_authoritative BOOLEAN NOT NULL DEFAULT FALSE,
    name                TEXT,
    picture             TEXT,
    raw_claims          TEXT NOT NULL DEFAULT '{}',
    first_seen_at       BIGINT NOT NULL,
    last_seen_at        BIGINT NOT NULL,
    PRIMARY KEY (provider_id, subject)
);
CREATE INDEX identities_user_id ON identities (user_id);
CREATE INDEX identities_email ON identities (email);

CREATE TABLE providers (
    provider_id           TEXT PRIMARY KEY,
    kind                  TEXT NOT NULL CHECK (kind IN ('oidc', 'oauth2', 'email_link', 'password', 'ldap')),
    display_name          TEXT NOT NULL,
    enabled               BOOLEAN NOT NULL,
    managed_by            TEXT NOT NULL CHECK (managed_by IN ('file', 'api')),
    deleted_at            BIGINT,
    sort_order            INTEGER NOT NULL DEFAULT 0,
    config                TEXT NOT NULL DEFAULT '{}',
    client_secret_env     TEXT,
    allowed_email_domains TEXT NOT NULL DEFAULT '[]',
    authoritative_domains TEXT NOT NULL DEFAULT '[]',
    auto_link             BOOLEAN NOT NULL DEFAULT FALSE,
    trust_email           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            BIGINT NOT NULL,
    updated_at            BIGINT NOT NULL
);

CREATE TABLE sessions (
    session_id            TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES users (user_id),
    provider_id           TEXT NOT NULL,
    auth_time             BIGINT NOT NULL,
    factors               TEXT NOT NULL DEFAULT '[]',
    aal                   INTEGER NOT NULL CHECK (aal IN (1, 2)),
    authz_version         BIGINT NOT NULL,
    cred_gen              BIGINT NOT NULL,
    snapshot              TEXT NOT NULL DEFAULT '{}',
    bound_ip              TEXT NOT NULL,
    bound_ua_sha256       BYTEA CHECK (bound_ua_sha256 IS NULL OR octet_length(bound_ua_sha256) = 32),
    bound_country         TEXT,
    created_at            BIGINT NOT NULL,
    last_seen_at          BIGINT NOT NULL,
    absolute_expires_at   BIGINT NOT NULL,
    terminated_at         BIGINT,
    terminated_reason     TEXT,
    authz_version_at_auth BIGINT NOT NULL,
    bound_ua_prefix       TEXT,
    auth_time_source      TEXT NOT NULL DEFAULT 'hopae_completion'
                          CHECK (auth_time_source IN ('provider_claim', 'hopae_completion'))
);
CREATE INDEX sessions_user_terminated ON sessions (user_id, terminated_at);
CREATE INDEX sessions_live_created ON sessions (created_at, session_id) WHERE terminated_at IS NULL;

CREATE TABLE session_handles (
    handle_sha256       BYTEA PRIMARY KEY CHECK (octet_length(handle_sha256) = 32),
    session_id          TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    host                TEXT NOT NULL,
    issued_aal          INTEGER NOT NULL CHECK (issued_aal IN (1, 2)),
    created_at          BIGINT NOT NULL,
    last_seen_at        BIGINT NOT NULL,
    absolute_expires_at BIGINT NOT NULL,
    revoked_at          BIGINT,
    revoked_reason      TEXT
);
CREATE INDEX session_handles_session ON session_handles (session_id);

CREATE TABLE login_txns (
    txn_sha256      BYTEA PRIMARY KEY CHECK (octet_length(txn_sha256) = 32),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    purpose         TEXT NOT NULL CHECK (purpose IN ('login', 'stepup', 'link', 'switch', 'logout')),
    consumed_at     BIGINT,
    consumed_reason TEXT
    -- Remaining columns arrive with slice 2 (transactions and handoff).
);

CREATE TABLE handoff_codes (
    code_sha256     BYTEA PRIMARY KEY CHECK (octet_length(code_sha256) = 32),
    session_id      TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    consumed_at     BIGINT,
    consumed_reason TEXT
    -- Remaining columns arrive with slice 2.
);
CREATE INDEX handoff_codes_session ON handoff_codes (session_id, consumed_at);

CREATE TABLE events (
    event_id    TEXT PRIMARY KEY,
    at          DOUBLE PRECISION NOT NULL,
    kind        TEXT NOT NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'info')),
    reason      TEXT,
    user_id     TEXT,
    session_id  TEXT,
    app_id      TEXT,
    provider_id TEXT,
    client_ip   TEXT,
    ua_sha256   BYTEA,
    ua_prefix   TEXT,
    request_id  TEXT NOT NULL,
    attrs       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX events_at_id ON events (at, event_id);
CREATE INDEX events_user_at_id ON events (user_id, at, event_id);
CREATE INDEX events_kind_at_id ON events (kind, at, event_id);

CREATE TABLE event_deliveries (
    sink            TEXT NOT NULL,
    event_id        TEXT NOT NULL REFERENCES events (event_id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL,
    last_error      TEXT,
    updated_at      BIGINT NOT NULL,
    PRIMARY KEY (sink, event_id)
);
CREATE INDEX event_deliveries_event_id ON event_deliveries (event_id);
CREATE INDEX event_deliveries_claim ON event_deliveries (sink, state, next_attempt_at);
