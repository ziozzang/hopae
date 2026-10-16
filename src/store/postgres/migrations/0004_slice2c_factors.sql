-- ADR-0020 slice 2c: second factors and passkeys. Mirrors SQLite schema
-- 5, 6, 8, 11, 12 and 13 with native types; no secret or key material is
-- stored in plain form (TOTP seeds are sealed envelopes, recovery codes are
-- Argon2id PHC strings, passkeys hold public keys only).

-- Store-wide values (the configuration generation, the external factor
-- snapshot revision), as SQLite's `meta` table.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

ALTER TABLE users
    ADD COLUMN webauthn_user_handle BYTEA
        CHECK (webauthn_user_handle IS NULL OR octet_length(webauthn_user_handle) = 16),
    ADD COLUMN factor_recovery_required_at BIGINT;
CREATE UNIQUE INDEX users_webauthn_user_handle ON users (webauthn_user_handle)
    WHERE webauthn_user_handle IS NOT NULL;

CREATE TABLE totp_enrollments (
    enrollment_id      TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users (user_id),
    envelope           TEXT NOT NULL CHECK (length(envelope) <= 1024),
    revision           BIGINT NOT NULL CHECK (revision > 0),
    state              TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    last_counter       BIGINT CHECK (last_counter >= 0),
    pending_expires_at BIGINT,
    created_at         BIGINT NOT NULL,
    updated_at         BIGINT NOT NULL
);
CREATE UNIQUE INDEX totp_one_pending_per_user ON totp_enrollments (user_id) WHERE state = 'pending';
CREATE UNIQUE INDEX totp_one_active_per_user ON totp_enrollments (user_id) WHERE state = 'active';

CREATE TABLE external_factor_authorities (
    factor            TEXT PRIMARY KEY CHECK (length(factor) BETWEEN 1 AND 128),
    revision          BIGINT NOT NULL CHECK (revision > 0),
    binding           BYTEA CHECK (binding IS NULL OR octet_length(binding) = 32),
    config_generation BIGINT NOT NULL CHECK (config_generation > 0)
);
CREATE TABLE external_factor_sessions (
    factor     TEXT NOT NULL REFERENCES external_factor_authorities (factor),
    session_id TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    revision   BIGINT NOT NULL CHECK (revision > 0),
    PRIMARY KEY (factor, session_id)
);
CREATE TABLE external_factor_proofs (
    factor         TEXT NOT NULL REFERENCES external_factor_authorities (factor),
    revision       BIGINT NOT NULL CHECK (revision > 0),
    proof_sha256   BYTEA NOT NULL CHECK (octet_length(proof_sha256) = 32),
    consumed_at_ms BIGINT NOT NULL,
    PRIMARY KEY (factor, revision, proof_sha256)
);
CREATE TABLE external_factor_budget (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    used      BIGINT NOT NULL CHECK (used BETWEEN 0 AND 1000000)
);
INSERT INTO external_factor_budget (singleton, used) VALUES (1, 0);
CREATE FUNCTION hopae_external_proof_budget() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE external_factor_budget SET used = used + 1 WHERE singleton = 1 AND used < 1000000;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'external proof capacity' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER external_factor_proof_budget AFTER INSERT ON external_factor_proofs
    FOR EACH ROW EXECUTE FUNCTION hopae_external_proof_budget();

CREATE TABLE session_totp_provenance (
    session_id            TEXT PRIMARY KEY REFERENCES sessions (session_id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL,
    credential_generation BIGINT NOT NULL CHECK (credential_generation > 0),
    enrollment_id         TEXT NOT NULL,
    enrollment_revision   BIGINT NOT NULL CHECK (enrollment_revision > 0),
    factor_index          BIGINT NOT NULL CHECK (factor_index >= 0),
    verified_at_ms        BIGINT NOT NULL CHECK (verified_at_ms >= 0),
    config_generation     BIGINT CHECK (config_generation > 0)
);

CREATE TABLE webauthn_credentials (
    credential_id      BYTEA PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    user_id            TEXT NOT NULL REFERENCES users (user_id),
    label              TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    passkey            TEXT NOT NULL CHECK (length(passkey) <= 65536),
    aaguid             BYTEA CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
    transports         TEXT NOT NULL DEFAULT '[]' CHECK (length(transports) <= 256),
    backup_eligible    BOOLEAN NOT NULL,
    backup_state       BOOLEAN NOT NULL,
    user_verified      BOOLEAN NOT NULL,
    attestation_format TEXT NOT NULL CHECK (length(attestation_format) <= 32),
    attested           BOOLEAN NOT NULL,
    assurance          TEXT NOT NULL CHECK (assurance IN ('aal2', 'aal3')),
    sign_count         BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    created_at         BIGINT NOT NULL,
    last_used_at       BIGINT,
    state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    revoked_at         BIGINT,
    revoked_reason     TEXT,
    revision           BIGINT NOT NULL CHECK (revision > 0),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id, state);

CREATE TABLE webauthn_challenges (
    challenge_sha256      BYTEA PRIMARY KEY CHECK (octet_length(challenge_sha256) = 32),
    purpose               TEXT NOT NULL CHECK (purpose IN ('register', 'verify', 'stepup')),
    user_id               TEXT NOT NULL REFERENCES users (user_id),
    session_id            TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    handle_sha256         BYTEA NOT NULL CHECK (octet_length(handle_sha256) = 32),
    portal_bind_sha256    BYTEA NOT NULL CHECK (octet_length(portal_bind_sha256) = 32),
    txn_sha256            BYTEA CHECK (txn_sha256 IS NULL OR octet_length(txn_sha256) = 32),
    credential_generation BIGINT NOT NULL CHECK (credential_generation >= 0),
    state                 TEXT NOT NULL CHECK (length(state) <= 65536),
    created_at            BIGINT NOT NULL,
    expires_at            BIGINT NOT NULL,
    consumed_at           BIGINT,
    -- Insertion order, for the per-session cap (SQLite uses its rowid).
    seq                   BIGINT GENERATED ALWAYS AS IDENTITY,
    CHECK ((purpose = 'stepup') = (txn_sha256 IS NOT NULL))
);
CREATE INDEX webauthn_challenges_session ON webauthn_challenges (session_id, created_at);
CREATE INDEX webauthn_challenges_expires ON webauthn_challenges (expires_at);

CREATE TABLE recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users (user_id),
    lookup     TEXT NOT NULL CHECK (length(lookup) = 5),
    hash       TEXT NOT NULL CHECK (length(hash) <= 256),
    batch      TEXT NOT NULL CHECK (length(batch) <= 64),
    created_at BIGINT NOT NULL,
    used_at    BIGINT,
    PRIMARY KEY (user_id, lookup)
);

CREATE TABLE session_webauthn_elevations (
    session_id    TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    at            BIGINT NOT NULL,
    PRIMARY KEY (session_id, credential_id)
);
CREATE INDEX session_webauthn_elevations_credential ON session_webauthn_elevations (credential_id);

CREATE TABLE session_webauthn_provenance (
    session_id            TEXT PRIMARY KEY REFERENCES sessions (session_id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL,
    credential_generation BIGINT NOT NULL CHECK (credential_generation > 0),
    credential_id         BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    assurance             TEXT NOT NULL CHECK (assurance IN ('aal2', 'aal3')),
    factor_index          BIGINT NOT NULL CHECK (factor_index >= 0),
    verified_at_ms        BIGINT NOT NULL CHECK (verified_at_ms >= 0),
    config_generation     BIGINT CHECK (config_generation > 0)
);

CREATE TABLE webauthn_login_challenges (
    challenge_sha256   BYTEA PRIMARY KEY CHECK (octet_length(challenge_sha256) = 32),
    txn_sha256         BYTEA NOT NULL CHECK (octet_length(txn_sha256) = 32),
    portal_bind_sha256 BYTEA NOT NULL CHECK (octet_length(portal_bind_sha256) = 32),
    client_ip          TEXT NOT NULL CHECK (length(client_ip) <= 64),
    state              TEXT NOT NULL CHECK (length(state) <= 65536),
    created_at         BIGINT NOT NULL,
    expires_at         BIGINT NOT NULL,
    consumed_at        BIGINT
);
CREATE INDEX webauthn_login_challenges_ip ON webauthn_login_challenges (client_ip, created_at);
CREATE INDEX webauthn_login_challenges_expires ON webauthn_login_challenges (expires_at);
