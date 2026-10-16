-- WebAuthn passkeys and recovery codes (ADR-0017). Additive only: no existing
-- row changes meaning. Public keys are stored plain; recovery codes as
-- Argon2id PHC strings; ceremony state is server-side, single use, expiring.

-- Random WebAuthn user handle (UUID bytes), never the user id or an email.
ALTER TABLE users ADD COLUMN webauthn_user_handle BLOB
    CHECK (webauthn_user_handle IS NULL OR length(webauthn_user_handle) = 16);
CREATE UNIQUE INDEX users_webauthn_user_handle ON users (webauthn_user_handle)
    WHERE webauthn_user_handle IS NOT NULL;
-- Set when a recovery code was used; cleared by the next factor enrollment.
ALTER TABLE users ADD COLUMN factor_recovery_required_at INTEGER;

CREATE TABLE webauthn_credentials (
    credential_id      BLOB PRIMARY KEY NOT NULL
                       CHECK (length(credential_id) BETWEEN 16 AND 1023),
    user_id            TEXT NOT NULL REFERENCES users (user_id),
    label              TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    -- Serialized webauthn-rs credential: public key, counter, flags, attestation.
    passkey            TEXT NOT NULL CHECK (length(passkey) <= 65536),
    aaguid             BLOB CHECK (aaguid IS NULL OR length(aaguid) = 16),
    transports         TEXT NOT NULL DEFAULT '[]' CHECK (length(transports) <= 256),
    backup_eligible    INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
    backup_state       INTEGER NOT NULL CHECK (backup_state IN (0, 1)),
    user_verified      INTEGER NOT NULL CHECK (user_verified IN (0, 1)),
    attestation_format TEXT NOT NULL CHECK (length(attestation_format) <= 32),
    -- 1 only when the attestation chain verified against an operator CA.
    attested           INTEGER NOT NULL CHECK (attested IN (0, 1)),
    assurance          TEXT NOT NULL CHECK (assurance IN ('aal2', 'aal3')),
    sign_count         INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    created_at         INTEGER NOT NULL,
    last_used_at       INTEGER,
    state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    revoked_at         INTEGER,
    revoked_reason     TEXT,
    revision           INTEGER NOT NULL CHECK (revision > 0),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
) STRICT;
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id, state);

CREATE TABLE webauthn_challenges (
    challenge_sha256    BLOB PRIMARY KEY NOT NULL CHECK (length(challenge_sha256) = 32),
    purpose             TEXT NOT NULL CHECK (purpose IN ('register', 'verify', 'stepup')),
    user_id             TEXT NOT NULL REFERENCES users (user_id),
    session_id          TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    handle_sha256       BLOB NOT NULL CHECK (length(handle_sha256) = 32),
    portal_bind_sha256  BLOB NOT NULL CHECK (length(portal_bind_sha256) = 32),
    txn_sha256          BLOB CHECK (txn_sha256 IS NULL OR length(txn_sha256) = 32),
    credential_generation INTEGER NOT NULL CHECK (credential_generation >= 0),
    -- Serialized webauthn-rs ceremony state; never sent to the browser.
    state               TEXT NOT NULL CHECK (length(state) <= 65536),
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    consumed_at         INTEGER,
    CHECK ((purpose = 'stepup') = (txn_sha256 IS NOT NULL))
) STRICT;
CREATE INDEX webauthn_challenges_session ON webauthn_challenges (session_id, created_at);
CREATE INDEX webauthn_challenges_expires ON webauthn_challenges (expires_at);

CREATE TABLE recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users (user_id),
    lookup     TEXT NOT NULL CHECK (length(lookup) = 5),
    -- Argon2id PHC string of the code's secret part.
    hash       TEXT NOT NULL CHECK (length(hash) <= 256),
    batch      TEXT NOT NULL CHECK (length(batch) <= 64),
    created_at INTEGER NOT NULL,
    used_at    INTEGER,
    PRIMARY KEY (user_id, lookup)
) STRICT;

-- Which credential elevated which session: removal or a clone signal ends
-- the sessions a credential elevated.
CREATE TABLE session_webauthn_elevations (
    session_id    TEXT NOT NULL REFERENCES sessions (session_id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL,
    at            INTEGER NOT NULL,
    PRIMARY KEY (session_id, credential_id)
) STRICT;
CREATE INDEX session_webauthn_elevations_credential ON session_webauthn_elevations (credential_id);
