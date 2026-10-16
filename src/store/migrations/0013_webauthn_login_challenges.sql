-- Passwordless passkey sign-in ceremonies (ADR-0017 phase 2). No user or
-- session exists yet: the row is bound to the login transaction, the
-- portal binding cookie and the client address; single use, five minutes.
CREATE TABLE webauthn_login_challenges (
    challenge_sha256   BLOB PRIMARY KEY NOT NULL CHECK (length(challenge_sha256) = 32),
    txn_sha256         BLOB NOT NULL CHECK (length(txn_sha256) = 32),
    portal_bind_sha256 BLOB NOT NULL CHECK (length(portal_bind_sha256) = 32),
    client_ip          TEXT NOT NULL CHECK (length(client_ip) <= 64),
    state              TEXT NOT NULL CHECK (length(state) <= 65536),
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    consumed_at        INTEGER
) STRICT;
CREATE INDEX webauthn_login_challenges_ip ON webauthn_login_challenges (client_ip, created_at);
CREATE INDEX webauthn_login_challenges_expires ON webauthn_login_challenges (expires_at);
