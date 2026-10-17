-- Password and code attempt windows shared by every replica
-- (`password_attempts.per_ip`, `password_attempts.per_account`). Keys are
-- SHA-256 digests (never an address or a username); a row lives until its
-- window ends and is pruned after that, so the table is bounded by the
-- windows open at once.
CREATE TABLE attempt_windows (
    scope      TEXT NOT NULL CHECK (scope IN ('ip', 'account')),
    key        BYTEA NOT NULL CHECK (octet_length(key) = 32),
    started_ms BIGINT NOT NULL,
    ends_ms    BIGINT NOT NULL,
    count      BIGINT NOT NULL CHECK (count >= 1),
    PRIMARY KEY (scope, key)
);
CREATE INDEX attempt_windows_ends ON attempt_windows (ends_ms);
