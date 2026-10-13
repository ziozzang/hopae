-- Encrypted owner state; no plaintext TOTP seed or encryption key.
CREATE TABLE totp_enrollments (
 enrollment_id TEXT PRIMARY KEY NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(user_id),
 envelope TEXT NOT NULL CHECK(length(envelope) <= 1024),
 revision INTEGER NOT NULL CHECK(revision > 0),
 state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),
 last_counter INTEGER CHECK(last_counter >= 0),
 pending_expires_at INTEGER,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX totp_one_pending_per_user ON totp_enrollments(user_id) WHERE state='pending';
CREATE UNIQUE INDEX totp_one_active_per_user ON totp_enrollments(user_id) WHERE state='active';
