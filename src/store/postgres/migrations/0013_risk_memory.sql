-- The risk memory shared by every replica (ADR-0023 follow-up): per session
-- the last country and ASN of an allowed request, per user the countries
-- seen (a JSON array, most recent last). No address is kept. Entries older
-- than their TTL are ignored and pruned; the entry caps are enforced by a
-- maintenance pass.
CREATE TABLE risk_sessions (
    session_id TEXT PRIMARY KEY,
    country    TEXT CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
    asn        BIGINT CHECK (asn IS NULL OR asn BETWEEN 0 AND 4294967295),
    seen_ms    BIGINT NOT NULL
);
CREATE INDEX risk_sessions_seen ON risk_sessions (seen_ms);
CREATE TABLE risk_users (
    user_id   TEXT PRIMARY KEY,
    countries TEXT NOT NULL CHECK (length(countries) <= 1024),
    seen_ms   BIGINT NOT NULL
);
CREATE INDEX risk_users_seen ON risk_users (seen_ms);
