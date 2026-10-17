-- ADR-0020 slice 3: console listings, the event relay, groups and the
-- subject directory feeds.

-- Claim order of deliveries (SQLite uses its rowid).
ALTER TABLE event_deliveries ADD COLUMN seq BIGINT GENERATED ALWAYS AS IDENTITY;
CREATE INDEX event_deliveries_due ON event_deliveries (sink, state, next_attempt_at, seq);

-- Console listing windows (ADR-0016), as SQLite schema 3.
CREATE INDEX events_session_at_id ON events (session_id, at, event_id);
CREATE INDEX sessions_live_user_created ON sessions (user_id, created_at, session_id) WHERE terminated_at IS NULL;

-- Ledger positions must be handed out in commit order: a feed reader that
-- has seen position N never later finds a new row below N. Reservations
-- serialize on one transaction-scoped advisory lock (user creation is rare).
CREATE OR REPLACE FUNCTION hopae_user_reserve() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(7040);
    INSERT INTO human_user_ids (user_id) VALUES (NEW.user_id);
    RETURN NEW;
END $$;

-- The subject lifecycle feed: positions of the outbox events it reports
-- (`admin.user_disable`, `admin.user_enable`, `group.*`), handed out in
-- commit order under an advisory lock taken only by those writes. A pruned
-- event takes its position with it, so a consumer at that position is told
-- to take a new snapshot.
CREATE TABLE outbox_feed (
    pos      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES events (event_id) ON DELETE CASCADE
);
INSERT INTO outbox_feed (event_id)
    SELECT event_id FROM events
    WHERE kind IN ('admin.user_disable', 'admin.user_enable') OR kind LIKE 'group.%'
    ORDER BY at, event_id;

-- Groups and memberships (ADR-0019), as SQLite schema 14.
CREATE TABLE directory_groups (
    group_id     TEXT PRIMARY KEY
                 CHECK (length(group_id) = 31 AND substr(group_id, 1, 5) = 'grp1:'),
    source       TEXT NOT NULL CHECK (source IN ('local', 'ldap', 'oidc')),
    provider_id  TEXT,
    external_key TEXT NOT NULL CHECK (length(external_key) BETWEEN 1 AND 512),
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    description  TEXT CHECK (description IS NULL OR length(description) <= 1024),
    state        TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'deleted')),
    revision     BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL,
    last_seen_at BIGINT,
    deleted_at   BIGINT,
    CHECK ((source = 'local') = (provider_id IS NULL)),
    CHECK ((state = 'deleted') = (deleted_at IS NOT NULL))
);
CREATE UNIQUE INDEX groups_live_key
    ON directory_groups (source, COALESCE(provider_id, ''), external_key) WHERE state = 'active';
CREATE INDEX groups_name ON directory_groups (lower(name), group_id);
CREATE INDEX groups_created ON directory_groups (created_at, group_id);

CREATE TABLE group_members (
    group_id           TEXT NOT NULL REFERENCES directory_groups (group_id),
    user_id            TEXT NOT NULL,
    source             TEXT NOT NULL CHECK (source IN ('local', 'ldap', 'oidc')),
    provider_id        TEXT,
    first_seen_at      BIGINT NOT NULL,
    last_seen_at       BIGINT NOT NULL,
    expires_at         BIGINT,
    removal_pending_at BIGINT,
    stale_at           BIGINT,
    added_by           TEXT,
    reason             TEXT CHECK (reason IS NULL OR length(reason) <= 256),
    PRIMARY KEY (group_id, user_id),
    CHECK ((source = 'local') = (provider_id IS NULL)),
    CHECK (source = 'local' OR expires_at IS NULL),
    CHECK (source <> 'local' OR removal_pending_at IS NULL),
    CHECK (source <> 'local' OR stale_at IS NULL)
);
CREATE INDEX group_members_user ON group_members (user_id, group_id);

-- The projection journal. Every group write holds one advisory lock until it
-- commits and numbers its rows from the current maximum, so revisions are
-- gapless and become visible in order (no reader skips one). Pruning always
-- keeps the newest row, so the maximum never moves back.
CREATE TABLE group_changes (
    revision BIGINT PRIMARY KEY CHECK (revision > 0),
    at       BIGINT NOT NULL,
    change   TEXT NOT NULL CHECK (change IN
                 ('group_created', 'group_updated', 'group_deleted', 'member_added', 'member_removed')),
    group_id TEXT NOT NULL,
    user_id  TEXT,
    CHECK ((change IN ('member_added', 'member_removed')) = (user_id IS NOT NULL))
);
CREATE INDEX group_changes_at ON group_changes (at);

CREATE TABLE group_sync_state (
    provider_id    TEXT PRIMARY KEY,
    cursor_subject TEXT,
    last_run_at    BIGINT,
    last_ok_at     BIGINT,
    last_error     TEXT
);
