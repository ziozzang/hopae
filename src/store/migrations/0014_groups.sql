-- Groups and memberships (Hangang ADR 0021: Hopae owns groups; ADR-0019).
--
-- Numbered 0014: 0011-0013 are reserved by the WebAuthn/passkey branch. A
-- store migrated by this file without those three is not upgraded by a later
-- binary that carries them (the runner applies versions above the recorded
-- maximum); this branch must merge after them (see ADR-0019, "Migration").

-- One row per group ever created. `group_id` is the opaque GroupRef
-- (`grp1:` + 26 Crockford symbols), never reused: a deleted group stays as a
-- tombstone (`state = 'deleted'`) so a reference keeps resolving.
CREATE TABLE directory_groups (
    group_id     TEXT PRIMARY KEY NOT NULL
                 CHECK (length(group_id) = 31 AND substr(group_id, 1, 5) = 'grp1:'),
    source       TEXT NOT NULL CHECK (source IN ('local', 'ldap', 'oidc')),
    provider_id  TEXT,
    -- Stable key within (source, provider): a local key chosen by the
    -- administrator, a normalized LDAP DN or entry key, or a mapped OIDC value.
    external_key TEXT NOT NULL CHECK (length(external_key) BETWEEN 1 AND 512),
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    description  TEXT CHECK (description IS NULL OR length(description) <= 1024),
    state        TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'deleted')),
    -- Compare-and-swap revision: every change to the group or its members.
    revision     INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    -- Last time a provider sync reported the group (provider groups only).
    last_seen_at INTEGER,
    deleted_at   INTEGER,
    CHECK ((source = 'local') = (provider_id IS NULL)),
    CHECK ((state = 'deleted') = (deleted_at IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX groups_live_key
    ON directory_groups (source, COALESCE(provider_id, ''), external_key) WHERE state = 'active';
CREATE INDEX groups_name ON directory_groups (name COLLATE NOCASE, group_id);

-- Memberships of a person (a Hopae user ID) in a group. The source is the
-- group's: provider groups hold only that provider's synced memberships and
-- local groups only administrator-managed ones.
CREATE TABLE group_members (
    group_id           TEXT NOT NULL REFERENCES directory_groups (group_id),
    user_id            TEXT NOT NULL,
    source             TEXT NOT NULL CHECK (source IN ('local', 'ldap', 'oidc')),
    provider_id        TEXT,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL,
    -- Local memberships only: removed by the maintenance pass after this time.
    expires_at         INTEGER,
    -- Provider memberships only: the sync stopped reporting the membership at
    -- this time; it is removed once the provider's removal grace has passed.
    removal_pending_at INTEGER,
    -- Provider memberships only: suspended at this time because no
    -- successful assertion refreshed it for `groups.max_staleness_secs`;
    -- a suspended membership is kept but excluded from the projection and
    -- the gateway mirror until an assertion restores it.
    stale_at           INTEGER,
    added_by           TEXT,
    reason             TEXT CHECK (reason IS NULL OR length(reason) <= 256),
    PRIMARY KEY (group_id, user_id),
    CHECK ((source = 'local') = (provider_id IS NULL)),
    CHECK (source = 'local' OR expires_at IS NULL),
    CHECK (source <> 'local' OR removal_pending_at IS NULL),
    CHECK (source <> 'local' OR stale_at IS NULL)
) STRICT, WITHOUT ROWID;
CREATE INDEX group_members_user ON group_members (user_id, group_id);

-- The change journal of the signed membership projection. `revision` is the
-- projection revision: monotonic (AUTOINCREMENT never reuses a value, even
-- after the oldest rows are pruned by `groups.change_retention_days`).
CREATE TABLE group_changes (
    revision INTEGER PRIMARY KEY AUTOINCREMENT,
    at       INTEGER NOT NULL,
    change   TEXT NOT NULL CHECK (change IN
                 ('group_created', 'group_updated', 'group_deleted', 'member_added', 'member_removed')),
    group_id TEXT NOT NULL,
    user_id  TEXT,
    CHECK ((change IN ('member_added', 'member_removed')) = (user_id IS NOT NULL))
) STRICT;
CREATE INDEX group_changes_at ON group_changes (at);

-- Bounded periodic-sync progress per provider (the next identity to refresh).
CREATE TABLE group_sync_state (
    provider_id    TEXT PRIMARY KEY NOT NULL,
    cursor_subject TEXT,
    last_run_at    INTEGER,
    last_ok_at     INTEGER,
    last_error     TEXT
) STRICT;
