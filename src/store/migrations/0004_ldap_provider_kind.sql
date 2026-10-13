-- Add LDAP as a distinct provider kind without changing existing identities or grants.
-- No foreign key references providers in the owner schema. Run in the migration transaction.
CREATE TABLE providers_v4 (
    provider_id           TEXT PRIMARY KEY NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('oidc', 'oauth2', 'email_link', 'password', 'ldap')),
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
INSERT INTO providers_v4 SELECT * FROM providers;
DROP TABLE providers;
ALTER TABLE providers_v4 RENAME TO providers;
