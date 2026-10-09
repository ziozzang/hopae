-- Migration 0001: the key/value metadata table (schema version bookkeeping
-- lives in schema_migrations; instance id and key ids are stored here later).
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;
