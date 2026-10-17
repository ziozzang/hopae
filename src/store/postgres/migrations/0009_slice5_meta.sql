-- ADR-0020 slice 5: the native owners read `meta` key ranges in byte order
-- (SQLite's BINARY collation): an index in the "C" collation serves them.
CREATE INDEX meta_key_c ON meta (key COLLATE "C");
