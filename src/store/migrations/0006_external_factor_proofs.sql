-- Native MFA authority and permanent hashed single-use proof ledger.
CREATE TABLE external_factor_authorities (
 factor TEXT PRIMARY KEY NOT NULL CHECK(length(factor) BETWEEN 1 AND 128),
 revision INTEGER NOT NULL CHECK(revision > 0),
 binding BLOB CHECK(binding IS NULL OR length(binding)=32),
 config_generation INTEGER NOT NULL CHECK(config_generation > 0)
) STRICT;
CREATE TABLE external_factor_sessions (
 factor TEXT NOT NULL REFERENCES external_factor_authorities(factor),
 session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
 revision INTEGER NOT NULL CHECK(revision > 0),
 PRIMARY KEY(factor,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE external_factor_proofs (
 factor TEXT NOT NULL REFERENCES external_factor_authorities(factor),
 revision INTEGER NOT NULL CHECK(revision > 0),
 proof_sha256 BLOB NOT NULL CHECK(length(proof_sha256)=32),
 consumed_at_ms INTEGER NOT NULL,
 PRIMARY KEY(factor,revision,proof_sha256)
) STRICT, WITHOUT ROWID;
CREATE TABLE external_factor_budget (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 used INTEGER NOT NULL CHECK(used BETWEEN 0 AND 1000000)
) STRICT;
INSERT INTO external_factor_budget(singleton,used) VALUES(1,0);
CREATE TRIGGER external_factor_proof_budget AFTER INSERT ON external_factor_proofs
BEGIN
 UPDATE external_factor_budget SET used=used+1 WHERE singleton=1 AND used<1000000;
 SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'external proof capacity') END;
END;
