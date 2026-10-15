-- Original native primary authentication only; legacy sessions remain unqualified.
CREATE TABLE session_primary_provenance (
 session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 provider_id TEXT NOT NULL,
 material_revision INTEGER NOT NULL CHECK(material_revision>0),
 provider_revision INTEGER NOT NULL CHECK(provider_revision>0),
 config_generation INTEGER NOT NULL CHECK(config_generation>0),
 credential_generation INTEGER NOT NULL CHECK(credential_generation>0),
 subject TEXT NOT NULL CHECK(length(subject)>0 AND length(subject)<=4096),
 auth_time_ms INTEGER NOT NULL CHECK(auth_time_ms>=0),
 auth_time_source TEXT NOT NULL,
 factor_index INTEGER NOT NULL CHECK(factor_index>=0),
 factor_kind TEXT NOT NULL,
 factor_at_ms INTEGER NOT NULL CHECK(factor_at_ms>=0)
) STRICT;

-- Opaque keyed compiler fingerprints, with permanent monotonic tombstones.
CREATE TABLE human_provider_material_owners (
 provider_id TEXT PRIMARY KEY NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 fingerprint BLOB CHECK(fingerprint IS NULL OR length(fingerprint)=32)
) STRICT;
CREATE TRIGGER human_material_owner_delete BEFORE DELETE ON human_provider_material_owners BEGIN
 SELECT RAISE(ABORT,'material owner cannot be deleted');
END;
CREATE TRIGGER human_material_owner_update BEFORE UPDATE ON human_provider_material_owners BEGIN
 SELECT CASE WHEN NEW.provider_id IS NOT OLD.provider_id OR
 (NEW.fingerprint IS OLD.fingerprint AND NEW.revision IS NOT OLD.revision) OR
 (NEW.fingerprint IS NOT OLD.fingerprint AND (OLD.revision=9223372036854775807 OR NEW.revision!=OLD.revision+1))
 THEN RAISE(ABORT,'invalid material owner transition') END;
END;
CREATE TRIGGER human_material_owner_insert BEFORE INSERT ON human_provider_material_owners WHEN NEW.revision!=1 AND NOT EXISTS(SELECT 1 FROM human_provider_material_owners WHERE provider_id=NEW.provider_id) BEGIN
 SELECT RAISE(ABORT,'material owner must begin at one');
END;
