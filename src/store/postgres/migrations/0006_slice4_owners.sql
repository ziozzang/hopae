-- ADR-0020 slice 4: the native Human owner foundation, as SQLite schema
-- 7, 9 and 10: the store's identity namespace (realm), provider and
-- compiled-material owner revisions, and primary-authentication provenance.

-- Public identity namespace, not a secret. Set once (by the store on first
-- start, or copied by the SQLite migration) and immutable afterwards.
CREATE TABLE human_authority_realm (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    realm     TEXT NOT NULL CHECK (realm ~ '^[0-9a-f]{64}$' AND realm <> repeat('0', 64))
);
CREATE FUNCTION hopae_realm_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Human realm is immutable' USING ERRCODE = 'P0001';
END $$;
CREATE TRIGGER human_realm_update BEFORE UPDATE OR DELETE ON human_authority_realm
    FOR EACH ROW EXECUTE FUNCTION hopae_realm_immutable();

-- Provider owner revisions: every material change of a provider row moves it.
CREATE TABLE human_provider_owners (
    provider_id TEXT PRIMARY KEY,
    revision    BIGINT NOT NULL CHECK (revision > 0)
);
INSERT INTO human_provider_owners (provider_id, revision) SELECT provider_id, 1 FROM providers;
CREATE FUNCTION hopae_provider_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO human_provider_owners (provider_id, revision) VALUES (NEW.provider_id, 1)
            ON CONFLICT (provider_id) DO UPDATE SET revision = human_provider_owners.revision + 1;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE human_provider_owners SET revision = revision + 1 WHERE provider_id = OLD.provider_id;
        RETURN OLD;
    END IF;
    IF NEW.provider_id IS DISTINCT FROM OLD.provider_id THEN
        RAISE EXCEPTION 'provider identity is immutable' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.enabled IS DISTINCT FROM OLD.enabled
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR NEW.config IS DISTINCT FROM OLD.config
       OR NEW.client_secret_env IS DISTINCT FROM OLD.client_secret_env
       OR NEW.allowed_email_domains IS DISTINCT FROM OLD.allowed_email_domains
       OR NEW.authoritative_domains IS DISTINCT FROM OLD.authoritative_domains
       OR NEW.auto_link IS DISTINCT FROM OLD.auto_link OR NEW.trust_email IS DISTINCT FROM OLD.trust_email THEN
        UPDATE human_provider_owners SET revision = revision + 1 WHERE provider_id = NEW.provider_id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER human_provider_owner AFTER INSERT OR UPDATE OR DELETE ON providers
    FOR EACH ROW EXECUTE FUNCTION hopae_provider_owner();

-- Opaque keyed compiler fingerprints with permanent monotonic tombstones.
CREATE TABLE human_provider_material_owners (
    provider_id TEXT PRIMARY KEY,
    revision    BIGINT NOT NULL CHECK (revision > 0),
    fingerprint BYTEA CHECK (fingerprint IS NULL OR octet_length(fingerprint) = 32)
);
CREATE FUNCTION hopae_material_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'material owner cannot be deleted' USING ERRCODE = 'P0001';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 THEN
            RAISE EXCEPTION 'material owner must begin at one' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.provider_id IS DISTINCT FROM OLD.provider_id
       OR (NEW.fingerprint IS NOT DISTINCT FROM OLD.fingerprint AND NEW.revision IS DISTINCT FROM OLD.revision)
       OR (NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
           AND (OLD.revision = 9223372036854775807 OR NEW.revision <> OLD.revision + 1)) THEN
        RAISE EXCEPTION 'invalid material owner transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER human_material_owner BEFORE INSERT OR UPDATE OR DELETE ON human_provider_material_owners
    FOR EACH ROW EXECUTE FUNCTION hopae_material_owner();

-- Original native primary authentication only.
CREATE TABLE session_primary_provenance (
    session_id            TEXT PRIMARY KEY REFERENCES sessions (session_id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL,
    provider_id           TEXT NOT NULL,
    material_revision     BIGINT NOT NULL CHECK (material_revision > 0),
    provider_revision     BIGINT NOT NULL CHECK (provider_revision > 0),
    config_generation     BIGINT NOT NULL CHECK (config_generation > 0),
    credential_generation BIGINT NOT NULL CHECK (credential_generation > 0),
    subject               TEXT NOT NULL CHECK (length(subject) > 0 AND length(subject) <= 4096),
    auth_time_ms          BIGINT NOT NULL CHECK (auth_time_ms >= 0),
    auth_time_source      TEXT NOT NULL,
    factor_index          BIGINT NOT NULL CHECK (factor_index >= 0),
    factor_kind           TEXT NOT NULL,
    factor_at_ms          BIGINT NOT NULL CHECK (factor_at_ms >= 0)
);
