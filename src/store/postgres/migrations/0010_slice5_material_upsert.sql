-- ADR-0020 slice 5: PostgreSQL fires BEFORE INSERT row triggers also for an
-- INSERT ... ON CONFLICT DO UPDATE whose row exists. As SQLite's insert
-- trigger, "must begin at one" applies only when the provider has no row
-- yet; the update branch keeps the revision rules for the existing row.
CREATE OR REPLACE FUNCTION hopae_material_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'material owner cannot be deleted' USING ERRCODE = 'P0001';
    ELSIF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 AND NOT EXISTS (
            SELECT 1 FROM human_provider_material_owners WHERE provider_id = NEW.provider_id
        ) THEN
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
