-- ADR-0020 slice 5: advisory locks live in the store's namespace (its
-- schema, two-key form), as the application's own locks now do, so stores in
-- different schemas of one database never contend.
CREATE OR REPLACE FUNCTION hopae_user_reserve() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(current_schema()), 7040);
    INSERT INTO human_user_ids (user_id) VALUES (NEW.user_id);
    RETURN NEW;
END $$;
