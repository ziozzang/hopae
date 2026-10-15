-- Internal durable incarnation for future native Human owner checks.
-- Deliberately no FK: a deleted provider leaves a tombstone.
CREATE TABLE human_provider_owners (
    provider_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK (typeof(revision)='integer' AND revision>0)
) STRICT;
INSERT INTO human_provider_owners(provider_id,revision) SELECT provider_id,1 FROM providers;

CREATE TRIGGER human_provider_owner_identity BEFORE UPDATE OF provider_id ON providers
WHEN NEW.provider_id IS NOT OLD.provider_id
BEGIN
    SELECT RAISE(ABORT,'provider identity is immutable');
END;

CREATE TRIGGER human_provider_owner_insert AFTER INSERT ON providers
BEGIN
    INSERT INTO human_provider_owners(provider_id,revision) VALUES(NEW.provider_id,1)
    ON CONFLICT(provider_id) DO UPDATE SET revision=revision+1;
END;

CREATE TRIGGER human_provider_owner_delete AFTER DELETE ON providers
BEGIN
    UPDATE human_provider_owners SET revision=revision+1 WHERE provider_id=OLD.provider_id;
END;

CREATE TRIGGER human_provider_owner_material AFTER UPDATE ON providers
WHEN NEW.kind IS NOT OLD.kind
  OR NEW.enabled IS NOT OLD.enabled OR NEW.deleted_at IS NOT OLD.deleted_at
  OR NEW.config IS NOT OLD.config OR NEW.client_secret_env IS NOT OLD.client_secret_env
  OR NEW.allowed_email_domains IS NOT OLD.allowed_email_domains
  OR NEW.authoritative_domains IS NOT OLD.authoritative_domains
  OR NEW.auto_link IS NOT OLD.auto_link OR NEW.trust_email IS NOT OLD.trust_email
BEGIN
    UPDATE human_provider_owners SET revision=revision+1 WHERE provider_id=NEW.provider_id;
END;
