-- Public Store identity namespace, not a secret or an authentication proof.
-- History begins at v10; earlier deleted user IDs cannot be reconstructed.
CREATE TABLE human_authority_realm (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton=1),
    realm TEXT NOT NULL CHECK (typeof(realm)='text' AND length(realm)=64 AND realm NOT GLOB '*[^0-9a-f]*' AND realm<>'0000000000000000000000000000000000000000000000000000000000000000')
) STRICT;
INSERT INTO human_authority_realm(singleton,realm) VALUES(1,lower(hex(randomblob(32))));
CREATE TRIGGER human_realm_insert BEFORE INSERT ON human_authority_realm
WHEN EXISTS(SELECT 1 FROM human_authority_realm)
BEGIN
    SELECT RAISE(ABORT,'Human realm is immutable');
END;
CREATE TRIGGER human_realm_update BEFORE UPDATE ON human_authority_realm
BEGIN
    SELECT RAISE(ABORT,'Human realm is immutable');
END;
CREATE TRIGGER human_realm_delete BEFORE DELETE ON human_authority_realm
BEGIN
    SELECT RAISE(ABORT,'Human realm is immutable');
END;

-- No FK: reservations survive hard deletion and cannot be reused by REPLACE.
CREATE TABLE human_user_ids (
    user_id TEXT PRIMARY KEY NOT NULL
) STRICT;
INSERT INTO human_user_ids(user_id) SELECT user_id FROM users;
CREATE TRIGGER human_user_ids_insert BEFORE INSERT ON human_user_ids
WHEN EXISTS(SELECT 1 FROM human_user_ids WHERE user_id=NEW.user_id)
BEGIN
    SELECT RAISE(ABORT,'Human user ID is reserved');
END;
CREATE TRIGGER human_user_ids_update BEFORE UPDATE ON human_user_ids
BEGIN
    SELECT RAISE(ABORT,'Human user ID is immutable');
END;
CREATE TRIGGER human_user_ids_delete BEFORE DELETE ON human_user_ids
BEGIN
    SELECT RAISE(ABORT,'Human user ID reservation is permanent');
END;
CREATE TRIGGER human_user_identity_insert BEFORE INSERT ON users
WHEN EXISTS(SELECT 1 FROM human_user_ids WHERE user_id=NEW.user_id)
BEGIN
    SELECT RAISE(ABORT,'Human user ID cannot be reused');
END;
CREATE TRIGGER human_user_identity_reserve AFTER INSERT ON users
BEGIN
    INSERT INTO human_user_ids(user_id) VALUES(NEW.user_id);
END;
CREATE TRIGGER human_user_identity_update BEFORE UPDATE OF user_id ON users
WHEN NEW.user_id IS NOT OLD.user_id
BEGIN
    SELECT RAISE(ABORT,'User identity is immutable');
END;
