//! Stable account labels for policy administration; never authentication evidence.
use crate::store::{Deadline, StoreError, StoreResult};
use sha2::{Digest as _, Sha256};

fn valid_user_coordinate(user: &str) -> bool {
    !user.is_empty() && user.len() <= 256 && !user.chars().any(char::is_control)
}

pub(super) fn derive(issuer: &str, realm: &str, user: &str) -> StoreResult<String> {
    let invalid = || StoreError::Conflict("invalid Human subject coordinate");
    if issuer.is_empty()
        || issuer.len() > 128
        || !issuer
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        || !valid_user_coordinate(user)
        || !super::identity_owner::valid_realm(realm)
    {
        return Err(invalid());
    }
    let realm = data_encoding::HEXLOWER
        .decode(realm.as_bytes())
        .map_err(|_| invalid())?;
    let mut hash = Sha256::new();
    hash.update(b"hopae:native-human-subject:v1\0");
    for value in [issuer.as_bytes(), realm.as_slice(), user.as_bytes()] {
        hash.update(
            u32::try_from(value.len())
                .map_err(|_| invalid())?
                .to_be_bytes(),
        );
        hash.update(value);
    }
    Ok(format!(
        "human1:{}",
        data_encoding::HEXLOWER.encode(&hash.finalize())
    ))
}
impl super::Store {
    /// Admin-only metadata lookup. Existing user and historical reservation must
    /// belong to the actual Store realm; no session, AAL or grant is created.
    #[cfg(test)]
    pub(crate) async fn admin_human_subject(
        &self,
        issuer: String,
        user: String,
        deadline: Deadline,
    ) -> StoreResult<Option<String>> {
        Ok(self
            .admin_human_subjects(issuer, vec![user.clone()], deadline)
            .await?
            .remove(&user))
    }
    pub(crate) async fn admin_human_subjects(
        &self,
        issuer: String,
        users: Vec<String>,
        deadline: Deadline,
    ) -> StoreResult<std::collections::BTreeMap<String, String>> {
        if users.len() > 200 {
            return Err(StoreError::Conflict("too many Human metadata subjects"));
        }
        let users: Vec<_> = users
            .into_iter()
            .filter(|user| valid_user_coordinate(user))
            .collect();
        let query = serde_json::to_string(&users)
            .map_err(|_| StoreError::Conflict("invalid Human metadata query"))?;
        self.read_checked("admin_human_subjects", Some(deadline), move |connection, check| {
            check.now()?;
            let mut statement = connection.prepare_cached(
                "SELECT u.user_id,a.realm FROM users u JOIN human_user_ids i ON i.user_id=u.user_id JOIN human_authority_realm a ON a.singleton=1 WHERE u.user_id IN (SELECT value FROM json_each(?1))",
            )?;
            let rows = statement.query_map([query], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
            let mut result = std::collections::BTreeMap::new();
            for row in rows {
                check.now()?;
                let (user, realm) = row?;
                let subject = derive(&issuer, &realm, &user)?;
                result.insert(user, subject);
            }
            check.now()?;
            Ok(result)
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_human_subject_metadata_uses_independent_coordinate_vector() {
        let realm = "12".repeat(32);
        assert_eq!(
            derive("owned-issuer", &realm, "u_legacy:kept").unwrap(),
            "human1:0ba9b6ee1c2f84747d389d7432edfb1a8d4ace8ee44200dae9f6d4121a107dda"
        );
        for value in [
            derive("other", &realm, "u_legacy:kept"),
            derive("owned-issuer", &"13".repeat(32), "u_legacy:kept"),
            derive("owned-issuer", &realm, "u_other"),
        ] {
            assert_ne!(
                value.unwrap(),
                derive("owned-issuer", &realm, "u_legacy:kept").unwrap()
            );
        }
        for (issuer, realm, user) in [
            ("", realm.clone(), "u_ok"),
            ("bad/issuer", realm.clone(), "u_ok"),
            ("owned", "00".repeat(32), "u_ok"),
            ("owned", "AB".repeat(32), "u_ok"),
            ("owned", realm.clone(), ""),
            ("owned", realm, "u_\n"),
        ] {
            assert!(derive(issuer, &realm, user).is_err());
        }
    }
}
