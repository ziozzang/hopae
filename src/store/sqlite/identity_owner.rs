//! Durable identity namespace and historical user-ID reservations, not a proof.
use crate::store::{StoreError, StoreResult};
use rusqlite::OptionalExtension;
fn corrupt() -> StoreError {
    StoreError::Corrupt("schema v10 invalid Human identity owner".into())
}
pub(super) fn valid_realm(realm: &str) -> bool {
    realm.len() == 64
        && realm
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && realm.bytes().any(|b| b != b'0')
}
// Normalize only outside quoted tokens. In particular preserve case and spaces
// inside SQL string literals: changing GLOB [a-f] to [A-F] changes its meaning.
fn normalized(sql: &str) -> String {
    let mut output = String::new();
    let mut quote = None;
    for c in sql.chars() {
        if let Some(end) = quote {
            output.push(c);
            if c == end {
                quote = None;
            }
        } else if matches!(c, '\'' | '"' | '`' | '[') {
            quote = Some(if c == '[' { ']' } else { c });
            output.push(c);
        } else if !c.is_whitespace() {
            output.push(c.to_ascii_lowercase());
        }
    }
    output.trim_end_matches(';').to_owned()
}
pub(super) fn validate_foundation(connection: &rusqlite::Connection) -> StoreResult<()> {
    let sql = include_str!("../migrations/0010_human_identity_owners.sql");
    for (kind, name) in [
        ("table", "human_authority_realm"),
        ("table", "human_user_ids"),
        ("trigger", "human_realm_insert"),
        ("trigger", "human_realm_update"),
        ("trigger", "human_realm_delete"),
        ("trigger", "human_user_ids_insert"),
        ("trigger", "human_user_ids_update"),
        ("trigger", "human_user_ids_delete"),
        ("trigger", "human_user_identity_insert"),
        ("trigger", "human_user_identity_reserve"),
        ("trigger", "human_user_identity_update"),
    ] {
        let start = sql
            .find(&format!("CREATE {} {name}", kind.to_ascii_uppercase()))
            .expect("embedded identity schema");
        let rest = &sql[start..];
        let end = if kind == "trigger" {
            rest.find("\nEND;").expect("embedded identity trigger") + 5
        } else {
            rest.find(';').expect("embedded identity table") + 1
        };
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                [kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref().map(normalized) != Some(normalized(&rest[..end])) {
            return Err(corrupt());
        }
    }
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM human_authority_realm", [], |row| {
            row.get(0)
        })?;
    if count != 1 {
        return Err(corrupt());
    }
    let realm: Option<String> = connection
        .query_row(
            "SELECT realm FROM human_authority_realm WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if !realm.as_deref().is_some_and(valid_realm) {
        return Err(corrupt());
    }
    let missing:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM users u LEFT JOIN human_user_ids h ON h.user_id=u.user_id WHERE h.user_id IS NULL)",[],|row|row.get(0))?;
    if missing {
        return Err(corrupt());
    }
    Ok(())
}
#[cfg(test)]
#[path = "identity_owner_tests.rs"]
mod tests;
