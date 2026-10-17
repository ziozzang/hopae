//! The ADR-0023 risk memory in the shared store (schema 13), as the process
//! memory of `policy::risk::Memory`: a session's requests land on any
//! replica, so its last country and ASN, and the user's countries, are kept
//! where every replica reads them. A user's list is read and rewritten
//! under its row lock (concurrent replicas never lose a country). Expired
//! entries are ignored on read and pruned a few per write; the entry caps
//! are enforced by `risk_maintain` (oldest first).
use crate::crypto::Timestamp;
use crate::policy::risk::{MemoryBounds, RiskLedger, Seen};
use crate::store::{StoreError, StoreResult};

use super::{PgStore, pg, retry};

const PRUNE_BATCH: i64 = 32;

fn ms(d: std::time::Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn countries(text: &str) -> StoreResult<Vec<String>> {
    serde_json::from_str(text).map_err(|_| StoreError::Corrupt("risk_users.countries".into()))
}

#[async_trait::async_trait]
impl RiskLedger for PgStore {
    async fn risk_seen(
        &self,
        session: &str,
        user: &str,
        now: Timestamp,
        bounds: &MemoryBounds,
    ) -> StoreResult<Seen> {
        let client = self.client().await?;
        let now = now.0;
        let s = client
            .query_opt(
                "SELECT country, asn FROM risk_sessions WHERE session_id = $1 AND seen_ms <= $2 AND $2 - seen_ms <= $3",
                &[&session, &now, &ms(bounds.session_ttl)],
            )
            .await
            .map_err(pg)?;
        let u = client
            .query_opt(
                "SELECT countries FROM risk_users WHERE user_id = $1 AND seen_ms <= $2 AND $2 - seen_ms <= $3",
                &[&user, &now, &ms(bounds.user_ttl)],
            )
            .await
            .map_err(pg)?;
        Ok(Seen {
            session_country: s.as_ref().and_then(|r| r.get(0)),
            session_asn: s
                .as_ref()
                .and_then(|r| r.get::<_, Option<i64>>(1))
                .and_then(|v| u32::try_from(v).ok()),
            user_countries: match u {
                Some(r) => countries(&r.get::<_, String>(0))?,
                None => Vec::new(),
            },
        })
    }

    async fn risk_observe(
        &self,
        session: &str,
        user: &str,
        country: Option<&str>,
        asn: Option<u32>,
        now: Timestamp,
        bounds: &MemoryBounds,
    ) -> StoreResult<()> {
        let now = now.0;
        retry(|| async {
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            tx.execute(
                "INSERT INTO risk_sessions (session_id, country, asn, seen_ms) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (session_id) DO UPDATE SET country = excluded.country, asn = excluded.asn, seen_ms = excluded.seen_ms",
                &[&session, &country, &asn.map(i64::from), &now],
            )
            .await
            .map_err(pg)?;
            if let Some(country) = country {
                tx.execute(
                    "INSERT INTO risk_users (user_id, countries, seen_ms) VALUES ($1, '[]', $2) ON CONFLICT (user_id) DO NOTHING",
                    &[&user, &now],
                )
                .await
                .map_err(pg)?;
                let r = tx
                    .query_one(
                        "SELECT countries, seen_ms FROM risk_users WHERE user_id = $1 FOR UPDATE",
                        &[&user],
                    )
                    .await
                    .map_err(pg)?;
                let at: i64 = r.get(1);
                let mut list = if at <= now && now - at <= ms(bounds.user_ttl) {
                    countries(&r.get::<_, String>(0))?
                } else {
                    Vec::new()
                };
                list.retain(|c| c != country);
                list.push(country.to_string());
                while list.len() > bounds.countries_per_user {
                    list.remove(0);
                }
                let text = serde_json::to_string(&list)
                    .map_err(|_| StoreError::Corrupt("risk_users.countries".into()))?;
                tx.execute(
                    "UPDATE risk_users SET countries = $2, seen_ms = $3 WHERE user_id = $1",
                    &[&user, &text, &now],
                )
                .await
                .map_err(pg)?;
            }
            for (table, ttl) in [
                ("risk_sessions", ms(bounds.session_ttl)),
                ("risk_users", ms(bounds.user_ttl)),
            ] {
                let key = if table == "risk_sessions" { "session_id" } else { "user_id" };
                tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} WHERE seen_ms < $1 - $2 LIMIT $3 FOR UPDATE SKIP LOCKED)"
                    ),
                    &[&now, &ttl, &PRUNE_BATCH],
                )
                .await
                .map_err(pg)?;
            }
            tx.commit().await.map_err(pg)
        })
        .await
    }

    async fn risk_maintain(&self, bounds: &MemoryBounds) -> StoreResult<()> {
        let client = self.client().await?;
        for (table, key, max) in [
            ("risk_sessions", "session_id", bounds.max_sessions),
            ("risk_users", "user_id", bounds.max_users),
        ] {
            let max = i64::try_from(max).unwrap_or(i64::MAX);
            client
                .execute(
                    &format!(
                        "DELETE FROM {table} WHERE {key} IN (SELECT {key} FROM {table} ORDER BY seen_ms DESC, {key} DESC OFFSET $1)"
                    ),
                    &[&max],
                )
                .await
                .map_err(pg)?;
        }
        Ok(())
    }
}
