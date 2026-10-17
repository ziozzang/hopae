//! Password and code attempt windows in the shared store (schema 12): the
//! `password_attempts` limits hold across replicas. One upsert per window
//! counts the submission atomically (the row lock serializes concurrent
//! replicas); a window whose end passed restarts at one. Expired rows are
//! pruned a few at a time on every admission.
use crate::portal::password_attempts::{AttemptLedger, Check};
use crate::store::StoreResult;

use super::{PgStore, pg, retry};

/// Expired rows removed per admission (keeps the table to open windows).
const PRUNE_BATCH: i64 = 32;

#[async_trait::async_trait]
impl AttemptLedger for PgStore {
    async fn admit_attempts(&self, checks: &[Check]) -> StoreResult<bool> {
        retry(|| async {
            let now = self.now().0;
            let mut client = self.client().await?;
            let tx = self.begin(&mut client).await?;
            let mut admitted = true;
            for check in checks {
                let span = i64::try_from(check.limit.window.as_millis()).unwrap_or(i64::MAX);
                let ends = now.saturating_add(span);
                let count: i64 = tx
                    .query_one(
                        "INSERT INTO attempt_windows (scope, key, started_ms, ends_ms, count) VALUES ($1, $2, $3, $4, 1) \
                         ON CONFLICT (scope, key) DO UPDATE SET \
                           started_ms = CASE WHEN attempt_windows.ends_ms <= $3 THEN $3 ELSE attempt_windows.started_ms END, \
                           ends_ms = CASE WHEN attempt_windows.ends_ms <= $3 THEN $4 ELSE attempt_windows.ends_ms END, \
                           count = CASE WHEN attempt_windows.ends_ms <= $3 THEN 1 ELSE attempt_windows.count + 1 END \
                         RETURNING count",
                        &[&check.scope.as_str(), &check.key.to_vec(), &now, &ends],
                    )
                    .await
                    .map_err(pg)?
                    .get(0);
                if count > i64::from(check.limit.burst) {
                    admitted = false;
                }
            }
            tx.execute(
                "DELETE FROM attempt_windows WHERE (scope, key) IN \
                 (SELECT scope, key FROM attempt_windows WHERE ends_ms <= $1 LIMIT $2 FOR UPDATE SKIP LOCKED)",
                &[&now, &PRUNE_BATCH],
            )
            .await
            .map_err(pg)?;
            tx.commit().await.map_err(pg)?;
            Ok(admitted)
        })
        .await
    }
}
