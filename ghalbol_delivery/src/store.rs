//! Mailbox storage and quota.

use crate::config::DeliveryConfig;
use crate::envelope::ValidatedEnvelope;
use crate::error::{DeliveryError, Result};
use crate::policy::PolicyLimits;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, serde::Serialize)]
pub struct QuotaStatus {
    pub allocated_bytes: i64,
    pub used_bytes: i64,
    pub pending_count: i64,
}

impl QuotaStatus {
    /// `quota.warning` when pending bytes reach 90% of the allocation.
    pub fn above_warning_threshold(&self) -> bool {
        self.allocated_bytes > 0
            && self.used_bytes.saturating_mul(10) >= self.allocated_bytes.saturating_mul(9)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MailboxRow {
    pub message_id: String,
    pub recipient_wire: String,
    pub size_bytes: i64,
    pub uploaded_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: String,
}

#[derive(Clone, Debug)]
pub struct HealthMetrics {
    pub connected_peers: usize,
    pub pending_messages: i64,
    pub pending_bytes: i64,
    pub oldest_pending_age_secs: i64,
}

pub struct MailboxStore {
    conn: Mutex<Connection>,
    quota_per_peer: i64,
    max_pending_messages: i64,
    max_terminal_rows: i64,
}

impl MailboxStore {
    pub fn new(conn: Connection, config: &DeliveryConfig) -> Self {
        Self {
            conn: Mutex::new(conn),
            quota_per_peer: config.quota_bytes_per_peer as i64,
            max_pending_messages: config.max_pending_messages_per_peer as i64,
            max_terminal_rows: config.max_terminal_rows_per_peer as i64,
        }
    }

    pub fn shared(conn: Connection, config: &DeliveryConfig) -> Arc<Self> {
        Arc::new(Self::new(conn, config))
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn prune_excess_terminal_rows(
        tx: &rusqlite::Transaction<'_>,
        sender_wire: &str,
        max_terminal_rows: i64,
    ) -> Result<()> {
        if max_terminal_rows <= 0 {
            return Ok(());
        }
        loop {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pending_messages
                 WHERE sender_wire = ?1 AND state IN ('delivered', 'read', 'expired')",
                params![sender_wire],
                |r| r.get(0),
            )?;
            if count <= max_terminal_rows {
                break;
            }
            let excess = count - max_terminal_rows;
            let batch = excess.min(500);
            tx.execute(
                "DELETE FROM pending_messages WHERE rowid IN (
                    SELECT rowid FROM pending_messages
                    WHERE sender_wire = ?1 AND state IN ('delivered', 'read', 'expired')
                    ORDER BY uploaded_at_ms ASC, message_id ASC
                    LIMIT ?2
                 )",
                params![sender_wire, batch],
            )?;
        }
        Ok(())
    }

    pub fn quota_status(&self, sender_wire: &str) -> Result<QuotaStatus> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let used: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM pending_messages
             WHERE sender_wire = ?1 AND state = 'queued'",
            params![sender_wire],
            |r| r.get(0),
        )?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pending_messages
             WHERE sender_wire = ?1 AND state = 'queued'",
            params![sender_wire],
            |r| r.get(0),
        )?;
        Ok(QuotaStatus {
            allocated_bytes: self.quota_per_peer,
            used_bytes: used,
            pending_count: count,
        })
    }

    pub fn list_outbox(&self, sender_wire: &str, include_expired: bool) -> Result<Vec<MailboxRow>> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let sql = if include_expired {
            "SELECT message_id, recipient_wire, size_bytes, uploaded_at_ms, expires_at_ms, state
             FROM pending_messages WHERE sender_wire = ?1
             ORDER BY uploaded_at_ms DESC"
        } else {
            "SELECT message_id, recipient_wire, size_bytes, uploaded_at_ms, expires_at_ms, state
             FROM pending_messages WHERE sender_wire = ?1 AND state = 'queued'
             ORDER BY uploaded_at_ms DESC"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params![sender_wire], |r| {
                Ok(MailboxRow {
                    message_id: r.get(0)?,
                    recipient_wire: r.get(1)?,
                    size_bytes: r.get(2)?,
                    uploaded_at_ms: r.get(3)?,
                    expires_at_ms: r.get(4)?,
                    state: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn upload(
        &self,
        env: ValidatedEnvelope,
        ttl_secs: u64,
        policy: &PolicyLimits,
    ) -> Result<(QuotaStatus, bool)> {
        let mut conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = Self::now_ms();
        let expires_at = now + (ttl_secs as i64) * 1000;
        let max_exp = policy.max_expires_at_ms(now);
        let expires_at = expires_at.min(max_exp);

        let existing_state: Option<String> = tx
            .query_row(
                "SELECT state FROM pending_messages WHERE sender_wire = ?1 AND message_id = ?2",
                params![env.sender_wire, env.message_id],
                |r| r.get(0),
            )
            .ok();

        let pending_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM pending_messages
             WHERE sender_wire = ?1 AND state = 'queued'",
            params![env.sender_wire],
            |r| r.get(0),
        )?;
        let adds_pending_queue = existing_state.as_deref() != Some("queued");
        if adds_pending_queue && pending_count >= self.max_pending_messages {
            return Err(DeliveryError::QuotaExceeded(format!(
                "pending message count {pending_count} at cap {}",
                self.max_pending_messages
            )));
        }

        let used: i64 = tx.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM pending_messages
             WHERE sender_wire = ?1 AND state = 'queued'",
            params![env.sender_wire],
            |r| r.get(0),
        )?;

        let replace_bytes: i64 = if existing_state.as_deref() == Some("queued") {
            tx.query_row(
                "SELECT size_bytes FROM pending_messages
                 WHERE sender_wire = ?1 AND message_id = ?2",
                params![env.sender_wire, env.message_id],
                |r| r.get(0),
            )
            .unwrap_or(0)
        } else {
            0
        };

        let new_used = used - replace_bytes + env.size_bytes;
        if new_used > self.quota_per_peer {
            return Err(DeliveryError::QuotaExceeded(format!(
                "used {new_used} exceeds allocated {}",
                self.quota_per_peer
            )));
        }

        let replaced = existing_state.as_deref() == Some("queued");
        if let Some(state) = existing_state {
            if state == "queued" {
                tx.execute(
                    "UPDATE pending_messages SET
                        recipient_wire = ?3, envelope_blob = ?4, size_bytes = ?5,
                        uploaded_at_ms = ?6, expires_at_ms = ?7, state = 'queued',
                        delivered_at_ms = NULL, expired_at_ms = NULL, read_at_ms = NULL
                     WHERE sender_wire = ?1 AND message_id = ?2",
                    params![
                        env.sender_wire,
                        env.message_id,
                        env.recipient_wire,
                        env.envelope_blob,
                        env.size_bytes,
                        now,
                        expires_at,
                    ],
                )?;
            } else {
                tx.execute(
                    "UPDATE pending_messages SET
                        recipient_wire = ?3, envelope_blob = ?4, size_bytes = ?5,
                        uploaded_at_ms = ?6, expires_at_ms = ?7, state = 'queued',
                        delivered_at_ms = NULL, expired_at_ms = NULL, read_at_ms = NULL
                     WHERE sender_wire = ?1 AND message_id = ?2",
                    params![
                        env.sender_wire,
                        env.message_id,
                        env.recipient_wire,
                        env.envelope_blob,
                        env.size_bytes,
                        now,
                        expires_at,
                    ],
                )?;
            }
        } else {
            tx.execute(
                "INSERT INTO pending_messages
                 (sender_wire, message_id, recipient_wire, envelope_blob, size_bytes,
                  uploaded_at_ms, expires_at_ms, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued')",
                params![
                    env.sender_wire,
                    env.message_id,
                    env.recipient_wire,
                    env.envelope_blob,
                    env.size_bytes,
                    now,
                    expires_at,
                ],
            )?;
        }
        Self::prune_excess_terminal_rows(&tx, &env.sender_wire, self.max_terminal_rows)?;
        tx.commit()?;

        tracing::info!(
            sender_wire = %env.sender_wire,
            message_id = %env.message_id,
            recipient_wire = %env.recipient_wire,
            bytes = env.size_bytes,
            state = "queued",
            replaced,
            "message uploaded"
        );

        let sender_wire = env.sender_wire.clone();
        drop(conn);
        let quota = self.quota_status(&sender_wire)?;
        Ok((quota, replaced))
    }

    pub fn extend_ttl(
        &self,
        sender_wire: &str,
        message_id: &str,
        extend_secs: u64,
        policy: &PolicyLimits,
    ) -> Result<MailboxRow> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let row: MailboxRow = conn
            .query_row(
                "SELECT message_id, recipient_wire, size_bytes, uploaded_at_ms, expires_at_ms, state
                 FROM pending_messages WHERE sender_wire = ?1 AND message_id = ?2",
                params![sender_wire, message_id],
                |r| {
                    Ok(MailboxRow {
                        message_id: r.get(0)?,
                        recipient_wire: r.get(1)?,
                        size_bytes: r.get(2)?,
                        uploaded_at_ms: r.get(3)?,
                        expires_at_ms: r.get(4)?,
                        state: r.get(5)?,
                    })
                },
            )
            .map_err(|_| DeliveryError::NotFound("message not found".into()))?;

        if row.state != "queued" {
            if row.state == "expired" {
                return Err(DeliveryError::Expired(
                    "message expired; resend required".into(),
                ));
            }
            return Err(DeliveryError::BadRequest(format!(
                "cannot extend state={}",
                row.state
            )));
        }

        let now = Self::now_ms();
        let candidate = now + (extend_secs as i64) * 1000;
        let max_exp = policy.max_expires_at_ms(row.uploaded_at_ms);
        let new_expires = candidate.min(max_exp);
        if new_expires <= row.expires_at_ms {
            return Err(DeliveryError::TtlInvalid(
                "extend_secs would not increase expiry".into(),
            ));
        }

        let changed = conn.execute(
            "UPDATE pending_messages SET expires_at_ms = ?3
             WHERE sender_wire = ?1 AND message_id = ?2 AND state = 'queued'",
            params![sender_wire, message_id, new_expires],
        )?;
        if changed == 0 {
            let state: String = conn.query_row(
                "SELECT state FROM pending_messages
                 WHERE sender_wire = ?1 AND message_id = ?2",
                params![sender_wire, message_id],
                |r| r.get(0),
            )?;
            if state == "expired" {
                return Err(DeliveryError::Expired(
                    "message expired; resend required".into(),
                ));
            }
            return Err(DeliveryError::BadRequest(format!(
                "cannot extend state={state}"
            )));
        }

        tracing::info!(
            sender_wire = %sender_wire,
            message_id = %message_id,
            new_expires_at_ms = new_expires,
            "ttl extended"
        );

        Ok(MailboxRow {
            expires_at_ms: new_expires,
            ..row
        })
    }

    /// Ack delivery. Returns `(sender_wire, newly_transitioned)`.
    /// Already-`delivered` / `read` rows are idempotent success with `newly_transitioned=false`
    /// so reconnect retries do not fail or re-notify the sender.
    pub fn ack_deliver(
        &self,
        recipient_wire: &str,
        message_id: &str,
        sender_wire: &str,
    ) -> Result<(String, bool)> {
        let mut conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let state: String = conn
            .query_row(
                "SELECT state FROM pending_messages
                 WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3",
                params![recipient_wire, message_id, sender_wire],
                |r| r.get(0),
            )
            .map_err(|_| DeliveryError::NotFound("message metadata not found".into()))?;

        if state == "delivered" || state == "read" {
            return Ok((sender_wire.to_string(), false));
        }
        if state != "queued" {
            return Err(DeliveryError::BadRequest(format!(
                "cannot deliver-ack state={state}"
            )));
        }

        let now = Self::now_ms();
        let changed = conn.execute(
            "UPDATE pending_messages SET state = 'delivered', envelope_blob = NULL,
             delivered_at_ms = ?4
             WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3
               AND state = 'queued'",
            params![recipient_wire, message_id, sender_wire, now],
        )?;
        if changed == 0 {
            let state: String = conn.query_row(
                "SELECT state FROM pending_messages
                 WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3",
                params![recipient_wire, message_id, sender_wire],
                |r| r.get(0),
            )?;
            if state == "delivered" || state == "read" {
                return Ok((sender_wire.to_string(), false));
            }
            return Err(DeliveryError::BadRequest(
                "cannot deliver-ack state changed".into(),
            ));
        }

        let tx = conn.transaction()?;
        Self::prune_excess_terminal_rows(&tx, sender_wire, self.max_terminal_rows)?;
        tx.commit()?;

        tracing::info!(
            recipient_wire = %recipient_wire,
            sender_wire = %sender_wire,
            message_id = %message_id,
            state = "delivered",
            "message acked"
        );

        Ok((sender_wire.to_string(), true))
    }

    /// `(sender_wire, newly_transitioned)`. Already-`read` is success with `false`
    /// so a replay does not notify the sender again.
    pub fn ack_read(
        &self,
        recipient_wire: &str,
        message_id: &str,
        sender_wire: &str,
    ) -> Result<(String, bool)> {
        let mut conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let state: String = conn
            .query_row(
                "SELECT state FROM pending_messages
                 WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3",
                params![recipient_wire, message_id, sender_wire],
                |r| r.get(0),
            )
            .map_err(|_| DeliveryError::NotFound("message metadata not found".into()))?;

        if state == "read" {
            return Ok((sender_wire.to_string(), false));
        }
        if state != "delivered" {
            return Err(DeliveryError::BadRequest(format!(
                "cannot read-ack state={state}"
            )));
        }

        let now = Self::now_ms();
        let changed = conn.execute(
            "UPDATE pending_messages SET state = 'read', read_at_ms = ?4
             WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3
               AND state = 'delivered'",
            params![recipient_wire, message_id, sender_wire, now],
        )?;
        if changed == 0 {
            let state: String = conn.query_row(
                "SELECT state FROM pending_messages
                 WHERE recipient_wire = ?1 AND message_id = ?2 AND sender_wire = ?3",
                params![recipient_wire, message_id, sender_wire],
                |r| r.get(0),
            )?;
            if state == "read" {
                return Ok((sender_wire.to_string(), false));
            }
            return Err(DeliveryError::BadRequest(
                "cannot read-ack state changed".into(),
            ));
        }

        let tx = conn.transaction()?;
        Self::prune_excess_terminal_rows(&tx, sender_wire, self.max_terminal_rows)?;
        tx.commit()?;

        tracing::info!(
            recipient_wire = %recipient_wire,
            sender_wire = %sender_wire,
            message_id = %message_id,
            state = "read",
            "message read acked"
        );

        Ok((sender_wire.to_string(), true))
    }

    pub fn pending_for_recipient(&self, recipient_wire: &str) -> Result<Vec<(String, String, i64)>> {
        let mut out = Vec::new();
        let mut after_ms = -1i64;
        let mut after_id = String::new();
        loop {
            let page = self.pending_page(recipient_wire, after_ms, &after_id, 128)?;
            if page.is_empty() {
                break;
            }
            let last = page.len() - 1;
            after_ms = page[last].3;
            after_id = page[last].1.clone();
            let n = page.len();
            for (blob, id, exp, _) in page {
                out.push((blob, id, exp));
            }
            if n < 128 {
                break;
            }
        }
        Ok(out)
    }

    /// `(envelope_blob, message_id, expires_at_ms, uploaded_at_ms)`.
    pub(crate) fn pending_page(
        &self,
        recipient_wire: &str,
        after_uploaded_at_ms: i64,
        after_message_id: &str,
        limit: i64,
    ) -> Result<Vec<(String, String, i64, i64)>> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let now = Self::now_ms();
        let limit = limit.clamp(1, 500);
        let mut stmt = conn.prepare(
            "SELECT envelope_blob, message_id, expires_at_ms, uploaded_at_ms
             FROM pending_messages
             WHERE recipient_wire = ?1 AND state = 'queued' AND envelope_blob IS NOT NULL
               AND expires_at_ms > ?2
               AND (uploaded_at_ms > ?3 OR (uploaded_at_ms = ?3 AND message_id > ?4))
             ORDER BY uploaded_at_ms ASC, message_id ASC
             LIMIT ?5",
        )?;
        let rows = stmt
            .query_map(
                params![
                    recipient_wire,
                    now,
                    after_uploaded_at_ms,
                    after_message_id,
                    limit
                ],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn sweep_expired(&self) -> Result<Vec<(String, String, String)>> {
        let mut all = Vec::new();
        loop {
            let batch = self.sweep_expired_batch(500)?;
            let n = batch.len();
            all.extend(batch);
            if n < 500 {
                break;
            }
        }
        Ok(all)
    }

    /// Expire a bounded batch. The queued+expired predicate is part of the update,
    /// so a resend that refreshed TTL between batches stays queued.
    pub(crate) fn sweep_expired_batch(&self, limit: i64) -> Result<Vec<(String, String, String)>> {
        let mut conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let now = Self::now_ms();
        let limit = limit.clamp(1, 1000);
        let mut expired = Vec::new();
        {
            let mut stmt = conn.prepare(
                "UPDATE pending_messages
                 SET state = 'expired', envelope_blob = NULL, expired_at_ms = ?1
                 WHERE rowid IN (
                     SELECT rowid FROM pending_messages
                     WHERE state = 'queued' AND expires_at_ms <= ?1
                     LIMIT ?2
                 )
                 RETURNING sender_wire, message_id, recipient_wire",
            )?;
            let mut rows = stmt.query(params![now, limit])?;
            while let Some(row) = rows.next()? {
                let sender: String = row.get(0)?;
                let message_id: String = row.get(1)?;
                let recipient: String = row.get(2)?;
                tracing::info!(
                    sender_wire = %sender,
                    message_id = %message_id,
                    state = "expired",
                    "message expired"
                );
                expired.push((sender, message_id, recipient));
            }
        }
        if !expired.is_empty() {
            let tx = conn.transaction()?;
            let mut pruned_senders = std::collections::HashSet::new();
            for (sender, _, _) in &expired {
                if pruned_senders.insert(sender.as_str()) {
                    Self::prune_excess_terminal_rows(&tx, sender, self.max_terminal_rows)?;
                }
            }
            tx.commit()?;
        }
        Ok(expired)
    }

    /// Fold the WAL into the main database file on process shutdown.
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap_or_default();
        if !mode.eq_ignore_ascii_case("wal") {
            return Ok(());
        }
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    /// Test helper: force `expires_at_ms` for integration tests.
    /// Test helper: replace stored envelope JSON for a queued row (corruption replay tests).
    #[doc(hidden)]
    pub fn test_replace_pending_envelope_blob(
        &self,
        sender_wire: &str,
        message_id: &str,
        envelope_blob: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let n = conn.execute(
            "UPDATE pending_messages SET envelope_blob = ?3
             WHERE sender_wire = ?1 AND message_id = ?2 AND state = 'queued'",
            params![sender_wire, message_id, envelope_blob],
        )?;
        if n == 0 {
            return Err(DeliveryError::NotFound("pending row missing".into()));
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn test_force_expires_at(
        &self,
        sender_wire: &str,
        message_id: &str,
        expires_at_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        conn.execute(
            "UPDATE pending_messages SET expires_at_ms = ?3
             WHERE sender_wire = ?1 AND message_id = ?2",
            params![sender_wire, message_id, expires_at_ms],
        )?;
        Ok(())
    }

    pub fn aggregate_health(&self, connected_peers: usize) -> Result<HealthMetrics> {
        let conn = self.conn.lock().map_err(|_| {
            DeliveryError::Internal("store mutex poisoned".into())
        })?;
        let now = Self::now_ms();
        let pending_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pending_messages WHERE state = 'queued'",
            [],
            |r| r.get(0),
        )?;
        let pending_bytes: i64 = conn.query_row(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM pending_messages WHERE state = 'queued'",
            [],
            |r| r.get(0),
        )?;
        let oldest: Option<i64> = conn
            .query_row(
                "SELECT MIN(uploaded_at_ms) FROM pending_messages WHERE state = 'queued'",
                [],
                |r| r.get(0),
            )
            .ok();
        let oldest_pending_age_secs = oldest
            .map(|t| ((now - t).max(0)) / 1000)
            .unwrap_or(0);
        Ok(HealthMetrics {
            connected_peers,
            pending_messages,
            pending_bytes,
            oldest_pending_age_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeliveryConfig;
    use crate::db;
    use crate::envelope::ValidatedEnvelope;
    use crate::policy::PolicyLimits;

    #[test]
    fn upload_and_extend() {
        let cfg = DeliveryConfig::default();
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let validated = ValidatedEnvelope {
            message_id: "m1".into(),
            sender_wire: sender.clone(),
            recipient_wire: "03".repeat(33),
            envelope_blob: "{}".into(),
            size_bytes: 64,
        };
        store.upload(validated.clone(), 300, &policy).unwrap();
        let row = store.extend_ttl(&sender, "m1", 3600, &policy).unwrap();
        assert!(row.expires_at_ms > 0);
    }

    #[test]
    fn ack_deliver_then_read() {
        let cfg = DeliveryConfig::default();
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        let validated = ValidatedEnvelope {
            message_id: "m-read".into(),
            sender_wire: sender.clone(),
            recipient_wire: recipient.clone(),
            envelope_blob: "{}".into(),
            size_bytes: 32,
        };
        let policy = PolicyLimits::from_config(&cfg);
        store.upload(validated, 300, &policy).unwrap();
        let (_s, newly) = store
            .ack_deliver(&recipient, "m-read", &sender)
            .unwrap();
        assert!(newly);
        let (_s, newly_again) = store
            .ack_deliver(&recipient, "m-read", &sender)
            .unwrap();
        assert!(!newly_again);
        store
            .ack_read(&recipient, "m-read", &sender)
            .unwrap();
        let (_s, after_read) = store
            .ack_deliver(&recipient, "m-read", &sender)
            .unwrap();
        assert!(!after_read);
        let rows = store.list_outbox(&sender, true).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "read");
        let (_who, again) = store.ack_read(&recipient, "m-read", &sender).unwrap();
        assert!(!again);
    }

    #[test]
    fn sweep_leaves_delivered_and_refreshed_rows() {
        let cfg = DeliveryConfig::default();
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        let row = |id: &str, blob: &str| ValidatedEnvelope {
            message_id: id.into(),
            sender_wire: sender.clone(),
            recipient_wire: recipient.clone(),
            envelope_blob: blob.into(),
            size_bytes: blob.len() as i64,
        };
        store.upload(row("delivered", "a"), 3600, &policy).unwrap();
        store.upload(row("stale", "b"), 3600, &policy).unwrap();
        store.upload(row("fresh", "c"), 3600, &policy).unwrap();
        store.ack_deliver(&recipient, "delivered", &sender).unwrap();
        store.test_force_expires_at(&sender, "delivered", 1).unwrap();
        store.test_force_expires_at(&sender, "stale", 1).unwrap();
        let expired = store.sweep_expired().unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].1, "stale");
        store.upload(row("stale", "resent"), 3600, &policy).unwrap();
        assert!(store.sweep_expired().unwrap().is_empty());
        let rows = store.list_outbox(&sender, true).unwrap();
        let state_of = |id: &str| {
            rows.iter().find(|r| r.message_id == id).unwrap().state.clone()
        };
        assert_eq!(state_of("delivered"), "delivered");
        assert_eq!(state_of("stale"), "queued");
        assert_eq!(state_of("fresh"), "queued");
    }

    #[test]
    fn pending_pages_cover_every_row_once() {
        let cfg = DeliveryConfig::default();
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        for id in ["m1", "m2", "m3"] {
            store.upload(
                ValidatedEnvelope {
                    message_id: id.into(),
                    sender_wire: sender.clone(),
                    recipient_wire: recipient.clone(),
                    envelope_blob: id.into(),
                    size_bytes: 2,
                },
                3600,
                &policy,
            ).unwrap();
        }
        let mut got = Vec::new();
        let mut after_ms = -1i64;
        let mut after_id = String::new();
        for _ in 0..6 {
            let page = store.pending_page(&recipient, after_ms, &after_id, 2).unwrap();
            if page.is_empty() {
                break;
            }
            after_ms = page.last().unwrap().3;
            after_id = page.last().unwrap().1.clone();
            got.extend(page.into_iter().map(|(_, id, _, _)| id));
        }
        got.sort();
        assert_eq!(got, vec!["m1".to_string(), "m2".into(), "m3".into()]);
    }

    #[test]
    fn quota_warning_threshold_is_ninety_percent() {
        let under = QuotaStatus { allocated_bytes: 100, used_bytes: 89, pending_count: 1 };
        let at = QuotaStatus { allocated_bytes: 100, used_bytes: 90, pending_count: 1 };
        assert!(!under.above_warning_threshold());
        assert!(at.above_warning_threshold());
    }

    #[test]
    fn checkpoint_is_safe_for_memory_and_wal() {
        let mem = MailboxStore::new(db::open_memory().unwrap(), &DeliveryConfig::default());
        mem.checkpoint().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let mut cfg = DeliveryConfig::default();
        cfg.data_dir = dir.path().join("data");
        let state = crate::AppState::new(cfg).unwrap();
        state.store.checkpoint().unwrap();
    }

    #[test]
    fn upload_rejects_when_quota_would_be_exceeded() {
        let mut cfg = DeliveryConfig::default();
        cfg.quota_bytes_per_peer = 64;
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        let row = |id: &str, n: usize| ValidatedEnvelope {
            message_id: id.into(),
            sender_wire: sender.clone(),
            recipient_wire: recipient.clone(),
            envelope_blob: "x".repeat(n),
            size_bytes: n as i64,
        };
        store.upload(row("a", 40), 3600, &policy).unwrap();
        let err = store.upload(row("b", 30), 3600, &policy).unwrap_err();
        assert!(matches!(err, DeliveryError::QuotaExceeded(_)));
    }

    #[test]
    fn sweep_expired_prunes_terminal_row_cap() {
        let mut cfg = DeliveryConfig::default();
        cfg.max_terminal_rows_per_peer = 2;
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        for i in 0..4 {
            let mid = format!("exp{i}");
            store
                .upload(
                    ValidatedEnvelope {
                        message_id: mid,
                        sender_wire: sender.clone(),
                        recipient_wire: recipient.clone(),
                        envelope_blob: "{}".into(),
                        size_bytes: 2,
                    },
                    3600,
                    &policy,
                )
                .unwrap();
            store.test_force_expires_at(&sender, &format!("exp{i}"), 1).unwrap();
        }
        assert_eq!(store.sweep_expired().unwrap().len(), 4);
        let rows = store.list_outbox(&sender, true).unwrap();
        assert_eq!(rows.len(), 2);
        let mut ids: Vec<_> = rows.iter().map(|r| r.message_id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["exp2".to_string(), "exp3".to_string()]);
    }

    #[test]
    fn pending_for_recipient_omits_acked_rows_without_blob() {
        let cfg = DeliveryConfig::default();
        let store = MailboxStore::new(db::open_memory().unwrap(), &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        store
            .upload(
                ValidatedEnvelope {
                    message_id: "gone".into(),
                    sender_wire: sender.clone(),
                    recipient_wire: recipient.clone(),
                    envelope_blob: "payload".into(),
                    size_bytes: 7,
                },
                3600,
                &policy,
            )
            .unwrap();
        store.ack_deliver(&recipient, "gone", &sender).unwrap();
        assert!(store.pending_for_recipient(&recipient).unwrap().is_empty());
    }
}
