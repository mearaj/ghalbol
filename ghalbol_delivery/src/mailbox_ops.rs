//! Mailbox export / import for operator migration between hosts.

use crate::config::DeliveryConfig;
use crate::db::{self, SCHEMA_VERSION};
use crate::error::{DeliveryError, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Cap adversarial manifest.json in import archives.
const MAX_MANIFEST_JSON_BYTES: usize = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxStats {
    pub schema_version: i32,
    pub instance_id: String,
    pub queued_count: i64,
    pub queued_bytes: i64,
    pub delivered_count: i64,
    pub expired_count: i64,
    pub total_rows: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportManifest {
    schema_version: i32,
    exported_at_ms: i64,
    instance_id: String,
    stats: MailboxStats,
}

pub fn mailbox_db_path(config: &DeliveryConfig) -> PathBuf {
    config.data_dir.join("mailbox.db")
}

pub fn collect_stats(conn: &Connection, instance_id: &str) -> Result<MailboxStats> {
    let queued_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_messages WHERE state = 'queued'",
        [],
        |r| r.get(0),
    )?;
    let queued_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM pending_messages WHERE state = 'queued'",
        [],
        |r| r.get(0),
    )?;
    let delivered_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_messages WHERE state = 'delivered'",
        [],
        |r| r.get(0),
    )?;
    let expired_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_messages WHERE state = 'expired'",
        [],
        |r| r.get(0),
    )?;
    let total_rows: i64 = conn.query_row("SELECT COUNT(*) FROM pending_messages", [], |r| r.get(0))?;
    Ok(MailboxStats {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        queued_count,
        queued_bytes,
        delivered_count,
        expired_count,
        total_rows,
    })
}

pub fn mailbox_stats(config: &DeliveryConfig) -> Result<MailboxStats> {
    let path = mailbox_db_path(config);
    if !path.is_file() {
        return Ok(MailboxStats {
            schema_version: SCHEMA_VERSION,
            instance_id: crate::instance::instance_id(),
            queued_count: 0,
            queued_bytes: 0,
            delivered_count: 0,
            expired_count: 0,
            total_rows: 0,
        });
    }
    let conn = Connection::open(&path)?;
    collect_stats(&conn, &crate::instance::instance_id())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_export_manifest(raw: &str) -> Result<ExportManifest> {
    if raw.len() > MAX_MANIFEST_JSON_BYTES {
        return Err(DeliveryError::BadRequest("manifest.json too large".into()));
    }
    serde_json::from_str(raw).map_err(|e| {
        DeliveryError::BadRequest(format!("invalid manifest.json: {e}"))
    })
}

pub fn export_mailbox(config: &DeliveryConfig, out_path: &Path) -> Result<()> {
    let db_path = mailbox_db_path(config);
    if !db_path.is_file() {
        return Err(DeliveryError::NotFound(format!(
            "mailbox db missing at {}",
            db_path.display()
        )));
    }
    let conn = Connection::open(&db_path)?;
    conn.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
    drop(conn);

    let stats = {
        let conn = Connection::open(&db_path)?;
        collect_stats(&conn, &crate::instance::instance_id())?
    };
    let manifest = ExportManifest {
        schema_version: SCHEMA_VERSION,
        exported_at_ms: now_ms(),
        instance_id: stats.instance_id.clone(),
        stats,
    };

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut tar_buf = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut tar_buf);
        archive.append_path_with_name(&db_path, "mailbox.db")?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| {
            DeliveryError::Internal(format!("manifest json: {e}"))
        })?;
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        header.set_cksum();
        archive.append_data(&mut header, "manifest.json", &manifest_bytes[..])?;
        archive.finish()?;
    }

    let file = File::create(out_path)?;
    let mut enc = zstd::stream::write::Encoder::new(file, 3)?;
    enc.write_all(&tar_buf)?;
    enc.finish()?;
    Ok(())
}

pub fn import_mailbox(config: &DeliveryConfig, in_path: &Path, replace: bool) -> Result<MailboxStats> {
    if !in_path.is_file() {
        return Err(DeliveryError::NotFound(format!(
            "import archive missing: {}",
            in_path.display()
        )));
    }
    std::fs::create_dir_all(&config.data_dir)?;
    let tmp_dir = config.data_dir.join(".import_tmp");
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir)?;
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let file = File::open(in_path)?;
    let dec = zstd::stream::read::Decoder::new(file)?;
    let mut archive = tar::Archive::new(dec);
    archive.unpack(&tmp_dir)?;

    let manifest_path = tmp_dir.join("manifest.json");
    let imported_db = tmp_dir.join("mailbox.db");
    if !manifest_path.is_file() || !imported_db.is_file() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(DeliveryError::BadRequest(
            "archive must contain manifest.json and mailbox.db".into(),
        ));
    }

    let manifest_raw = std::fs::read_to_string(&manifest_path)?;
    let manifest = parse_export_manifest(&manifest_raw)?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(DeliveryError::BadRequest(format!(
            "unsupported schema version {} (expected {SCHEMA_VERSION})",
            manifest.schema_version
        )));
    }

    let dest = mailbox_db_path(config);
    if dest.is_file() {
        let mut existing = db::open_and_migrate(&dest)?;
        existing.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        let backup = config.data_dir.join(format!(
            "mailbox.db.bak.{}",
            now_ms()
        ));
        std::fs::copy(&dest, &backup)?;
        existing.execute(
            "ATTACH DATABASE ?1 AS imported",
            rusqlite::params![imported_db.to_string_lossy()],
        )?;
        let imported_version: i32 = existing
            .query_row(
                "SELECT version FROM imported.schema_version LIMIT 1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| {
                DeliveryError::BadRequest(format!("invalid imported database schema: {e}"))
            })?;
        if imported_version != SCHEMA_VERSION {
            existing.execute_batch("DETACH DATABASE imported;")?;
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(DeliveryError::BadRequest(format!(
                "imported database schema {imported_version} does not match {SCHEMA_VERSION}"
            )));
        }

        let conflicts: i64 = existing.query_row(
            "SELECT COUNT(*) FROM pending_messages e
             INNER JOIN imported.pending_messages i
               ON e.sender_wire = i.sender_wire AND e.message_id = i.message_id",
            [],
            |r| r.get(0),
        )?;
        if conflicts > 0 && !replace {
            existing.execute_batch("DETACH DATABASE imported;")?;
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(DeliveryError::BadRequest(format!(
                "{conflicts} conflicting row(s); use --replace to overwrite"
            )));
        }

        let insert = if replace {
            "INSERT OR REPLACE INTO pending_messages
             (sender_wire, message_id, recipient_wire, envelope_blob, size_bytes,
              uploaded_at_ms, expires_at_ms, state, delivered_at_ms, expired_at_ms, read_at_ms)
             SELECT sender_wire, message_id, recipient_wire, envelope_blob, size_bytes,
                    uploaded_at_ms, expires_at_ms, state, delivered_at_ms, expired_at_ms, read_at_ms
             FROM imported.pending_messages"
        } else {
            "INSERT OR IGNORE INTO pending_messages
             (sender_wire, message_id, recipient_wire, envelope_blob, size_bytes,
              uploaded_at_ms, expires_at_ms, state, delivered_at_ms, expired_at_ms, read_at_ms)
             SELECT sender_wire, message_id, recipient_wire, envelope_blob, size_bytes,
                    uploaded_at_ms, expires_at_ms, state, delivered_at_ms, expired_at_ms, read_at_ms
             FROM imported.pending_messages"
        };
        let tx = existing.transaction()?;
        tx.execute(insert, [])?;
        tx.commit()?;
        existing.execute_batch("DETACH DATABASE imported;")?;
    } else {
        let staging = dest.with_extension("db.staging");
        std::fs::copy(&imported_db, &staging)?;
        std::fs::rename(&staging, &dest)?;
    }
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let conn = db::open_and_migrate(&dest)?;
    collect_stats(&conn, &crate::instance::instance_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeliveryConfig;
    use crate::envelope::ValidatedEnvelope;
    use crate::policy::PolicyLimits;
    use crate::store::MailboxStore;
    use tempfile::TempDir;

    fn test_config(dir: &Path) -> DeliveryConfig {
        DeliveryConfig {
            data_dir: dir.to_path_buf(),
            ..DeliveryConfig::default()
        }
    }

    #[test]
    fn export_import_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let conn = db::open_and_migrate(&mailbox_db_path(&cfg)).unwrap();
        let store = MailboxStore::new(conn, &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        store
            .upload(
                ValidatedEnvelope {
                    message_id: "m1".into(),
                    sender_wire: sender.clone(),
                    recipient_wire: recipient,
                    envelope_blob: "{}".into(),
                    size_bytes: 2,
                },
                3600,
                &policy,
            )
            .unwrap();

        let out = dir.path().join("export.tar.zst");
        export_mailbox(&cfg, &out).unwrap();
        assert!(out.is_file());

        let dest_dir = TempDir::new().unwrap();
        let dest_cfg = test_config(dest_dir.path());
        let stats = import_mailbox(&dest_cfg, &out, true).unwrap();
        assert_eq!(stats.queued_count, 1);
        assert_eq!(stats.queued_bytes, 2);
    }

    #[test]
    fn import_conflict_without_replace() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let conn = db::open_and_migrate(&mailbox_db_path(&cfg)).unwrap();
        let store = MailboxStore::new(conn, &cfg);
        let policy = PolicyLimits::from_config(&cfg);
        store
            .upload(
                ValidatedEnvelope {
                    message_id: "m1".into(),
                    sender_wire: "02".repeat(33),
                    recipient_wire: "03".repeat(33),
                    envelope_blob: "{}".into(),
                    size_bytes: 2,
                },
                3600,
                &policy,
            )
            .unwrap();
        let out = dir.path().join("export.tar.zst");
        export_mailbox(&cfg, &out).unwrap();

        let err = import_mailbox(&cfg, &out, false).unwrap_err();
        assert!(matches!(err, DeliveryError::BadRequest(_)));
    }

    #[test]
    fn import_merges_non_conflicting_rows() {
        let source_dir = TempDir::new().unwrap();
        let source_cfg = test_config(source_dir.path());
        let source_conn = db::open_and_migrate(&mailbox_db_path(&source_cfg)).unwrap();
        let source_store = MailboxStore::new(source_conn, &source_cfg);
        let source_policy = PolicyLimits::from_config(&source_cfg);
        source_store
            .upload(
                ValidatedEnvelope {
                    message_id: "source-m1".into(),
                    sender_wire: "02".repeat(33),
                    recipient_wire: "03".repeat(33),
                    envelope_blob: "{}".into(),
                    size_bytes: 2,
                },
                3600,
                &source_policy,
            )
            .unwrap();
        let out = source_dir.path().join("export.tar.zst");
        export_mailbox(&source_cfg, &out).unwrap();

        let target_dir = TempDir::new().unwrap();
        let target_cfg = test_config(target_dir.path());
        let target_conn = db::open_and_migrate(&mailbox_db_path(&target_cfg)).unwrap();
        let target_store = MailboxStore::new(target_conn, &target_cfg);
        let target_policy = PolicyLimits::from_config(&target_cfg);
        target_store
            .upload(
                ValidatedEnvelope {
                    message_id: "target-m1".into(),
                    sender_wire: "04".repeat(33),
                    recipient_wire: "05".repeat(33),
                    envelope_blob: "{}".into(),
                    size_bytes: 2,
                },
                3600,
                &target_policy,
            )
            .unwrap();

        let stats = import_mailbox(&target_cfg, &out, false).unwrap();
        assert_eq!(stats.queued_count, 2);
        assert_eq!(stats.total_rows, 2);
    }

    #[test]
    fn import_rejects_oversized_and_unknown_manifest_fields() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path());
        let archive = dir.path().join("bad.tar.zst");
        let tmp_dir = dir.path().join(".import_tmp");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        std::fs::write(tmp_dir.join("mailbox.db"), b"").unwrap();

        let huge = " ".repeat(MAX_MANIFEST_JSON_BYTES + 1);
        std::fs::write(tmp_dir.join("manifest.json"), huge).unwrap();
        let mut tar_buf = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_buf);
            archive.append_path_with_name(tmp_dir.join("mailbox.db"), "mailbox.db").unwrap();
            archive
                .append_path_with_name(tmp_dir.join("manifest.json"), "manifest.json")
                .unwrap();
            archive.finish().unwrap();
        }
        let file = File::create(&archive).unwrap();
        let mut enc = zstd::stream::write::Encoder::new(file, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();

        let err = import_mailbox(&cfg, &archive, true).unwrap_err();
        assert!(matches!(err, DeliveryError::BadRequest(_)));
        assert!(err.to_string().contains("too large"));

        let nested = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "exported_at_ms": 1,
            "instance_id": "inst",
            "stats": {
                "schema_version": SCHEMA_VERSION,
                "instance_id": "inst",
                "queued_count": 0,
                "queued_bytes": 0,
                "delivered_count": 0,
                "expired_count": 0,
                "total_rows": 0,
            },
            "attacker": { "nested": { "a": [1, 2, 3] } }
        });
        std::fs::write(tmp_dir.join("manifest.json"), nested.to_string()).unwrap();
        tar_buf.clear();
        {
            let mut archive = tar::Builder::new(&mut tar_buf);
            archive.append_path_with_name(tmp_dir.join("mailbox.db"), "mailbox.db").unwrap();
            archive
                .append_path_with_name(tmp_dir.join("manifest.json"), "manifest.json")
                .unwrap();
            archive.finish().unwrap();
        }
        let file = File::create(dir.path().join("unknown.tar.zst")).unwrap();
        let mut enc = zstd::stream::write::Encoder::new(file, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();
        let err = import_mailbox(&cfg, &dir.path().join("unknown.tar.zst"), true).unwrap_err();
        assert!(matches!(err, DeliveryError::BadRequest(_)));
    }

    #[test]
    fn import_merge_keeps_read_at_ms() {
        let source_dir = TempDir::new().unwrap();
        let source_cfg = test_config(source_dir.path());
        let sender = "02".repeat(33);
        let recipient = "03".repeat(33);
        {
            let conn = db::open_and_migrate(&mailbox_db_path(&source_cfg)).unwrap();
            let store = MailboxStore::new(conn, &source_cfg);
            let policy = PolicyLimits::from_config(&source_cfg);
            store
                .upload(
                    ValidatedEnvelope {
                        message_id: "read-me".into(),
                        sender_wire: sender.clone(),
                        recipient_wire: recipient.clone(),
                        envelope_blob: "{}".into(),
                        size_bytes: 2,
                    },
                    3600,
                    &policy,
                )
                .unwrap();
            store.ack_deliver(&recipient, "read-me", &sender).unwrap();
            store.ack_read(&recipient, "read-me", &sender).unwrap();
        }
        let out = source_dir.path().join("export.tar.zst");
        export_mailbox(&source_cfg, &out).unwrap();

        let dest_dir = TempDir::new().unwrap();
        let dest_cfg = test_config(dest_dir.path());
        {
            let conn = db::open_and_migrate(&mailbox_db_path(&dest_cfg)).unwrap();
            let store = MailboxStore::new(conn, &dest_cfg);
            let policy = PolicyLimits::from_config(&dest_cfg);
            store
                .upload(
                    ValidatedEnvelope {
                        message_id: "other".into(),
                        sender_wire: "04".repeat(33),
                        recipient_wire: "05".repeat(33),
                        envelope_blob: "{}".into(),
                        size_bytes: 2,
                    },
                    3600,
                    &policy,
                )
                .unwrap();
        }
        import_mailbox(&dest_cfg, &out, false).unwrap();
        let conn = Connection::open(mailbox_db_path(&dest_cfg)).unwrap();
        let (state, read_at): (String, Option<i64>) = conn
            .query_row(
                "SELECT state, read_at_ms FROM pending_messages WHERE message_id = 'read-me'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "read");
        assert!(read_at.unwrap_or(0) > 0);
    }
}
