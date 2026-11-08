//! Delivery-server read receipts (`inbox.read` / `message.read_to_sender`).
//!
//! Mirrors P2P read-ack policy (DESIGN.md): in-room only for **new** mail; leave backlog
//! for inbound accepted while the room was open. All wire I/O here — Makepad displays transcript only.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use crate::contacts_v1::is_valid_public_key_hex;
use crate::delivery_client::blocking_inbox_read;
use crate::dm_event_handler::active_app_namespace;
use crate::dm_transcript_store::{StoredChatLine, load_merged, patch_inbound_read_ack_sent_global};
use crate::p2p::chat_room_session_at_ms;
use crate::p2p::may_send_read_ack_for_contact_pk;
use crate::p2p::native_log;

#[derive(Clone, Debug)]
struct PendingDeliveryReadAck {
    message_id: String,
    sender_wire: String,
    queued_at_ms: i64,
}

fn pending_mx() -> &'static Mutex<Vec<PendingDeliveryReadAck>> {
    static M: OnceLock<Mutex<Vec<PendingDeliveryReadAck>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(Vec::new()))
}

fn in_flight_mx() -> &'static Mutex<HashSet<String>> {
    static M: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashSet::new()))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn normalize_pk(pk: &str) -> String {
    pk.trim().to_ascii_lowercase()
}

fn read_ack_cutoff_ms(sender_pk: &str) -> i64 {
    if may_send_read_ack_for_contact_pk(sender_pk) {
        let live = chat_room_session_at_ms();
        if live > 0 {
            return live;
        }
        return now_ms();
    }
    let Some(ns) = active_app_namespace() else {
        return now_ms();
    };
    crate::contacts_v1::chat_room_exit_at_ms(&ns, sender_pk)
        .ok()
        .flatten()
        .filter(|t| *t > 0)
        .unwrap_or_else(now_ms)
}

fn inbound_received_at_for_row(row: &StoredChatLine) -> Option<i64> {
    row.received_at_ms.or(row.created_at_ms)
}

fn lookup_keys_for_sender(ns: &str, sender_pk: &str) -> Vec<String> {
    crate::dm_event_handler::inbound_transcript_lookup_keys(ns, sender_pk, sender_pk, sender_pk)
}

/// Cap pending inbox.read retries so a huge catch-up seed cannot unbounded-grow RAM.
const MAX_PENDING_DELIVERY_READ_ACKS: usize = 4_096;

fn enqueue_pending(message_id: &str, sender_wire: &str) {
    let mid = message_id.trim();
    let sender = normalize_pk(sender_wire);
    if mid.is_empty() || !is_valid_public_key_hex(&sender) {
        return;
    }
    let Ok(mut q) = pending_mx().lock() else {
        return;
    };
    if q.iter()
        .any(|p| p.message_id == mid && p.sender_wire == sender)
    {
        return;
    }
    while q.len() >= MAX_PENDING_DELIVERY_READ_ACKS {
        q.remove(0);
    }
    q.push(PendingDeliveryReadAck {
        message_id: mid.to_string(),
        sender_wire: sender,
        queued_at_ms: now_ms(),
    });
}

fn dequeue_pending(message_id: &str, sender_wire: &str) {
    let mid = message_id.trim();
    let sender = normalize_pk(sender_wire);
    let Ok(mut q) = pending_mx().lock() else {
        return;
    };
    q.retain(|p| !(p.message_id == mid && p.sender_wire == sender));
}

fn claim_in_flight(message_id: &str) -> bool {
    let Ok(mut g) = in_flight_mx().lock() else {
        return false;
    };
    g.insert(message_id.trim().to_string())
}

fn release_in_flight(message_id: &str) {
    if let Ok(mut g) = in_flight_mx().lock() {
        g.remove(message_id.trim());
    }
}

/// After the delivery worker exits, clear stale claims so the next session is not blocked.
pub(crate) fn clear_delivery_read_ack_in_flight() {
    if let Ok(mut g) = in_flight_mx().lock() {
        g.clear();
    }
}

fn bump_pending_retry_timestamp(message_id: &str, sender_wire: &str) {
    let mid = message_id.trim();
    let sender = normalize_pk(sender_wire);
    if let Ok(mut q) = pending_mx().lock() {
        for p in q.iter_mut() {
            if p.message_id == mid && p.sender_wire == sender {
                p.queued_at_ms = now_ms();
            }
        }
    }
}

struct ReadAckInFlightGuard {
    message_id: String,
}

impl ReadAckInFlightGuard {
    fn new(message_id: &str) -> Self {
        Self {
            message_id: message_id.trim().to_string(),
        }
    }
}

impl Drop for ReadAckInFlightGuard {
    fn drop(&mut self) {
        release_in_flight(&self.message_id);
    }
}

fn patch_read_ack_sent(message_id: &str) -> bool {
    let Some(ns) = active_app_namespace() else {
        return false;
    };
    patch_inbound_read_ack_sent_global(&ns, message_id).is_ok()
}

fn send_inbox_read(ws_url: &str, message_id: &str, sender_pk: &str) -> bool {
    if !claim_in_flight(message_id) {
        return false;
    }
    let _guard = ReadAckInFlightGuard::new(message_id);
    let result = blocking_inbox_read(ws_url, message_id, sender_pk);
    match result {
        Ok(()) => {
            if !patch_read_ack_sent(message_id) {
                native_log::warn(
                    "delivery_read",
                    format!(
                        "inbox.read ok but transcript patch failed mid={message_id} sender={sender_pk}"
                    ),
                );
                bump_pending_retry_timestamp(message_id, sender_pk);
                return false;
            }
            dequeue_pending(message_id, sender_pk);
            native_log::info(
                "delivery_read",
                format!("inbox.read sent mid={message_id} sender={sender_pk}"),
            );
            true
        }
        Err(e) => {
            native_log::warn(
                "delivery_read",
                format!("inbox.read failed mid={message_id} sender={sender_pk}: {e}"),
            );
            bump_pending_retry_timestamp(message_id, sender_pk);
            false
        }
    }
}

/// Seed + drain read acks when hub opens room or read gate turns on (delivery mode).
pub fn queue_delivery_read_catchup(sender_pk: &str) {
    if !crate::delivery_runtime::delivery_mode_enabled() {
        return;
    }
    let pk = normalize_pk(sender_pk);
    if !is_valid_public_key_hex(&pk) {
        return;
    }
    seed_frozen_leave_backlogs(Some(&pk));
    seed_read_acks_for_sender(&pk);
    drain_pending_read_acks(true);
}

/// Leave / switch room: flush read backlog for the contact we left (frozen cutoff).
pub fn dispatch_delivery_leave_drain(left_pk: &str) {
    if !crate::delivery_runtime::delivery_mode_enabled() {
        return;
    }
    let pk = normalize_pk(left_pk);
    if !is_valid_public_key_hex(&pk) {
        return;
    }
    seed_read_acks_for_sender(&pk);
    drain_pending_read_acks(true);
}

/// After inbound delivery ack — send read receipt on the worker session when read gate is open.
pub async fn try_read_ack_after_inbound_async(
    session: &mut crate::delivery_client::DeliverySession,
    message_id: &str,
    sender_wire: &str,
) {
    if !crate::delivery_runtime::delivery_mode_enabled() {
        return;
    }
    let sender = normalize_pk(sender_wire);
    if !is_valid_public_key_hex(&sender) {
        return;
    }
    if !may_send_read_ack_for_contact_pk(&sender) {
        return;
    }
    let Some(ns) = active_app_namespace() else {
        return;
    };
    if patch_already_sent(&ns, &sender, message_id) {
        return;
    }
    // Queue first so ~1s upkeep retries if this attempt fails or the process dies mid-flight.
    enqueue_pending(message_id, &sender);
    if !claim_in_flight(message_id) {
        return;
    }
    let _guard = ReadAckInFlightGuard::new(message_id);
    let result = session.inbox_read(message_id, &sender).await;
    match result {
        Ok(()) => {
            if !patch_read_ack_sent(message_id) {
                native_log::warn(
                    "delivery_read",
                    format!(
                        "inbox.read ok but transcript patch failed mid={message_id} sender={sender}"
                    ),
                );
                bump_pending_retry_timestamp(message_id, &sender);
            } else {
                dequeue_pending(message_id, &sender);
                native_log::info(
                    "delivery_read",
                    format!("inbox.read sent mid={message_id} sender={sender}"),
                );
            }
        }
        Err(e) => {
            native_log::warn(
                "delivery_read",
                format!("inbox.read failed mid={message_id} sender={sender}: {e}"),
            );
            bump_pending_retry_timestamp(message_id, &sender);
        }
    }
}

/// Contacts left without `dispatch_delivery_leave_drain` (e.g. foreground synced before
/// `SetForegroundPeer`) still need leave backlog seeded from `chat_room_exit_at_ms`.
const MAX_FROZEN_LEAVE_SEED_PER_TICK: usize = 2;

fn seed_frozen_leave_backlogs(except_sender: Option<&str>) {
    let Some(ns) = active_app_namespace() else {
        return;
    };
    let Ok(contacts) = crate::contacts_v1::list_contacts(&ns) else {
        return;
    };
    let except = except_sender.map(normalize_pk);
    let mut seeded = 0usize;
    for c in contacts {
        if seeded >= MAX_FROZEN_LEAVE_SEED_PER_TICK {
            break;
        }
        let pk = normalize_pk(&c.public_key_hex);
        if !is_valid_public_key_hex(&pk) {
            continue;
        }
        if except.as_ref() == Some(&pk) {
            continue;
        }
        if may_send_read_ack_for_contact_pk(&pk) {
            continue;
        }
        if c.chat_room_exit_at_ms.filter(|t| *t > 0).is_none() {
            continue;
        }
        seed_read_acks_for_sender(&pk);
        seeded += 1;
    }
}

/// ~1s upkeep hook from the delivery worker receive loop.
pub fn delivery_read_ack_upkeep() {
    if !crate::delivery_runtime::delivery_mode_enabled() {
        return;
    }
    seed_frozen_leave_backlogs(None);
    drain_pending_read_acks(false);
}

fn seed_read_acks_for_sender(sender_pk: &str) {
    let Some(ns) = active_app_namespace() else {
        return;
    };
    let cutoff = read_ack_cutoff_ms(sender_pk);
    let keys = lookup_keys_for_sender(&ns, sender_pk);
    let Ok(rows) = load_merged(&ns, &keys, None) else {
        return;
    };
    let mut seeded = 0usize;
    for row in rows {
        if row.outgoing || row.read_ack_sent {
            continue;
        }
        let Some(received_at) = inbound_received_at_for_row(&row) else {
            continue;
        };
        if received_at > cutoff {
            continue;
        }
        let Some(mid) = row
            .message_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        enqueue_pending(mid, sender_pk);
        seeded += 1;
    }
    if seeded > 0 {
        native_log::info(
            "delivery_read",
            format!("seeded {seeded} pending inbox.read for {sender_pk} cutoff_ms={cutoff}"),
        );
    }
}

enum ReadAckDrainAction {
    /// `queued_at_ms` inside ~1s retry window.
    SkipRateLimit,
    /// No app namespace yet (transient).
    SkipWait,
    /// Wire `inbox.read` now.
    Send,
    /// Dequeued — already sent or policy will never send.
    Drop,
}

fn read_ack_drain_action(item: &PendingDeliveryReadAck, force: bool, now: i64) -> ReadAckDrainAction {
    const RETRY_MS: i64 = 1000;
    if !force && now.saturating_sub(item.queued_at_ms) < RETRY_MS {
        return ReadAckDrainAction::SkipRateLimit;
    }
    let Some(ns) = active_app_namespace() else {
        return ReadAckDrainAction::SkipWait;
    };
    if patch_already_sent(&ns, &item.sender_wire, &item.message_id) {
        dequeue_pending(&item.message_id, &item.sender_wire);
        return ReadAckDrainAction::Drop;
    }
    if may_send_read_ack_for_contact_pk(&item.sender_wire) {
        return ReadAckDrainAction::Send;
    }
    let cutoff = read_ack_cutoff_ms(&item.sender_wire);
    if row_eligible_for_leave_read(&item.sender_wire, &item.message_id, cutoff) {
        return ReadAckDrainAction::Send;
    }
    dequeue_pending(&item.message_id, &item.sender_wire);
    ReadAckDrainAction::Drop
}

fn drain_pending_read_acks(force: bool) {
    let Some(url) = crate::delivery_runtime::delivery_url() else {
        return;
    };
    let ws_url = crate::delivery_client::ws_url_from_base(&url);
    let pending: Vec<PendingDeliveryReadAck> = pending_mx()
        .lock()
        .ok()
        .map(|q| q.clone())
        .unwrap_or_default();
    let now = now_ms();
    for item in pending {
        match read_ack_drain_action(&item, force, now) {
            ReadAckDrainAction::SkipRateLimit | ReadAckDrainAction::SkipWait | ReadAckDrainAction::Drop => {}
            ReadAckDrainAction::Send => {
                let _ = send_inbox_read(&ws_url, &item.message_id, &item.sender_wire);
            }
        }
    }
}

fn patch_already_sent(ns: &str, sender_pk: &str, message_id: &str) -> bool {
    let keys = lookup_keys_for_sender(ns, sender_pk);
    let Ok(rows) = load_merged(ns, &keys, None) else {
        return false;
    };
    rows.iter().any(|r| {
        !r.outgoing
            && r.read_ack_sent
            && r.message_id.as_deref().map(str::trim) == Some(message_id.trim())
    })
}

fn row_eligible_for_leave_read(sender_pk: &str, message_id: &str, cutoff_ms: i64) -> bool {
    let Some(ns) = active_app_namespace() else {
        return false;
    };
    let keys = lookup_keys_for_sender(&ns, sender_pk);
    let Ok(rows) = load_merged(&ns, &keys, None) else {
        return false;
    };
    rows.iter().any(|r| {
        if r.outgoing || r.read_ack_sent {
            return false;
        }
        if r.message_id.as_deref().map(str::trim) != Some(message_id.trim()) {
            return false;
        }
        inbound_received_at_for_row(r).is_some_and(|t| t <= cutoff_ms)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Global pending/in-flight maps are process-wide — serialize tests that mutate them.
    fn pending_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn read_ack_in_flight_guard_releases_on_drop() {
        let _serial = pending_test_lock();
        let mid = "read-ack-guard-drop-mid";
        if let Ok(mut g) = in_flight_mx().lock() {
            g.remove(mid);
        }
        assert!(claim_in_flight(mid));
        {
            let _guard = ReadAckInFlightGuard::new(mid);
            assert!(!claim_in_flight(mid));
        }
        assert!(claim_in_flight(mid));
        release_in_flight(mid);
    }

    #[test]
    fn normalize_pk_lowercases() {
        assert_eq!(normalize_pk("  ABCD "), "abcd");
    }

    #[test]
    fn enqueue_pending_dedupes_same_mid_and_sender() {
        let _serial = pending_test_lock();
        let mid = "test-read-ack-dedupe-mid";
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk);
        assert!(is_valid_public_key_hex(&sender));
        {
            let Ok(mut q) = pending_mx().lock() else {
                return;
            };
            q.retain(|p| p.message_id != mid);
        }
        enqueue_pending(mid, &sender);
        enqueue_pending(mid, &sender);
        let count = pending_mx()
            .lock()
            .map(|q| {
                q.iter()
                    .filter(|p| p.message_id == mid && p.sender_wire == normalize_pk(&sender))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(count, 1);
        dequeue_pending(mid, &sender);
    }

    #[test]
    fn seed_read_acks_skips_inbound_after_leave_cutoff() {
        use crate::app_paths::configure_android_data_directory;
        use crate::contacts_v1::{SavedContact, upsert_contact};
        use crate::dm_event_handler::set_p2p_handler_context;
        use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
        use tempfile::TempDir;

        let _guard = crate::app_paths::test_storage_isolation_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let td = TempDir::new().unwrap();
        configure_android_data_directory(td.path().to_str().unwrap());
        let ns = "test.read.seed.cutoff";
        let cfg = StorageConfig::new(ns).with_override_data_dir(td.path());
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        set_p2p_handler_context(ns);
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk_bytes);
        let exit_ms = 5_000i64;
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: sender.clone(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: Some(exit_ms),
            },
        )
        .unwrap();
        for (mid, at) in [("before-leave", 4_000i64), ("after-leave", 6_000i64)] {
            let _ = crate::dm_transcript_store::append_if_new(
                ns,
                &sender,
                StoredChatLine {
                    local_id: mid.to_string(),
                    text: mid.to_string(),
                    outgoing: false,
                    from: Some(sender.clone()),
                    message_id: Some(mid.to_string()),
                    delivery: "pending".to_string(),
                    created_at_ms: Some(at),
                    received_at_ms: Some(at),
                    read_ack_sent: false,
                    msg_kind: "text".into(),
                    duration_ms: None,
                    audio_path: None,
                    file_name: None,
                    mime_type: None,
                    size_bytes: None,
                    local_path: None,
                },
            );
        }
        {
            let Ok(mut q) = pending_mx().lock() else {
                return;
            };
            q.retain(|p| p.sender_wire != normalize_pk(&sender));
        }
        seed_read_acks_for_sender(&sender);
        let mids: Vec<String> = pending_mx()
            .lock()
            .map(|q| {
                q.iter()
                    .filter(|p| p.sender_wire == normalize_pk(&sender))
                    .map(|p| p.message_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(mids, vec!["before-leave".to_string()]);
        for mid in &mids {
            dequeue_pending(mid, &sender);
        }
        crate::dm_event_handler::clear_p2p_handler_context();
    }

    #[test]
    fn bump_pending_retry_timestamp_refreshes_entry() {
        let _serial = pending_test_lock();
        let mid = "bump-retry-mid";
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk);
        {
            let Ok(mut q) = pending_mx().lock() else {
                return;
            };
            q.retain(|p| p.message_id != mid);
        }
        enqueue_pending(mid, &sender);
        let before = pending_mx()
            .lock()
            .ok()
            .and_then(|q| {
                q.iter()
                    .find(|p| p.message_id == mid)
                    .map(|p| p.queued_at_ms)
            })
            .unwrap_or(0);
        bump_pending_retry_timestamp(mid, &sender);
        let after = pending_mx()
            .lock()
            .ok()
            .and_then(|q| {
                q.iter()
                    .find(|p| p.message_id == mid)
                    .map(|p| p.queued_at_ms)
            })
            .unwrap_or(0);
        assert!(after >= before);
        dequeue_pending(mid, &sender);
    }

    #[test]
    fn drain_drops_pending_after_leave_cutoff() {
        use crate::app_paths::configure_android_data_directory;
        use crate::contacts_v1::{SavedContact, upsert_contact};
        use crate::dm_event_handler::set_p2p_handler_context;
        use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
        use tempfile::TempDir;

        let _guard = crate::app_paths::test_storage_isolation_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = pending_test_lock();
        let td = TempDir::new().unwrap();
        configure_android_data_directory(td.path().to_str().unwrap());
        let ns = "test.read.drain.drop";
        let cfg = StorageConfig::new(ns).with_override_data_dir(td.path());
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        set_p2p_handler_context(ns);
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk_bytes);
        let exit_ms = 5_000i64;
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: sender.clone(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: Some(exit_ms),
            },
        )
        .unwrap();
        let mid = "after-leave-drain-drop";
        let _ = crate::dm_transcript_store::append_if_new(
            ns,
            &sender,
            StoredChatLine {
                local_id: mid.to_string(),
                text: mid.to_string(),
                outgoing: false,
                from: Some(sender.clone()),
                message_id: Some(mid.to_string()),
                delivery: "pending".to_string(),
                created_at_ms: Some(6_000),
                received_at_ms: Some(6_000),
                read_ack_sent: false,
                msg_kind: "text".into(),
                duration_ms: None,
                audio_path: None,
                file_name: None,
                mime_type: None,
                size_bytes: None,
                local_path: None,
            },
        );
        enqueue_pending(mid, &sender);
        let item = pending_mx()
            .lock()
            .ok()
            .and_then(|q| {
                q.iter()
                    .find(|p| p.message_id == mid)
                    .cloned()
            })
            .expect("pending row");
        assert!(matches!(
            read_ack_drain_action(&item, true, now_ms()),
            ReadAckDrainAction::Drop
        ));
        let remaining = pending_mx()
            .lock()
            .map(|q| q.iter().any(|p| p.message_id == mid))
            .unwrap_or(true);
        assert!(!remaining);
        crate::dm_event_handler::clear_p2p_handler_context();
    }

    #[test]
    fn clear_in_flight_empties_claims() {
        let _serial = pending_test_lock();
        let mid = "clear-in-flight-mid";
        assert!(claim_in_flight(mid));
        clear_delivery_read_ack_in_flight();
        assert!(claim_in_flight(mid));
        release_in_flight(mid);
    }

    #[test]
    fn enqueue_pending_evicts_oldest_when_full() {
        let _serial = pending_test_lock();
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk);
        {
            let Ok(mut q) = pending_mx().lock() else {
                return;
            };
            q.clear();
            for i in 0..MAX_PENDING_DELIVERY_READ_ACKS {
                q.push(PendingDeliveryReadAck {
                    message_id: format!("fill-{i}"),
                    sender_wire: sender.clone(),
                    queued_at_ms: i as i64,
                });
            }
        }
        enqueue_pending("newest-mid", &sender);
        let Ok(q) = pending_mx().lock() else {
            return;
        };
        assert_eq!(q.len(), MAX_PENDING_DELIVERY_READ_ACKS);
        assert_eq!(q[0].message_id, "fill-1");
        assert!(q.iter().any(|p| p.message_id == "newest-mid"));
        // Leave global queue clean for other tests in this process.
        drop(q);
        let Ok(mut q) = pending_mx().lock() else {
            return;
        };
        q.retain(|p| p.sender_wire != normalize_pk(&sender));
    }

    #[test]
    fn read_ack_drain_rate_limits_fresh_pending_without_force() {
        let _serial = pending_test_lock();
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk);
        let item = PendingDeliveryReadAck {
            message_id: "rate-limit-mid".into(),
            sender_wire: normalize_pk(&sender),
            queued_at_ms: now_ms(),
        };
        assert!(matches!(
            read_ack_drain_action(&item, false, item.queued_at_ms),
            ReadAckDrainAction::SkipRateLimit
        ));
        assert!(matches!(
            read_ack_drain_action(&item, false, item.queued_at_ms + 1_500),
            ReadAckDrainAction::SkipWait | ReadAckDrainAction::Send | ReadAckDrainAction::Drop
        ));
    }

    #[test]
    fn patch_already_sent_blocks_duplicate_inbound_read_enqueue() {
        use crate::app_paths::configure_android_data_directory;
        use crate::contacts_v1::{SavedContact, upsert_contact};
        use crate::dm_event_handler::set_p2p_handler_context;
        use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
        use tempfile::TempDir;

        let _guard = crate::app_paths::test_storage_isolation_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = pending_test_lock();
        let td = TempDir::new().unwrap();
        configure_android_data_directory(td.path().to_str().unwrap());
        let ns = "test.read.already.sent.guard";
        let cfg = StorageConfig::new(ns).with_override_data_dir(td.path());
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        set_p2p_handler_context(ns);
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk_bytes);
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: sender.clone(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let mid = "already-read-guard-mid";
        let _ = crate::dm_transcript_store::append_if_new(
            ns,
            &sender,
            StoredChatLine {
                local_id: mid.to_string(),
                text: mid.to_string(),
                outgoing: false,
                from: Some(sender.clone()),
                message_id: Some(mid.to_string()),
                delivery: "read".to_string(),
                created_at_ms: Some(1_000),
                received_at_ms: Some(1_000),
                read_ack_sent: true,
                msg_kind: "text".into(),
                duration_ms: None,
                audio_path: None,
                file_name: None,
                mime_type: None,
                size_bytes: None,
                local_path: None,
            },
        );
        assert!(patch_already_sent(ns, &sender, mid));
        crate::p2p::sync_foreground_peer_now(Some(sender.clone()));
        crate::p2p::set_app_ui_visible(true);
        crate::p2p::set_app_ack_read_enabled(true);
        assert!(may_send_read_ack_for_contact_pk(&sender));
        assert!(patch_already_sent(ns, &sender, mid));
        crate::p2p::sync_foreground_peer_now(None);
        crate::p2p::set_app_ack_read_enabled(false);
        crate::dm_event_handler::clear_p2p_handler_context();
    }

    #[test]
    fn seed_frozen_leave_backlogs_seeds_non_foreground_contact() {
        use crate::app_paths::configure_android_data_directory;
        use crate::contacts_v1::{SavedContact, upsert_contact};
        use crate::dm_event_handler::set_p2p_handler_context;
        use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
        use tempfile::TempDir;

        let _guard = crate::app_paths::test_storage_isolation_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = pending_test_lock();
        let td = TempDir::new().unwrap();
        configure_android_data_directory(td.path().to_str().unwrap());
        let ns = "test.read.frozen.leave";
        let cfg = StorageConfig::new(ns).with_override_data_dir(td.path());
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        set_p2p_handler_context(ns);
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let left = hex::encode(pk_bytes);
        let secret_b = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_b = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret_b,
        )
        .expect("pk");
        let open = hex::encode(pk_b);
        let exit_ms = 5_000i64;
        for (pk, exit) in [(left.as_str(), Some(exit_ms)), (open.as_str(), None)] {
            upsert_contact(
                ns,
                SavedContact {
                    public_key_hex: pk.to_string(),
                    display_alias: None,
                    availability_status: None,
                    last_message_preview: None,
                    last_message_at_ms: None,
                    unread_count: 0,
                    created_at_ms: None,
                    updated_at_ms: None,
                    is_known: true,
                    is_blocked: false,
                    chat_room_exit_at_ms: exit,
                },
            )
            .unwrap();
        }
        let mid = "frozen-leave-mid";
        let _ = crate::dm_transcript_store::append_if_new(
            ns,
            &left,
            StoredChatLine {
                local_id: mid.to_string(),
                text: mid.to_string(),
                outgoing: false,
                from: Some(left.clone()),
                message_id: Some(mid.to_string()),
                delivery: "pending".to_string(),
                created_at_ms: Some(4_000),
                received_at_ms: Some(4_000),
                read_ack_sent: false,
                msg_kind: "text".into(),
                duration_ms: None,
                audio_path: None,
                file_name: None,
                mime_type: None,
                size_bytes: None,
                local_path: None,
            },
        );
        {
            let Ok(mut q) = pending_mx().lock() else {
                return;
            };
            q.retain(|p| p.sender_wire != normalize_pk(&left));
        }
        crate::p2p::sync_foreground_peer_now(Some(open.clone()));
        crate::p2p::set_app_ack_read_enabled(true);
        seed_frozen_leave_backlogs(Some(&open));
        let seeded = pending_mx()
            .lock()
            .map(|q| {
                q.iter()
                    .any(|p| p.message_id == mid && p.sender_wire == normalize_pk(&left))
            })
            .unwrap_or(false);
        assert!(seeded);
        dequeue_pending(mid, &left);
        crate::p2p::sync_foreground_peer_now(None);
        crate::p2p::set_app_ack_read_enabled(false);
        crate::dm_event_handler::clear_p2p_handler_context();
    }

    #[test]
    fn drain_dequeues_pending_when_transcript_already_read_ack_sent() {
        use crate::app_paths::configure_android_data_directory;
        use crate::contacts_v1::{SavedContact, upsert_contact};
        use crate::dm_event_handler::set_p2p_handler_context;
        use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
        use tempfile::TempDir;

        let _guard = crate::app_paths::test_storage_isolation_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _serial = pending_test_lock();
        let td = TempDir::new().unwrap();
        configure_android_data_directory(td.path().to_str().unwrap());
        let ns = "test.read.drain.already";
        let cfg = StorageConfig::new(ns).with_override_data_dir(td.path());
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        set_p2p_handler_context(ns);
        let secret = crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
            .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let sender = hex::encode(pk_bytes);
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: sender.clone(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let mid = "already-read-acked";
        let _ = crate::dm_transcript_store::append_if_new(
            ns,
            &sender,
            StoredChatLine {
                local_id: mid.to_string(),
                text: mid.to_string(),
                outgoing: false,
                from: Some(sender.clone()),
                message_id: Some(mid.to_string()),
                delivery: "read".to_string(),
                created_at_ms: Some(1_000),
                received_at_ms: Some(1_000),
                read_ack_sent: true,
                msg_kind: "text".into(),
                duration_ms: None,
                audio_path: None,
                file_name: None,
                mime_type: None,
                size_bytes: None,
                local_path: None,
            },
        );
        enqueue_pending(mid, &sender);
        let item = pending_mx()
            .lock()
            .ok()
            .and_then(|q| q.iter().find(|p| p.message_id == mid).cloned())
            .expect("pending");
        assert!(matches!(
            read_ack_drain_action(&item, true, now_ms()),
            ReadAckDrainAction::Drop
        ));
        assert!(
            !pending_mx()
                .lock()
                .map(|q| q.iter().any(|p| p.message_id == mid))
                .unwrap_or(true)
        );
        crate::dm_event_handler::clear_p2p_handler_context();
    }
}
