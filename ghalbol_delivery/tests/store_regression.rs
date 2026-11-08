//! Adversarial / failure-mode regression tests for mailbox store acks, TTL, and upload races.

use ghalbol_delivery::{
    AppState, DeliveryConfig, DeliveryError, MailboxStore, PolicyLimits, ValidatedEnvelope,
};
use std::sync::Arc;

fn test_store() -> (Arc<MailboxStore>, PolicyLimits) {
    let cfg = DeliveryConfig::default();
    let state = AppState::new_in_memory(cfg).unwrap();
    (Arc::clone(&state.store), state.policy.clone())
}

fn env(sender: &str, recipient: &str, message_id: &str, blob: &str) -> ValidatedEnvelope {
    ValidatedEnvelope {
        message_id: message_id.into(),
        sender_wire: sender.into(),
        recipient_wire: recipient.into(),
        envelope_blob: blob.into(),
        size_bytes: blob.len() as i64,
    }
}

#[test]
fn ack_read_idempotent_and_rejects_queued_state() {
    let (store, policy) = test_store();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    store
        .upload(env(&sender, &recipient, "mid-read", "x"), 3600, &policy)
        .unwrap();

    let err = store.ack_read(&recipient, "mid-read", &sender).unwrap_err();
    assert!(matches!(err, DeliveryError::BadRequest(_)));

    store.ack_deliver(&recipient, "mid-read", &sender).unwrap();
    let (who, newly) = store.ack_read(&recipient, "mid-read", &sender).unwrap();
    assert_eq!(who, sender);
    assert!(newly);
    let (who_again, again) = store.ack_read(&recipient, "mid-read", &sender).unwrap();
    assert_eq!(who_again, sender);
    assert!(!again);

    let rows = store.list_outbox(&sender, true).unwrap();
    assert_eq!(rows[0].state, "read");
}

#[test]
fn extend_rejected_after_deliver_read_and_expired() {
    let (store, policy) = test_store();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    store
        .upload(env(&sender, &recipient, "m-ext", "{}"), 3600, &policy)
        .unwrap();
    store.ack_deliver(&recipient, "m-ext", &sender).unwrap();

    let delivered_err = store.extend_ttl(&sender, "m-ext", 7200, &policy).unwrap_err();
    assert!(matches!(delivered_err, DeliveryError::BadRequest(_)));

    store.ack_read(&recipient, "m-ext", &sender).unwrap();
    let read_err = store.extend_ttl(&sender, "m-ext", 7200, &policy).unwrap_err();
    assert!(matches!(read_err, DeliveryError::BadRequest(_)));

    store
        .upload(env(&sender, &recipient, "m-exp", "{}"), 3600, &policy)
        .unwrap();
    store.test_force_expires_at(&sender, "m-exp", 1).unwrap();
    store.sweep_expired().unwrap();
    let expired_err = store.extend_ttl(&sender, "m-exp", 7200, &policy).unwrap_err();
    assert!(matches!(expired_err, DeliveryError::Expired(_)));
}

#[test]
fn sequential_same_message_id_upload_ack_race() {
    let (store, policy) = test_store();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    let mid = "race-mid";

    store
        .upload(env(&sender, &recipient, mid, "v1"), 3600, &policy)
        .unwrap();
    let (_, dup_upload) = store
        .upload(env(&sender, &recipient, mid, "v2"), 3600, &policy)
        .unwrap();
    assert!(dup_upload);

    let (_, d1) = store.ack_deliver(&recipient, mid, &sender).unwrap();
    let (_, d2) = store.ack_deliver(&recipient, mid, &sender).unwrap();
    assert!(d1);
    assert!(!d2);

    store
        .upload(env(&sender, &recipient, mid, "v3-resend"), 3600, &policy)
        .unwrap();
    let pending = store.pending_for_recipient(&recipient).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, "v3-resend");
    let rows = store.list_outbox(&sender, true).unwrap();
    assert_eq!(rows[0].state, "queued");
}

#[test]
fn resend_after_read_clears_read_metadata_and_respects_quota() {
    let (store, policy) = test_store();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    let mid = "read-resend";
    store
        .upload(env(&sender, &recipient, mid, "aaaa"), 3600, &policy)
        .unwrap();
    store.ack_deliver(&recipient, mid, &sender).unwrap();
    store.ack_read(&recipient, mid, &sender).unwrap();

    store
        .upload(env(&sender, &recipient, mid, "bb"), 3600, &policy)
        .unwrap();
    let quota = store.quota_status(&sender).unwrap();
    assert_eq!(quota.used_bytes, 2);
    assert_eq!(quota.pending_count, 1);
    let rows = store.list_outbox(&sender, true).unwrap();
    assert_eq!(rows[0].state, "queued");
    let pending = store.pending_for_recipient(&recipient).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, "bb");
}

#[test]
fn quota_replace_accounts_for_prior_queued_bytes() {
    let mut cfg = DeliveryConfig::default();
    cfg.quota_bytes_per_peer = 15;
    let state = AppState::new_in_memory(cfg).unwrap();
    let store = Arc::clone(&state.store);
    let policy = state.policy.clone();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    store
        .upload(env(&sender, &recipient, "a", "1234567890"), 3600, &policy)
        .unwrap();
    let err = store
        .upload(env(&sender, &recipient, "b", "12345678901"), 3600, &policy)
        .unwrap_err();
    assert!(matches!(err, DeliveryError::QuotaExceeded(_)));
    let (quota, _) = store
        .upload(env(&sender, &recipient, "a", "1234"), 3600, &policy)
        .unwrap();
    assert_eq!(quota.used_bytes, 4);
}

#[test]
fn ack_wrong_sender_wire_returns_not_found() {
    let (store, policy) = test_store();
    let sender = "02".repeat(33);
    let impostor = "04".repeat(33);
    let recipient = "03".repeat(33);
    store
        .upload(env(&sender, &recipient, "m-forged", "p"), 3600, &policy)
        .unwrap();

    let deliver_err = store
        .ack_deliver(&recipient, "m-forged", &impostor)
        .unwrap_err();
    assert!(matches!(deliver_err, DeliveryError::NotFound(_)));

    store.ack_deliver(&recipient, "m-forged", &sender).unwrap();
    let read_err = store
        .ack_read(&recipient, "m-forged", &impostor)
        .unwrap_err();
    assert!(matches!(read_err, DeliveryError::NotFound(_)));
}

#[test]
fn pending_message_count_cap_rejects_storm() {
    let mut cfg = DeliveryConfig::default();
    cfg.max_pending_messages_per_peer = 3;
    cfg.quota_bytes_per_peer = 10_000_000;
    let state = AppState::new_in_memory(cfg).unwrap();
    let store = Arc::clone(&state.store);
    let policy = state.policy.clone();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    for i in 0..3 {
        store
            .upload(
                env(&sender, &recipient, &format!("m{i}"), "x"),
                3600,
                &policy,
            )
            .unwrap();
    }
    let err = store
        .upload(env(&sender, &recipient, "overflow", "y"), 3600, &policy)
        .unwrap_err();
    assert!(matches!(err, DeliveryError::QuotaExceeded(_)));
    store
        .upload(env(&sender, &recipient, "m0", "replace"), 3600, &policy)
        .unwrap();
}

#[test]
fn terminal_row_cap_prunes_oldest_metadata() {
    let mut cfg = DeliveryConfig::default();
    cfg.max_terminal_rows_per_peer = 2;
    cfg.max_pending_messages_per_peer = 100;
    let state = AppState::new_in_memory(cfg).unwrap();
    let store = Arc::clone(&state.store);
    let policy = state.policy.clone();
    let sender = "02".repeat(33);
    let recipient = "03".repeat(33);
    for i in 0..4 {
        let mid = format!("t{i}");
        store
            .upload(env(&sender, &recipient, &mid, "p"), 3600, &policy)
            .unwrap();
        store.ack_deliver(&recipient, &mid, &sender).unwrap();
        store.ack_read(&recipient, &mid, &sender).unwrap();
    }
    let rows = store.list_outbox(&sender, true).unwrap();
    assert_eq!(rows.len(), 2);
    let mut ids: Vec<_> = rows.iter().map(|r| r.message_id.clone()).collect();
    ids.sort();
    // Cap keeps the newest terminal metadata; listing order is not part of the contract.
    assert_eq!(ids, vec!["t2".to_string(), "t3".to_string()]);
}

#[test]
fn shared_message_id_from_two_senders_both_ack() {
    let (store, policy) = test_store();
    let sender_a = "02".repeat(33);
    let sender_b = "04".repeat(33);
    let recipient = "03".repeat(33);
    let shared_id = "shared-ulid";

    store
        .upload(
            env(&sender_a, &recipient, shared_id, "from-a"),
            3600,
            &policy,
        )
        .unwrap();
    store
        .upload(
            env(&sender_b, &recipient, shared_id, "from-b"),
            3600,
            &policy,
        )
        .unwrap();

    let pending = store.pending_for_recipient(&recipient).unwrap();
    assert_eq!(pending.len(), 2);

    let (_, a_new) = store.ack_deliver(&recipient, shared_id, &sender_a).unwrap();
    let (_, b_new) = store.ack_deliver(&recipient, shared_id, &sender_b).unwrap();
    assert!(a_new);
    assert!(b_new);
    assert!(store.pending_for_recipient(&recipient).unwrap().is_empty());
}
