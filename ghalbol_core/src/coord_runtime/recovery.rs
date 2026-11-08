//! Coord recovery throttles, presence invalidate, and lookup backoff sync.

use super::presence::{refresh_relay_presence_from_coord, schedule_check_relay_presence_once};
use super::register::{has_public_coord_register_endpoints, spawn_register_presence_inner};
use super::state::*;
use std::sync::atomic::Ordering;

pub fn clear_coord_lookup_backoff_for_pk(public_key_hex: &str) {
    let Ok(pk) = crate::public_key_util::normalize_contact_identity_wire(public_key_hex) else {
        return;
    };
    if let Ok(mut m) = lookup_backoff_map().lock() {
        m.remove(&pk);
    }
}

/// Mirror `:p2p` `note_coord_lookup_not_found` so duplicate UI lookups do not fight native upkeep.
pub fn sync_coord_lookup_peer_not_found(public_key_hex: &str, step_ms: u64, now_ms: i64) {
    let Ok(pk) = crate::public_key_util::normalize_contact_identity_wire(public_key_hex) else {
        return;
    };
    let step = step_ms.clamp(500, 5_000);
    let next = (now_ms as u64).saturating_add(step);
    if let Ok(mut m) = lookup_backoff_map().lock() {
        insert_lookup_backoff(
            &mut m,
            pk,
            CoordLookupBackoff {
                next_allowed_ms: next,
                step_ms: step,
            },
        );
    }
}
pub(super) fn relay_presence_reschedule_min_ms() -> u64 {
    if COORD_REGISTERED.load(Ordering::Relaxed) {
        RELAY_PRESENCE_RESCHEDULE_REGISTERED_MS
    } else {
        RELAY_PRESENCE_RESCHEDULE_MIN_MS
    }
}

pub(super) fn coord_recovery_throttled(now: u64) -> bool {
    let last = COORD_RECOVERY_LAST_MS.load(Ordering::Relaxed);
    last > 0 && now.saturating_sub(last) < COORD_RECOVERY_MIN_MS
}

pub(super) fn note_coord_recovery_attempt(now: u64) {
    COORD_RECOVERY_LAST_MS.store(now, Ordering::Relaxed);
}

pub(super) fn should_log_coord_heartbeat_fail(now: u64) -> bool {
    let last = COORD_HEARTBEAT_FAIL_LOG_LAST_MS.load(Ordering::Relaxed);
    if last > 0 && now.saturating_sub(last) < COORD_HEARTBEAT_FAIL_LOG_MIN_MS {
        return false;
    }
    COORD_HEARTBEAT_FAIL_LOG_LAST_MS.store(now, Ordering::Relaxed);
    true
}
pub(super) fn heartbeat_err_peer_not_on_coord(err: &str) -> bool {
    err.contains("404") || err.contains("not registered")
}

pub(super) fn recover_coord_presence_after_server_drop(pk: &str) {
    let now = unix_ms_now();
    if coord_recovery_throttled(now) {
        return;
    }
    note_coord_recovery_attempt(now);
    if refresh_relay_presence_from_coord(pk) {
        return;
    }
    if has_public_coord_register_endpoints() {
        spawn_register_presence_inner(false);
    } else {
        schedule_check_relay_presence_once();
    }
}

/// Bootstrap HOP to coord relay dropped — reconcile WAN presence without tearing down
/// parallel LAN+WAN when local relay circuit listen is still up.
pub fn mark_coord_relay_hop_lost() {
    if !crate::wan_coord::local_relay_circuit_listening() {
        COORD_REGISTERED.store(false, Ordering::Relaxed);
    }
    schedule_check_relay_presence_once();
}

/// Clear stale endpoint snapshot after a full WAN network handover (Wi‑Fi ↔ cell).
/// Forces presence re-check / re-register so dials do not use pre-handover TCP endpoints.
pub fn coord_invalidate_presence_on_network_change() {
    crate::flow_log::info(
        "coord",
        "network handover — invalidate published endpoints and re-establish presence",
    );
    if let Ok(mut v) = coord_globals().endpoints.lock() {
        v.clear();
    }
    if let Ok(mut g) = coord_globals().preferred_relay_peer_id.lock() {
        *g = None;
    }
    if let Ok(mut m) = lookup_backoff_map().lock() {
        m.clear();
    }
    if let Ok(mut r) = coord_globals().registered_on.lock() {
        r.clear();
    }
    COORD_REG_PENDING.store(false, Ordering::Relaxed);
    // Public-TCP registration is stale after iface change. Relay-circuit presence may still
    // be valid on the coord relay — only clear the registered bit when we are not listening
    // on a circuit (same rule as mark_coord_relay_hop_lost).
    if !crate::wan_coord::local_relay_circuit_listening() {
        COORD_REGISTERED.store(false, Ordering::Relaxed);
    }
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    schedule_check_relay_presence_once();
    if has_public_coord_register_endpoints() {
        spawn_register_presence_inner(true);
    }
}
pub fn note_remote_peer_circuit_stale(public_key_hex: &str) {
    clear_coord_lookup_backoff_for_pk(public_key_hex);
}
