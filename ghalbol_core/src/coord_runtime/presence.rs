//! Coord heartbeat loop and relay presence polling.

use super::config::{
    coord_base_urls, coord_is_configured, coord_lookup_err_means_http_reachable,
    note_coord_transport_failure, note_coord_transport_ok,
};
use super::recovery::{
    coord_recovery_throttled, heartbeat_err_peer_not_on_coord, note_coord_recovery_attempt,
    recover_coord_presence_after_server_drop, should_log_coord_heartbeat_fail,
};
#[cfg(not(test))]
use super::recovery::relay_presence_reschedule_min_ms;
use super::register::{
    has_public_coord_register_endpoints, is_coord_publishable_host, spawn_register_presence_inner,
};
use super::state::*;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub(super) fn suspend_coord_presence_waiting_endpoints() {
    COORD_REGISTERED.store(false, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(0, Ordering::Relaxed);
    // Stop heartbeats so stale coord presence naturally expires while waiting for
    // a relay/public listen endpoint.
    coord_globals()
        .heartbeat_stop
        .store(true, Ordering::Relaxed);
}
pub fn schedule_register_presence_force() {
    spawn_register_presence_inner(true);
}

/// Relay reservation accepted or circuit listen up — server registers `/p2p-circuit` on coord.
pub fn schedule_coord_presence_after_relay() {
    if !coord_is_configured() {
        return;
    }
    if has_public_coord_register_endpoints() {
        spawn_register_presence_inner(true);
    }
    schedule_check_relay_presence_once();
}

/// Relay circuit listener is up — publish on coord and poll server row (do not set registered until HTTP confirms).
pub fn coord_note_relay_circuit_ready() {
    schedule_coord_presence_after_relay();
}
pub(super) fn schedule_check_relay_presence_once() {
    #[cfg(test)]
    {
        return;
    }
    #[cfg(not(test))]
    schedule_check_relay_presence_once_impl();
}

#[cfg(not(test))]
pub(super) fn schedule_check_relay_presence_once_impl() {
    if RELAY_PRESENCE_CHECK_PENDING.load(Ordering::Acquire) {
        return;
    }
    let now = unix_ms_now();
    let last_end = RELAY_PRESENCE_POLL_LAST_END_MS.load(Ordering::Relaxed);
    if last_end > 0 && now.saturating_sub(last_end) < relay_presence_reschedule_min_ms() {
        return;
    }
    if RELAY_PRESENCE_CHECK_PENDING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    std::thread::Builder::new()
        .name("ghalbol-coord-relay-poll".into())
        .spawn(|| {
            let mut attempt: u32 = 0;
            let poll_once = |attempt: u32| -> bool {
                if !coord_is_configured() {
                    return true;
                }
                let Ok(ident) = crate::session_runtime::unlocked_identity_clone() else {
                    return true;
                };
                if refresh_relay_presence_from_coord(&ident.identity_wire()) {
                    return true;
                }
                if crate::wan_coord::local_relay_circuit_listening()
                    && (attempt == 2 || attempt == 7 || attempt % 15 == 0)
                {
                    crate::p2p::notify_relay_refresh();
                    if has_public_coord_register_endpoints() {
                        spawn_register_presence_inner(false);
                    }
                }
                false
            };
            while attempt < RELAY_PRESENCE_POLL_FAST_ATTEMPTS {
                if attempt > 0 {
                    std::thread::sleep(Duration::from_millis(RELAY_PRESENCE_POLL_FAST_MS));
                }
                if poll_once(attempt) {
                    break;
                }
                attempt += 1;
            }
            while attempt < RELAY_PRESENCE_POLL_FAST_ATTEMPTS + RELAY_PRESENCE_POLL_SLOW_ATTEMPTS {
                if !crate::wan_coord::local_relay_circuit_listening() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(RELAY_PRESENCE_POLL_SLOW_MS));
                if poll_once(attempt) {
                    break;
                }
                attempt += 1;
            }
            RELAY_PRESENCE_POLL_LAST_END_MS.store(unix_ms_now(), Ordering::Relaxed);
            RELAY_PRESENCE_CHECK_PENDING.store(false, Ordering::Release);
        })
        .ok();
}

pub(super) fn peer_record_has_relay_circuit(record: &crate::coord::CoordPeerRecord) -> bool {
    record
        .endpoints
        .iter()
        .any(|e| e.scheme == "libp2p" && e.host.contains("/p2p-circuit"))
}

/// Native-connect or legacy row visible on coord (client TCP register or relay circuit).
pub(super) fn peer_record_has_coord_presence(record: &crate::coord::CoordPeerRecord) -> bool {
    if peer_record_has_relay_circuit(record) {
        return true;
    }
    record.endpoints.iter().any(|e| {
        e.scheme == "tcp"
            && !e.host.trim().is_empty()
            && e.port != 0
            && is_coord_publishable_host(&e.host)
    })
}

/// During LAN↔WAN handover coord HTTP may flap while the relay server still has our circuit.
/// Blocking HTTP — call only from a std thread (heartbeat, relay-presence poll, spawn_blocking).
/// Do **not** call from the libp2p tokio task (reqwest::blocking runtime drop panics).
/// Blocking HTTP — call only from a std thread (heartbeat, relay-presence poll, spawn_blocking).
/// Do **not** call from the libp2p tokio task (reqwest::blocking runtime drop panics).
pub fn try_restore_relay_presence_from_coord() -> bool {
    let Ok(ident) = crate::session_runtime::unlocked_identity_clone() else {
        return false;
    };
    refresh_relay_presence_from_coord(&ident.identity_wire())
}

/// GET /v1/peers/self — authoritative whether the relay server still has our circuit.
pub(super) fn refresh_relay_presence_from_coord(pk: &str) -> bool {
    let urls = coord_base_urls();
    if urls.is_empty() {
        return false;
    }
    let mut any_visible = false;
    let mut any_http_ok = false;
    let mut registered = HashSet::new();
    for base in &urls {
        let Ok(client) = client_for(base) else {
            continue;
        };
        match client.lookup(pk) {
            Ok(rec) if peer_record_has_coord_presence(&rec) => {
                any_http_ok = true;
                any_visible = true;
                registered.insert(base.clone());
            }
            Ok(_) => {
                any_http_ok = true;
            }
            Err(e) => {
                if coord_lookup_err_means_http_reachable(&e) {
                    any_http_ok = true;
                }
                crate::flow_log::debug(
                    "coord",
                    format!(
                        "relay presence poll on {base} for {}: {e}",
                        &pk[..8.min(pk.len())]
                    ),
                );
            }
        }
    }
    if any_http_ok {
        note_coord_transport_ok();
    }
    if any_http_ok && !any_visible {
        // HTTP up but no circuit row — re-publish; do not flip coord_registered=false on a
        // transient coord purge while our local relay reservation may still be live.
        if has_public_coord_register_endpoints() {
            spawn_register_presence_inner(false);
        } else {
            let now = unix_ms_now();
            if !coord_recovery_throttled(now) {
                note_coord_recovery_attempt(now);
                schedule_check_relay_presence_once();
            }
        }
        return false;
    }
    if !any_visible {
        return false;
    }
    // Idempotent: visible on coord while already registered — refresh transport ok only.
    if COORD_REGISTERED.load(Ordering::Relaxed) {
        if any_http_ok {
            note_coord_transport_ok();
        }
        return true;
    }
    if let Ok(mut r) = coord_globals().registered_on.lock() {
        *r = registered;
    }
    COORD_REGISTERED.store(true, Ordering::Relaxed);
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(unix_ms_now(), Ordering::Relaxed);
    let now = unix_ms_now();
    let last_log = RELAY_PRESENCE_VISIBLE_LOG_LAST_MS.load(Ordering::Relaxed);
    if last_log == 0 || now.saturating_sub(last_log) >= RELAY_PRESENCE_RESCHEDULE_REGISTERED_MS {
        RELAY_PRESENCE_VISIBLE_LOG_LAST_MS.store(now, Ordering::Relaxed);
        crate::flow_log::info(
            "coord",
            format!(
                "relay presence visible on coord for {} — circuit registered by relay server",
                &pk[..8.min(pk.len())]
            ),
        );
    }
    start_heartbeat_loop(pk.to_string());
    crate::p2p::notify_dm_presence_wake();
    true
}
pub(super) fn coord_heartbeat_running() -> bool {
    coord_globals()
        .heartbeat_join
        .lock()
        .ok()
        .and_then(|j| j.as_ref().map(|h| !h.is_finished()))
        .unwrap_or(false)
}

/// Start the coord heartbeat/presence thread while awaiting phase D (circuit mirror on coord).
pub fn ensure_coord_presence_polling() {
    if !coord_is_configured() || COORD_REGISTERED.load(Ordering::Relaxed) {
        return;
    }
    if !crate::wan_coord::local_relay_circuit_listening() {
        return;
    }
    if coord_heartbeat_running() {
        return;
    }
    let Ok(ident) = crate::session_runtime::unlocked_identity_clone() else {
        return;
    };
    start_heartbeat_loop(ident.identity_wire());
}
pub(super) fn start_heartbeat_loop(public_key_hex: String) {
    // One heartbeat thread only. Restarting without joining spawned duplicates that never saw
    // `heartbeat_stop` — that flooded coord HTTP and starved the poll bridge (2026-06-28).
    if coord_heartbeat_running() {
        return;
    }
    let g = coord_globals();
    g.heartbeat_stop.store(false, Ordering::Relaxed);
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    let stop = &g.heartbeat_stop;
    let handle = std::thread::Builder::new()
        .name("ghalbol-coord-heartbeat".into())
        .spawn(move || {
            loop {
                for _ in 0..HEARTBEAT_INTERVAL_SECS {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                let servers: Vec<String> = coord_globals()
                    .registered_on
                    .lock()
                    .ok()
                    .map(|g| g.iter().cloned().collect())
                    .unwrap_or_else(coord_base_urls);
                if servers.is_empty() {
                    continue;
                }
                if !COORD_REGISTERED.load(Ordering::Relaxed) {
                    let _ = refresh_relay_presence_from_coord(&public_key_hex);
                    continue;
                }
                let mut any_ok = false;
                let mut peer_gone = false;
                for base in &servers {
                    let Ok(c) = client_for(base) else {
                        continue;
                    };
                    match c.heartbeat(&public_key_hex) {
                        Ok(_) => {
                            any_ok = true;
                            note_coord_transport_ok();
                            break;
                        }
                        Err(e) if heartbeat_err_peer_not_on_coord(&e) => {
                            peer_gone = true;
                            COORD_REGISTERED.store(false, Ordering::Relaxed);
                            if let Ok(mut r) = coord_globals().registered_on.lock() {
                                r.clear();
                            }
                            crate::flow_log::warn(
                                "coord",
                                format!(
                                    "heartbeat: peer not on coord ({base}) for {} — recovering",
                                    &public_key_hex[..8.min(public_key_hex.len())]
                                ),
                            );
                            break;
                        }
                        Err(e) => {
                            if coord_lookup_err_means_http_reachable(&e) {
                                note_coord_transport_ok();
                            } else {
                                note_coord_transport_failure();
                            }
                            let now = unix_ms_now();
                            if should_log_coord_heartbeat_fail(now) {
                                crate::flow_log::warn(
                                    "coord",
                                    format!(
                                        "heartbeat failed on {base} for {}: {e}",
                                        &public_key_hex[..8.min(public_key_hex.len())]
                                    ),
                                );
                            }
                        }
                    }
                }
                if any_ok {
                    COORD_LAST_OK_MS.store(unix_ms_now(), Ordering::Relaxed);
                    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
                } else if peer_gone {
                    recover_coord_presence_after_server_drop(&public_key_hex);
                    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
                } else {
                    let fails = COORD_CONSEC_FAILS.fetch_add(1, Ordering::Relaxed) + 1;
                    if fails >= 2 {
                        if refresh_relay_presence_from_coord(&public_key_hex) {
                            COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
                            COORD_LAST_OK_MS.store(unix_ms_now(), Ordering::Relaxed);
                        } else if fails >= 3 {
                            recover_coord_presence_after_server_drop(&public_key_hex);
                            COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
                        }
                    }
                }
            }
        })
        .ok();
    if let Ok(mut j) = g.heartbeat_join.lock() {
        *j = handle;
    }
}

pub fn stop_coord_presence() {
    COORD_REGISTERED.store(false, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(0, Ordering::Relaxed);
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    let g = coord_globals();
    g.heartbeat_stop.store(true, Ordering::Relaxed);
    if let Ok(mut j) = g.heartbeat_join.lock() {
        if let Some(h) = j.take() {
            let _ = h.join();
        }
    }
}
