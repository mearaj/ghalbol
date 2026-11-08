//! UI visibility, foreground room, and availability status.

use std::sync::{Mutex, OnceLock};

use crate::contacts_v1::{clear_unread, is_valid_public_key_hex};
use crate::dm_event_handler::active_app_namespace;
use crate::p2p::{
    OutboundCmd, live_foreground_peer_for_catchup, native_log, queue_read_ack_catchup,
    sync_foreground_peer_now,
};
use serde_json::Value;

use super::helpers::{json_err, json_ok, now_ms};
use super::lifecycle::p2p_mx;

pub fn p2p_get_availability_status() -> Value {
    let Some(ns) = active_app_namespace() else {
        return json_err("app namespace not set");
    };
    let cfg = crate::app_paths::storage_config_for_namespace(&ns);
    match crate::preferences_v1::availability_status_get(&cfg) {
        Ok(status) => json_ok(serde_json::json!({ "ok": true, "status": status })),
        Err(e) => json_err(format!("{e}")),
    }
}

pub fn p2p_set_availability_status(status_raw: &str) -> Value {
    let Some(ns) = active_app_namespace() else {
        return json_err("app namespace not set");
    };
    let cfg = crate::app_paths::storage_config_for_namespace(&ns);
    let status = match crate::preferences_v1::availability_status_set(&cfg, status_raw) {
        Ok(s) => s,
        Err(e) => return json_err(format!("{e}")),
    };
    let updated_at_ms = now_ms();
    let out_tx = p2p_mx()
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|h| h.out_tx.clone()));
    let mut sent = 0usize;
    if let Some(out_tx) = out_tx {
        if let Ok(contacts) = crate::contacts_v1::list_contacts(&ns) {
            for c in contacts {
                if !c.has_public_key() {
                    continue;
                }
                if out_tx
                    .send(OutboundCmd::SendAvailabilityStatus {
                        recipient_public_key_hex: c.public_key_hex,
                        status: status.clone(),
                        updated_at_ms,
                    })
                    .is_ok()
                {
                    sent += 1;
                }
            }
        }
    }
    // Mailbox path so peers who never share a native mux still learn status.
    let mailbox_sent =
        crate::delivery_runtime::delivery_broadcast_availability(status.as_deref().unwrap_or(""), updated_at_ms);
    json_ok(serde_json::json!({
        "ok": true,
        "status": status,
        "broadcast_count": sent,
        "mailbox_broadcast_count": mailbox_sent,
        "updated_at_ms": updated_at_ms,
    }))
}

pub fn p2p_sync_ui_session(ui_visible: bool, room_public_key_hex: Option<&str>) -> Value {
    let room = room_public_key_hex
        .map(str::trim)
        .filter(|s| is_valid_public_key_hex(s));
    if ui_session_snapshot_unchanged(ui_visible, room) {
        return json_ok(serde_json::json!({
            "ok": true,
            "unchanged": true,
            "ui_visible": ui_visible,
            "room": room,
            "read_receipts": ui_visible && room.is_some(),
        }));
    }
    record_ui_session_snapshot(ui_visible, room);
    native_log::info(
        "session",
        format!(
            "sync_ui_session ui_visible={ui_visible} room={}",
            room.map(|_| "<pk>").unwrap_or("(none)")
        ),
    );
    crate::p2p::set_app_ui_visible(ui_visible);
    if room.is_none() {
        let r = p2p_set_foreground_peer(None);
        if r.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return r;
        }
        crate::p2p::set_app_ack_read_enabled(false);
        return json_ok(serde_json::json!({
            "ok": true,
            "ui_visible": ui_visible,
            "room": null,
            "read_receipts": false,
        }));
    }
    if ui_visible {
        crate::p2p::set_app_ack_read_enabled(true);
        let r = p2p_set_foreground_peer(room);
        // Android inactive keeps foreground pk but turns read gate off. On resumed the room is
        // unchanged so SetForegroundPeer is skipped — still seed + drain ack_read backlog.
        queue_read_catchup_for_room(room);
        if r.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            return json_ok(serde_json::json!({
                "ok": true,
                "ui_visible": true,
                "room": room,
                "read_receipts": true,
            }));
        }
        return r;
    }
    // Room still open in UI stack but app not interactive (Android inactive, etc.).
    crate::p2p::set_app_ack_read_enabled(false);
    json_ok(serde_json::json!({
        "ok": true,
        "ui_visible": false,
        "room": room,
        "read_receipts": false,
    }))
}

/// Linux read-gate nudge — re-run in-room `ack_read` catch-up without re-issuing `SetForegroundPeer`.

fn ui_session_snapshot_mx() -> &'static Mutex<Option<(bool, Option<String>)>> {
    static S: OnceLock<Mutex<Option<(bool, Option<String>)>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

fn ui_session_snapshot_unchanged(ui_visible: bool, room: Option<&str>) -> bool {
    let Ok(g) = ui_session_snapshot_mx().lock() else {
        return false;
    };
    let Some((was_visible, was_room)) = g.as_ref() else {
        return false;
    };
    *was_visible == ui_visible && was_room.as_deref() == room
}

fn record_ui_session_snapshot(ui_visible: bool, room: Option<&str>) {
    if let Ok(mut g) = ui_session_snapshot_mx().lock() {
        *g = Some((ui_visible, room.map(str::to_string)));
    }
}

pub(crate) fn clear_ui_session_snapshot() {
    if let Ok(mut g) = ui_session_snapshot_mx().lock() {
        *g = None;
    }
}

fn queue_read_catchup_for_room(room: Option<&str>) {
    let Some(peer_pk) = room
        .map(str::trim)
        .filter(|s| is_valid_public_key_hex(s))
        .map(str::to_string)
    else {
        return;
    };
    if crate::text_transport::wan_text_via_delivery_server() {
        crate::delivery_read_acks::queue_delivery_read_catchup(&peer_pk);
    }
    if crate::text_transport::lan_p2p_ack_mirror_enabled(&peer_pk) {
        if let Ok(g) = p2p_mx().lock() {
            if let Some(h) = g.as_ref() {
                queue_read_ack_catchup(&h.out_tx, peer_pk);
            }
        }
    }
}

fn foreground_room_unchanged(public_key_hex: Option<&str>) -> bool {
    let want = public_key_hex
        .map(str::trim)
        .filter(|s| is_valid_public_key_hex(s))
        .map(str::to_lowercase);
    match (want, live_foreground_peer_for_catchup()) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b.to_ascii_lowercase(),
        _ => false,
    }
}

pub fn p2p_set_foreground_peer(public_key_hex: Option<&str>) -> Value {
    if foreground_room_unchanged(public_key_hex) {
        return json_ok(serde_json::json!({ "ok": true, "unchanged": true }));
    }
    let label = public_key_hex
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(none)");
    native_log::info("session", format!("set_foreground_peer request pk={label}"));
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    let pk = public_key_hex
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let prev = live_foreground_peer_for_catchup();
    sync_foreground_peer_now(pk.clone());
    if let Some(ref new_pk) = pk {
        let changed =
            prev.as_deref().map(str::to_ascii_lowercase) != Some(new_pk.to_ascii_lowercase());
        if changed {
            if let Some(ns) = active_app_namespace() {
                let _ = clear_unread(&ns, new_pk);
            }
        }
    }
    let prev_pk = live_foreground_peer_for_catchup();
    let generation = crate::p2p::bump_foreground_peer_cmd_gen();
    if out_tx
        .send(OutboundCmd::SetForegroundPeer {
            identity_wire: pk.clone(),
            generation,
        })
        .is_err()
    {
        return json_err("p2p send failed (node stopped?)");
    }
    if crate::text_transport::wan_text_via_delivery_server() {
        let leaving = match (&prev_pk, &pk) {
            (Some(_prev), None) => true,
            (Some(prev), Some(new)) => !prev.eq_ignore_ascii_case(new),
            _ => false,
        };
        if leaving {
            if let Some(left) = prev_pk.as_ref() {
                crate::delivery_read_acks::dispatch_delivery_leave_drain(left);
            }
        }
        if let Some(new_pk) = pk.as_ref() {
            crate::delivery_read_acks::queue_delivery_read_catchup(new_pk);
        }
    }
    json_ok(serde_json::json!({ "ok": true }))
}

