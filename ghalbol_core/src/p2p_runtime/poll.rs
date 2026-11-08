//! Poll queue maintenance, event drain, and transcript enrich.

use std::sync::atomic::{AtomicI64, Ordering};

use crate::call_state;
use crate::dm_event_handler::apply_p2p_event_json;
use crate::dm_transport::DmDialAddr;
use crate::p2p::{GossipChatEvent, native_log};
use serde_json::Value;

use super::helpers::{gossip_event_json, json_err, json_ok};
use super::lifecycle::{pending_p2p_events_mx, poll_next_p2p_event};

static LAST_POLL_MAINTENANCE_MS: AtomicI64 = AtomicI64::new(0);
const POLL_MAINTENANCE_INTERVAL_MS: i64 = 5_000;

fn maybe_maintain_poll_queue(now_ms: i64) {
    let last = LAST_POLL_MAINTENANCE_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < POLL_MAINTENANCE_INTERVAL_MS {
        return;
    }
    LAST_POLL_MAINTENANCE_MS.store(now_ms, Ordering::Relaxed);
    purge_stale_pending_call_invites(now_ms);
    let expired = call_state::expire_stale_ringing(now_ms);
    if !expired.is_empty() {
        crate::incoming_call_notify::dismiss_incoming_call();
        for ring in expired {
            let reason = if ring.incoming { "missed" } else { "ui_hangup" };
            crate::call_history::record_ring_outcome(
                &ring.call_id,
                &ring.peer_public_key_hex,
                ring.video_enabled,
                reason,
            );
        }
    }
}

/// Drop buffered `invite` poll events so a late UI poll cannot ring after remote hangup.
pub fn drop_pending_call_invite(call_id: &str) {
    let cid = call_id.trim();
    if cid.is_empty() {
        return;
    }
    let Ok(mut q) = pending_p2p_events_mx().lock() else {
        return;
    };
    q.retain(|ev| {
        !matches!(
            ev,
            GossipChatEvent::CallSignal {
                call_id: c,
                signal,
                ..
            } if c == cid && signal == "invite"
        )
    });
}

/// Drop invite poll events older than [call_state::MAX_LIVE_CALL_INVITE_AGE_MS].
pub fn purge_stale_pending_call_invites(now_ms: i64) {
    let Ok(mut q) = pending_p2p_events_mx().lock() else {
        return;
    };
    q.retain(|ev| match ev {
        GossipChatEvent::CallSignal {
            signal,
            created_at_ms,
            ..
        } if signal == "invite" => call_state::call_invite_is_live(*created_at_ms, now_ms),
        _ => true,
    });
}


/// Delivery-server path writes stores directly; enqueue here so `p2p_poll` can emit `stores_updated`.
pub fn enqueue_delivery_gossip_event(ev: GossipChatEvent) {
    if let Ok(mut q) = pending_p2p_events_mx().lock() {
        q.push_back(ev);
    }
}

pub fn p2p_transcript_load_merged(config: &Value) -> Value {
    let ns = config
        .get("app_namespace")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(ns) = ns else {
        return json_err("app_namespace required");
    };
    let keys: Vec<String> = config
        .get("conversation_keys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        return json_err("conversation_keys required");
    }
    let from_peer = config
        .get("match_inbound_from_peer_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let limit = config
        .get("limit")
        .and_then(|v| v.as_u64())
        .filter(|n| *n > 0)
        .map(|n| n as usize);

    // Read-only: return lines to the RPC caller. Do **not** enqueue poll events here —
    // that caused a load → stores_updated → reload feedback loop that pinned chat scroll.
    let view = match crate::dm_transcript_store::thread_view_limited(ns, &keys, from_peer, limit) {
        Ok(v) => v,
        Err(e) => return json_err(format!("{e}")),
    };

    json_ok(serde_json::json!({
        "ok": true,
        "revision": view.revision,
        "has_more": view.has_more,
        "lines": view.lines.iter().map(|l| l.to_json()).collect::<Vec<_>>(),
    }))
}

fn enrich_transcript_poll_fields(j: &mut Value) {
    let Some(ns) = crate::dm_event_handler::active_app_namespace() else {
        return;
    };
    let Some(view_key) = crate::dm_event_handler::transcript_poll_view_key(&ns, j) else {
        return;
    };
    let rev = crate::dm_transcript_store::thread_revision_for_view(&ns, &view_key);
    if let Some(obj) = j.as_object_mut() {
        obj.insert("conversation_key".to_string(), Value::String(view_key));
        obj.insert("transcript_revision".to_string(), Value::Number(rev.into()));
    }
}

pub fn p2p_poll_event() -> Option<Value> {
    maybe_maintain_poll_queue(call_state::now_ms());
    let now = call_state::now_ms();
    loop {
        let Some(ev) = poll_next_p2p_event() else {
            return None;
        };
        if let GossipChatEvent::Listening(addr) = &ev {
            if let Some((host, port)) = addr.rsplit_once(':') {
                if let Ok(p) = port.parse::<u16>() {
                    crate::coord_runtime::on_listen_dm_addr(&DmDialAddr::new(host.to_string(), p));
                }
            }
        }
        let mut j = gossip_event_json(ev.clone());
        let stores_updated = apply_p2p_event_json(&j);
        if stores_updated {
            if let Some(obj) = j.as_object_mut() {
                obj.insert("stores_updated".to_string(), Value::Bool(true));
            }
            enrich_transcript_poll_fields(&mut j);
            if let Some(kind) = j.get("kind").and_then(|v| v.as_str()) {
                native_log::info("DM/store", format!("stores_updated after {kind}"));
            }
            return Some(j);
        }
        let Some(kind) = j.get("kind").and_then(|v| v.as_str()) else {
            return Some(j);
        };
        if kind == "dm_message" {
            let mk = j
                .get("msg_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if mk == "ack_received" || mk == "ack_read" || mk == "attachment_complete" {
                if stores_updated {
                    if let Some(obj) = j.as_object_mut() {
                        obj.insert("stores_updated".to_string(), Value::Bool(true));
                    }
                    enrich_transcript_poll_fields(&mut j);
                    return Some(j);
                }
                // Delivery worker (or the attachment fetch completion) may have patched
                // the transcript before this poll replay.
                if mk == "attachment_complete"
                    || crate::text_transport::wan_text_via_delivery_server()
                {
                    if let Some(obj) = j.as_object_mut() {
                        obj.insert("stores_updated".to_string(), Value::Bool(true));
                    }
                    enrich_transcript_poll_fields(&mut j);
                    return Some(j);
                }
                continue;
            }
            if mk == "text" || mk == "voice" || mk == "attachment_offer" {
                // Drop bogus empty frames (never persist; must not force UI reload/scroll).
                let id = j.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
                let from = j.get("from").and_then(|v| v.as_str()).unwrap_or("").trim();
                let text = j.get("text").and_then(|v| v.as_str()).unwrap_or("");
                if id.is_empty() && from.is_empty() && text.is_empty() {
                    continue;
                }
                // Wire path persists before this poll event; apply is often a no-op replay but
                // contacts on disk already have the new unread — UI must reload the roster.
                if let Some(obj) = j.as_object_mut() {
                    obj.insert("stores_updated".to_string(), Value::Bool(true));
                }
                enrich_transcript_poll_fields(&mut j);
                return Some(j);
            }
        }
        if kind == "peer_identified" {
            return Some(j);
        }
        if kind == "outbound_sent" && crate::text_transport::wan_text_via_delivery_server() {
            if let Some(obj) = j.as_object_mut() {
                obj.insert("stores_updated".to_string(), Value::Bool(true));
            }
            return Some(j);
        }
        if kind == "call_signal" {
            let signal = j.get("signal").and_then(|v| v.as_str()).unwrap_or("");
            if signal == "invite" {
                let created = j.get("created_at_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                if !call_state::call_invite_is_live(created, now) {
                    continue;
                }
            }
        }
        return Some(j);
    }
}

