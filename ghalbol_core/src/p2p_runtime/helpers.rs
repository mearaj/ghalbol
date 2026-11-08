//! JSON helpers, peer parsing, and gossip event serialization.

use crate::connect::identity_wire_for_libp2p_peer;
use crate::contacts_v1::is_valid_public_key_hex;
use crate::p2p::{DmPeer, GossipChatEvent};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn gossip_event_json(ev: GossipChatEvent) -> Value {
    match ev {
        GossipChatEvent::Listening(ma) => serde_json::json!({
            "kind": "listening",
            "multiaddr": ma.to_string(),
        }),
        GossipChatEvent::PeerConnected(p) => {
            let pk = identity_wire_for_libp2p_peer(&p).unwrap_or_else(|| p.to_string());
            serde_json::json!({
                "kind": "peer_connected",
                "peer_id": p.to_string(),
                "public_key_hex": pk,
            })
        }
        GossipChatEvent::PeerDisconnected(p) => {
            let pk = identity_wire_for_libp2p_peer(&p).unwrap_or_else(|| p.to_string());
            serde_json::json!({
                "kind": "peer_disconnected",
                "peer_id": p.to_string(),
                "public_key_hex": pk,
            })
        }
        GossipChatEvent::DialFailed { peer, error } => serde_json::json!({
            "kind": "dial_failed",
            "peer": peer.and_then(|p| identity_wire_for_libp2p_peer(&p)),
            "error": error,
        }),
        GossipChatEvent::DmMessage {
            from,
            id,
            msg_kind,
            text,
            ref_id,
            sender_public_key_hex,
            created_at_ms,
            received_at_ms,
            duration_ms,
        } => {
            let mut j = serde_json::json!({
                "kind": "dm_message",
                "from": from.to_string(),
                "id": id,
                "msg_kind": msg_kind,
                "text": text,
                "ref_id": ref_id,
                "sender_public_key_hex": sender_public_key_hex,
                "created_at_ms": created_at_ms,
            });
            if let Some(at) = received_at_ms.filter(|t| *t > 0) {
                j["received_at_ms"] = serde_json::json!(at);
            }
            if let Some(d) = duration_ms.filter(|d| *d > 0) {
                j["duration_ms"] = serde_json::json!(d);
            }
            j
        }
        GossipChatEvent::PeerIdentified {
            peer_id,
            public_key_hex,
        } => serde_json::json!({
            "kind": "peer_identified",
            "peer_id": peer_id.to_string(),
            "public_key_hex": public_key_hex,
        }),
        GossipChatEvent::ChatReady { peer_id } => {
            let pk = identity_wire_for_libp2p_peer(&peer_id).unwrap_or_else(|| peer_id.to_string());
            serde_json::json!({
                "kind": "chat_ready",
                "peer_id": peer_id.to_string(),
                "public_key_hex": pk,
            })
        }
        GossipChatEvent::SendFailed { message_id, error } => serde_json::json!({
            "kind": "send_failed",
            "message_id": message_id,
            "error": error,
        }),
        GossipChatEvent::OutboundSent { message_id } => serde_json::json!({
            "kind": "outbound_sent",
            "message_id": message_id,
        }),
        GossipChatEvent::NativeLog {
            level,
            tag,
            message,
        } => serde_json::json!({
            "kind": "native_log",
            "level": level,
            "tag": tag,
            "message": message,
        }),
        GossipChatEvent::CallSignal {
            from,
            id,
            call_id,
            signal,
            sender_public_key_hex,
            created_at_ms,
            payload,
        } => serde_json::json!({
            "kind": "call_signal",
            "from": from.to_string(),
            "id": id,
            "call_id": call_id,
            "signal": signal,
            "sender_public_key_hex": sender_public_key_hex,
            "created_at_ms": created_at_ms,
            "payload": payload,
        }),
        GossipChatEvent::CallSignalSent {
            call_id,
            signal,
            recipient_public_key_hex,
        } => serde_json::json!({
            "kind": "call_signal_sent",
            "call_id": call_id,
            "signal": signal,
            "recipient_public_key_hex": recipient_public_key_hex,
        }),
        GossipChatEvent::CallMedia {
            call_id,
            peer_public_key_hex,
            state,
            camera_on,
            remote_video_on,
            reason,
        } => serde_json::json!({
            "kind": "call_media",
            "call_id": call_id,
            "peer_public_key_hex": peer_public_key_hex,
            "state": state,
            "camera_on": camera_on,
            "remote_video_on": remote_video_on,
            "reason": reason,
        }),
        GossipChatEvent::NodeReady => serde_json::json!({ "kind": "node_ready" }),
        GossipChatEvent::NodeStopped { error } => serde_json::json!({
            "kind": "node_stopped",
            "error": error,
        }),
    }
}

pub(crate) fn json_err(msg: impl AsRef<str>) -> Value {
    serde_json::json!({ "ok": false, "error": msg.as_ref() })
}

pub(crate) fn json_ok(v: Value) -> Value {
    v
}

pub(crate) fn recipient_identity_from_config(config: &Value) -> Option<String> {
    config
        .get("recipient_public_key_hex")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| is_valid_public_key_hex(s))
        .map(str::to_string)
}

pub(crate) fn parse_dm_peers(v: &Value) -> Vec<DmPeer> {
    let mut out = Vec::new();
    let Some(arr) = v.get("dm_peers").and_then(|x| x.as_array()) else {
        return out;
    };
    for item in arr {
        let pk = item
            .get("public_key_hex")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| crate::contacts_v1::is_valid_public_key_hex(s));
        if let Some(pk) = pk {
            if let Ok(dm) = DmPeer::from_public_key_hex(pk.to_string()) {
                out.push(dm);
            }
        }
    }
    out
}

pub(crate) fn apply_coord_from_config(config: &Value) {
    let tls = config
        .get("coord_insecure_tls")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let urls = crate::coord_runtime::coord_urls_from_json_value(config);
    if !urls.is_empty() {
        crate::coord_runtime::set_coord_base_urls(&urls, tls);
    }
}

pub(crate) fn apply_delivery_from_p2p_config(config: &Value) {
    crate::rustls_init::ensure_rustls_crypto_provider();
    match config.get("delivery_url").and_then(|v| v.as_str()) {
        Some(url) if !url.trim().is_empty() => {
            crate::delivery_runtime::set_delivery_url(Some(url));
            if crate::text_transport::wan_text_via_delivery_server() {
                crate::delivery_runtime::delivery_start();
            }
        }
        _ => {
            crate::delivery_runtime::set_delivery_url(None);
            crate::delivery_runtime::delivery_stop();
        }
    }
}
