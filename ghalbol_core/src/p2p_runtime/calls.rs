//! Call signaling, media, video, and status snapshots.

use crate::call_sig_v1::CallSigKind;
use crate::call_state;
use crate::connect::new_msg_id_for_ffi;
use crate::p2p::{OutboundCmd, native_log};
use serde_json::Value;

use super::helpers::{json_err, json_ok, recipient_identity_from_config};
use super::lifecycle::p2p_mx;
use super::poll::drop_pending_call_invite;

pub fn p2p_force_end_active_call(reason: &str) -> Value {
    native_log::info("call", &format!("force_end_active_call reason={reason}"));
    let had_active = crate::p2p::call_active::snapshot().is_some()
        || call_state::first_incoming_ringing().is_some();

    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => {
                crate::p2p::call_active::clear();
                call_state::clear_all_calls();
                crate::incoming_call_notify::dismiss_incoming_call();
                return json_ok(serde_json::json!({
                    "ok": true,
                    "ended": had_active,
                    "reason": reason,
                }));
            }
        };
        g.as_ref().map(|h| h.out_tx.clone())
    };

    if let Some(out_tx) = out_tx {
        let mut hangup_targets = std::collections::HashSet::new();
        if let Some(s) = crate::p2p::call_active::snapshot() {
            hangup_targets.insert((s.peer_public_key_hex.clone(), s.call_id.clone()));
            let _ = out_tx.send(OutboundCmd::CallMediaStop {
                call_id: s.call_id.clone(),
            });
            let _ = out_tx.send(OutboundCmd::CallVideoStop {
                call_id: s.call_id.clone(),
            });
        }
        if let Ok(g) = call_state::store_for_teardown() {
            for (pk, call_id) in g {
                hangup_targets.insert((pk, call_id));
            }
        }
        for (pk, call_id) in hangup_targets {
            drop_pending_call_invite(&call_id);
            let _ = out_tx.send(OutboundCmd::SendCallSignal {
                recipient_public_key_hex: pk,
                call_id,
                signal_kind: CallSigKind::Hangup,
                payload: serde_json::json!({}),
                signal_id: new_msg_id_for_ffi(),
            });
        }
    }

    crate::p2p::call_active::clear();
    call_state::clear_all_calls();
    crate::incoming_call_notify::dismiss_incoming_call();
    json_ok(serde_json::json!({
        "ok": true,
        "ended": had_active,
        "reason": reason,
    }))
}

pub fn p2p_call_signal(config: &Value) -> Value {
    let recipient = match recipient_identity_from_config(config) {
        Some(s) => s,
        None => return json_err("recipient_public_key_hex required (valid identity wire)"),
    };
    let call_id = match config
        .get("call_id")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => return json_err("call_id required"),
    };
    let signal_s = match config.get("signal").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return json_err("signal required"),
    };
    let signal_kind = match CallSigKind::parse_wire(signal_s) {
        Ok(k) => k,
        Err(e) => return json_err(e),
    };
    // Apply local phase immediately so the dialer shows "Calling…" (not Accept)
    // before the outbound worker runs. The worker's apply_outbound is then a no-op
    // or confirms the same phase.
    let payload = config
        .get("payload")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    let invite_video = call_state::invite_payload_wants_video(&payload);
    if let Err(e) =
        call_state::apply_outbound_ex(&recipient, &call_id, signal_kind, invite_video)
    {
        return json_err(e);
    }
    let signal_id = config
        .get("signal_id")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(new_msg_id_for_ffi);

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
    if out_tx
        .send(OutboundCmd::SendCallSignal {
            recipient_public_key_hex: recipient,
            call_id: call_id.clone(),
            signal_kind,
            payload,
            signal_id: signal_id.clone(),
        })
        .is_err()
    {
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "call_id": call_id,
        "signal_id": signal_id,
        "queued": true,
    }))
}

/// Native voice **media** control plane. One entrypoint, `action`-dispatched, so
/// the FFI/RPC surface stays small. See `docs/GHALBOL_CALL_NATIVE_V2.md`.
///
/// - `{"action":"start","call_id":..,"recipient_public_key_hex":..}` — open media.
/// - `{"action":"stop","call_id":..}` — tear down media.
/// - `{"action":"set_mic_muted","call_id":..,"muted":bool}` — mute/unmute mic.
/// - `{"action":"set_speaker","call_id":..,"speaker_on":bool}` — Android speakerphone.
pub fn p2p_call_media(config: &Value) -> Value {
    let action = config
        .get("action")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .unwrap_or("");
    let call_id = match config
        .get("call_id")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => return json_err("call_id required"),
    };

    let cmd = match action {
        "start" => {
            let recipient = match recipient_identity_from_config(config) {
                Some(s) => s,
                None => return json_err("recipient_public_key_hex required (valid identity wire)"),
            };
            OutboundCmd::CallMediaStart {
                call_id: call_id.clone(),
                peer_public_key_hex: recipient,
            }
        }
        "stop" => OutboundCmd::CallMediaStop {
            call_id: call_id.clone(),
        },
        "set_mic_muted" => {
            let muted = config
                .get("muted")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            OutboundCmd::CallMediaSetMicMuted {
                call_id: call_id.clone(),
                muted,
            }
        }
        "set_speaker" => {
            let speaker_on = config
                .get("speaker_on")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            OutboundCmd::CallMediaSetSpeaker {
                call_id: call_id.clone(),
                speaker_on,
            }
        }
        other => return json_err(format!("unknown call media action: {other}")),
    };

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
    if out_tx.send(cmd).is_err() {
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "call_id": call_id,
        "action": action,
        "queued": true,
    }))
}

/// Snapshot of native call signaling/media (UI re-sync when the app was backgrounded or killed).
pub fn p2p_call_status(_config: &Value) -> Value {
    let now = call_state::now_ms();
    let expired = call_state::expire_stale_ringing(now);
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
    let media = crate::p2p::call_active::snapshot();
    // Ringing phases win for Accept / "Calling…" even when early media already
    // opened the audio pipeline (host starts media on dial before accept).
    if let Some((pk, call_id)) = crate::call_state::first_incoming_ringing() {
        let ring_age_ms = call_state::incoming_ring_age_ms(now).unwrap_or(0);
        let (voice_active, video_active, camera_on, remote_video_on) = media
            .as_ref()
            .filter(|s| s.call_id == call_id)
            .map(|s| {
                (
                    s.voice_active,
                    s.video_active,
                    s.camera_on,
                    s.remote_video_on,
                )
            })
            .unwrap_or((false, false, false, false));
        return json_ok(serde_json::json!({
            "ok": true,
            "active": false,
            "ringing": true,
            "incoming": true,
            "phase": "incoming_ringing",
            "call_id": call_id,
            "peer_public_key_hex": pk,
            "ring_age_ms": ring_age_ms,
            "voice_active": voice_active,
            "video_active": video_active,
            "camera_on": camera_on,
            "remote_video_on": remote_video_on,
        }));
    }
    if let Some((pk, call_id)) = crate::call_state::first_outgoing_ringing() {
        let (voice_active, video_active, camera_on, remote_video_on) = media
            .as_ref()
            .filter(|s| s.call_id == call_id)
            .map(|s| {
                (
                    s.voice_active,
                    s.video_active,
                    s.camera_on,
                    s.remote_video_on,
                )
            })
            .unwrap_or((false, false, false, false));
        return json_ok(serde_json::json!({
            "ok": true,
            "active": false,
            "ringing": false,
            "incoming": false,
            "phase": "outgoing_ringing",
            "call_id": call_id,
            "peer_public_key_hex": pk,
            "voice_active": voice_active,
            "video_active": video_active,
            "camera_on": camera_on,
            "remote_video_on": remote_video_on,
        }));
    }
    if let Some(s) = media {
        return json_ok(serde_json::json!({
            "ok": true,
            "active": true,
            "phase": "connected",
            "call_id": s.call_id,
            "peer_public_key_hex": s.peer_public_key_hex,
            "voice_active": s.voice_active,
            "video_active": s.video_active,
            "camera_on": s.camera_on,
            "remote_video_on": s.remote_video_on,
        }));
    }
    json_ok(serde_json::json!({
        "ok": true,
        "active": false,
    }))
}

/// Native **video** control plane (parallel to [`p2p_call_media`]).
///
/// - `{"action":"start","call_id":..,"recipient_public_key_hex":..}` — open video.
/// - `{"action":"stop","call_id":..}` — tear down video.
/// - `{"action":"set_camera_enabled","call_id":..,"enabled":bool}` — camera on/off.
pub fn p2p_call_video(config: &Value) -> Value {
    let action = config
        .get("action")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .unwrap_or("");
    let call_id = match config
        .get("call_id")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => return json_err("call_id required"),
    };

    let cmd = match action {
        "start" => {
            let recipient = match recipient_identity_from_config(config) {
                Some(s) => s,
                None => return json_err("recipient_public_key_hex required (valid identity wire)"),
            };
            let camera_enabled = config
                .get("camera_enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            OutboundCmd::CallVideoStart {
                call_id: call_id.clone(),
                peer_public_key_hex: recipient,
                camera_enabled,
            }
        }
        "stop" => OutboundCmd::CallVideoStop {
            call_id: call_id.clone(),
        },
        "set_camera_enabled" => {
            let enabled = config
                .get("enabled")
                .and_then(|x| x.as_bool())
                .unwrap_or(true);
            OutboundCmd::CallVideoSetCameraEnabled {
                call_id: call_id.clone(),
                enabled,
            }
        }
        "capture_backend" => {
            return json_ok(serde_json::json!({
                "ok": true,
                "backend": crate::call_video::desktop_capture_backend(),
            }));
        }
        other => return json_err(format!("unknown call video action: {other}")),
    };

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
    if out_tx.send(cmd).is_err() {
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "call_id": call_id,
        "action": action,
        "queued": true,
    }))
}

