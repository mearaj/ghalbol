//! Voice/video calls, speaker, mic, and call chrome helpers.

use serde_json::{Value, json};

use crate::call_state;
use crate::p2p_runtime;

use super::{json_error, require_contact_pk};
use super::contacts::peer_display_name;

pub fn start_voice_call(peer_public_key_hex: &str) -> Result<String, String> {
    let peer = require_contact_pk(peer_public_key_hex)?;
    let call_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let cfg = json!({
        "recipient_public_key_hex": peer,
        "call_id": call_id,
        "signal": "invite",
        "payload": {
            "media": "audio",
            "voice_engine": "native_v2",
            "video_engine": "native_v1",
        },
    });
    json_error(&p2p_runtime::p2p_call_signal(&cfg), "could not start call")?;
    if let Ok(mut g) = active_call().lock() {
        *g = Some((call_id.clone(), peer));
    }
    let _ = start_call_media();
    Ok(call_id)
}

pub fn accept_incoming_call() -> Result<(), String> {
    let _accept_guard = accept_incoming_once()
        .lock()
        .map_err(|_| "accept in progress".to_string())?;
    let status = p2p_runtime::p2p_call_status(&json!({}));
    if !call_is_incoming_ringing() {
        return Err("No incoming call".into());
    }
    let call_id = status
        .get("call_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let peer = status
        .get("peer_public_key_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if call_id.is_empty() || peer.is_empty() {
        return Err("No incoming call".into());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    crate::incoming_call_notify::dismiss_incoming_call();
    let cfg = json!({
        "recipient_public_key_hex": peer,
        "call_id": call_id,
        "signal": "accept",
        "payload": {
            "media": "audio",
            "voice_engine": "native_v2",
            "video_engine": "native_v1",
        },
    });
    json_error(&p2p_runtime::p2p_call_signal(&cfg), "could not accept call")?;
    if let Ok(mut g) = active_call().lock() {
        *g = Some((call_id, peer));
    }
    let _ = start_call_media();
    Ok(())
}

pub fn start_video_call(peer_public_key_hex: &str) -> Result<String, String> {
    let dial_peer = require_contact_pk(peer_public_key_hex)?;
    // Mid-call upgrade: if we already have this peer on the line, only start video.
    if let Ok((call_id, peer)) = current_call() {
        if crate::public_key_util::same_contact_pk(&peer, &dial_peer) {
            let cfg = json!({
                "action": "start",
                "call_id": call_id,
                "recipient_public_key_hex": peer,
                "camera_enabled": true,
            });
            json_error(&p2p_runtime::p2p_call_video(&cfg), "could not start video")?;
            return Ok(call_id);
        }
    }
    // Fresh video dial: invite advertises audio_video + engine tags (GHALBOL_VOICE_V1).
    let call_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let cfg = json!({
        "recipient_public_key_hex": dial_peer,
        "call_id": call_id,
        "signal": "invite",
        "payload": {
            "media": "audio_video",
            "voice_engine": "native_v2",
            "video_engine": "native_v1",
        },
    });
    json_error(&p2p_runtime::p2p_call_signal(&cfg), "could not start call")?;
    if let Ok(mut g) = active_call().lock() {
        *g = Some((call_id.clone(), dial_peer.clone()));
    }
    let _ = start_call_media();
    let cfg = json!({
        "action": "start",
        "call_id": call_id,
        "recipient_public_key_hex": dial_peer,
        "camera_enabled": true,
    });
    json_error(&p2p_runtime::p2p_call_video(&cfg), "could not start video")?;
    Ok(call_id)
}

/// Turn the local camera on or off during an active video session (sends `video_on`/`video_off`).
pub fn set_call_camera_enabled(enabled: bool) -> Result<(), String> {
    let (call_id, _) = current_call()?;
    let cfg = json!({
        "action": "set_camera_enabled",
        "call_id": call_id,
        "enabled": enabled,
    });
    json_error(&p2p_runtime::p2p_call_video(&cfg), "could not change camera")
}

pub fn set_speaker(on: bool) -> Result<(), String> {
    crate::call_media::set_desktop_speaker_on(on);
    #[cfg(target_os = "android")]
    {
        let (call_id, _) = current_call()?;
        let cfg = json!({
            "action": "set_speaker",
            "call_id": call_id,
            "speaker_on": on,
        });
        json_error(&p2p_runtime::p2p_call_media(&cfg), "could not change speaker")?;
    }
    Ok(())
}

pub fn set_mic_muted(muted: bool) -> Result<(), String> {
    let (call_id, _) = current_call()?;
    let cfg = json!({
        "action": "set_mic_muted",
        "call_id": call_id,
        "muted": muted,
    });
    json_error(&p2p_runtime::p2p_call_media(&cfg), "could not change mute")
}

fn current_call() -> Result<(String, String), String> {
    active_call()
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or_else(|| "No active call".to_string())
}

fn start_call_media() -> Result<(), String> {
    let (call_id, peer) = current_call()?;
    let cfg = json!({
        "action": "start",
        "call_id": call_id,
        "recipient_public_key_hex": peer,
    });
    json_error(&p2p_runtime::p2p_call_media(&cfg), "could not start call audio")
}

pub fn end_call() -> Result<(), String> {
    let declining = call_is_incoming_ringing();
    let Some((call_id, peer)) = resolve_end_call_target() else {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        crate::incoming_call_notify::dismiss_incoming_call();
        let _ = p2p_runtime::p2p_force_end_active_call("ui_hangup");
        if let Ok(mut g) = active_call().lock() {
            *g = None;
        }
        return Err("No active call".into());
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    crate::incoming_call_notify::dismiss_incoming_call();
    let signal = if declining { "reject" } else { "hangup" };
    let reason = if declining { "rejected" } else { "ui_hangup" };
    let cfg = json!({
        "recipient_public_key_hex": peer,
        "call_id": call_id,
        "signal": signal,
        "payload": {},
    });
    let _ = p2p_runtime::p2p_call_signal(&cfg);
    let _ = p2p_runtime::p2p_call_media(&json!({ "action": "stop", "call_id": call_id }));
    let _ = p2p_runtime::p2p_call_video(&json!({ "action": "stop", "call_id": call_id }));
    if declining {
        let video = call_state::peer_call_video_enabled(&peer)
            || crate::p2p::call_active::snapshot()
                .map(|s| s.video_active || s.camera_on || s.remote_video_on)
                .unwrap_or(false);
        crate::call_history::record_ring_outcome(&call_id, &peer, video, reason);
    } else {
        crate::call_history::record_from_active(reason);
    }
    let _ = p2p_runtime::p2p_force_end_active_call(reason);
    if let Ok(mut g) = active_call().lock() {
        *g = None;
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android"))]
    crate::call_pictures::clear_call_pictures();
    Ok(())
}

/// Local / remote call tiles as raw RGBA (width, height, bytes) for live textures.
pub fn call_picture_rgbas(
) -> (Option<(u32, u32, Vec<u8>)>, Option<(u32, u32, Vec<u8>)>) {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android"))]
    {
        if let Ok((call_id, _)) = current_call() {
            return crate::call_pictures::call_picture_rgbas(&call_id);
        }
    }
    (None, None)
}

pub fn call_banner() -> String {
    let status = p2p_runtime::p2p_call_status(&json!({}));
    let peer = status
        .get("peer_public_key_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let peer_label = peer_display_name(peer);
    // Incoming ring only — never treat the caller's outbound dial as Accept UI.
    if status.get("incoming").and_then(|v| v.as_bool()) == Some(true)
        || (status.get("ringing").and_then(|v| v.as_bool()) == Some(true)
            && status.get("phase").and_then(|v| v.as_str()) == Some("incoming_ringing"))
    {
        return format!("Incoming call · {peer_label}");
    }
    if status.get("phase").and_then(|v| v.as_str()) == Some("outgoing_ringing") {
        return format!("Calling {peer_label}…");
    }
    if status.get("active").and_then(|v| v.as_bool()) == Some(true) {
        let voice = status.get("voice_active").and_then(|v| v.as_bool()) == Some(true);
        let video = call_shows_video_from(&status);
        let e2e = " · End-to-end encrypted";
        return if video {
            format!("Video call · {peer_label}{e2e}")
        } else if voice {
            format!("Voice call · {peer_label}{e2e}")
        } else {
            format!("Connecting · {peer_label}")
        };
    }
    String::new()
}

/// Peer display name for the open call (alias, else short key).
pub fn call_peer_label() -> String {
    let status = p2p_runtime::p2p_call_status(&json!({}));
    let peer = status
        .get("peer_public_key_hex")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if peer.is_empty() {
        String::new()
    } else {
        peer_display_name(peer)
    }
}

/// True when local/remote video should be shown (not on plain voice dials).
pub fn call_shows_video() -> bool {
    let status = p2p_runtime::p2p_call_status(&json!({}));
    call_shows_video_from(&status)
}

fn call_shows_video_from(status: &Value) -> bool {
    status.get("video_active").and_then(|v| v.as_bool()) == Some(true)
        || status.get("camera_on").and_then(|v| v.as_bool()) == Some(true)
        || status.get("remote_video_on").and_then(|v| v.as_bool()) == Some(true)
}

/// True only while this device is the **callee** with an unanswered invite.
/// The caller's dial must never show Accept.
pub fn call_is_incoming_ringing() -> bool {
    let status = p2p_runtime::p2p_call_status(&json!({}));
    status.get("incoming").and_then(|v| v.as_bool()) == Some(true)
        || (status.get("ringing").and_then(|v| v.as_bool()) == Some(true)
            && status.get("phase").and_then(|v| v.as_str()) == Some("incoming_ringing"))
}

/// What mouse / Android / Escape back should do while call chrome is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallBackNav {
    /// No call to handle.
    None,
    /// Dialing or connected — consume back; do not hang up.
    Block,
    /// Incoming ring — decline / hang up.
    End,
}

pub fn call_back_nav() -> CallBackNav {
    if call_is_incoming_ringing() {
        return CallBackNav::End;
    }
    let status = p2p_runtime::p2p_call_status(&json!({}));
    if status.get("phase").and_then(|v| v.as_str()) == Some("outgoing_ringing")
        || status.get("active").and_then(|v| v.as_bool()) == Some(true)
    {
        return CallBackNav::Block;
    }
    CallBackNav::None
}

/// Flip the in-call camera (front ↔ back on Android; no-op elsewhere when unsupported).
pub fn flip_call_camera() -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        return crate::call_video::flip_camera();
    }
    #[cfg(not(target_os = "android"))]
    {
        Err("Camera flip is only available on Android during a video call".into())
    }
}

fn active_call() -> &'static std::sync::Mutex<Option<(String, String)>> {
    static CALL: std::sync::OnceLock<std::sync::Mutex<Option<(String, String)>>> =
        std::sync::OnceLock::new();
    CALL.get_or_init(|| std::sync::Mutex::new(None))
}

fn accept_incoming_once() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// UI hangup target: host snapshot, native status, then in-memory ring phases (window close path).
fn resolve_end_call_target() -> Option<(String, String)> {
    if let Ok(g) = active_call().lock() {
        if let Some(pair) = g.clone() {
            return Some(pair);
        }
    }
    let status = p2p_runtime::p2p_call_status(&json!({}));
    if status.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        let call_id = status
            .get("call_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let peer = status
            .get("peer_public_key_hex")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        return Some((call_id.to_string(), peer.to_string()));
    }
    if let Some((peer, call_id)) = call_state::first_incoming_ringing() {
        return Some((call_id, peer));
    }
    if let Some((peer, call_id)) = call_state::first_outgoing_ringing() {
        return Some((call_id, peer));
    }
    None
}

#[cfg(test)]
mod call_end_tests {
    use super::*;

    fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        L.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap()
    }

    const PK: &str = "03b5b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";

    #[test]
    fn resolve_end_call_from_ringing_store_without_host_snapshot() {
        let _lock = lock_tests();
        call_state::clear_all_calls();
        if let Ok(mut g) = active_call().lock() {
            *g = None;
        }
        call_state::apply_inbound_ex(PK, "ring-1", crate::call_sig_v1::CallSigKind::Invite, false)
            .unwrap();
        let resolved = resolve_end_call_target().expect("ringing call");
        assert_eq!(resolved.0, "ring-1");
        assert_eq!(resolved.1, PK);
        call_state::clear_all_calls();
    }
}

/// Play the incoming-call tone once per ring, a ringback while dialing, and stop when the banner clears.
pub fn note_call_banner(line: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::sync::atomic::{AtomicU8, Ordering};
        static PHASE: AtomicU8 = AtomicU8::new(0);
        let next = if line.starts_with("Incoming") {
            1
        } else if line.starts_with("Calling") {
            2
        } else {
            0
        };
        let prev = PHASE.swap(next, Ordering::Relaxed);
        if next == 0 && prev != 0 {
            crate::incoming_call_notify::dismiss_incoming_call();
        } else if next != 0 && prev != next {
            if next == 1 {
                crate::linux_desktop_launch::play_incoming_ring();
            } else {
                crate::linux_desktop_launch::play_ringback();
            }
        }
    }
    let _ = line;
}

