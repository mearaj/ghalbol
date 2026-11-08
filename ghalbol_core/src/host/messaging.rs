//! Text/voice/files, transcript, delivery, and network session.

use serde_json::{Value, json};

use crate::coord_runtime::parse_coord_urls;
use crate::p2p_runtime::{self, p2p_poll_event, p2p_start, p2p_sync_ui_session};
use crate::preferences_v1;

use super::{cfg, json_error};
use super::contacts::note_outbound_trust;
#[cfg(any(target_os = "linux", target_os = "android"))]
use super::identity::{keystore_exists, session_unlocked};
use crate::contacts_v1;

pub fn fetch_attachment(peer_public_key_hex: &str, offer_id: &str) -> Result<String, String> {
    let v = p2p_runtime::p2p_attachment_fetch(&json!({
        "peer_public_key_hex": peer_public_key_hex,
        "offer_id": offer_id,
    }));
    json_error(&v, "could not download attachment")?;
    if v.get("downloading").and_then(|x| x.as_bool()) == Some(true) {
        return Ok("Downloading".into());
    }
    Ok(v.get("local_path")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string())
}

pub fn send_attachment(peer_public_key_hex: &str, file_path: &str) -> Result<(), String> {
    note_outbound_trust(peer_public_key_hex);
    let cfg = json!({ "file_path": file_path.trim() });
    json_error(
        &p2p_runtime::p2p_send_attachment(peer_public_key_hex, &cfg),
        "could not send attachment",
    )
}

/// Android: send a file picked as a `content://` URI. The bytes are copied into app
/// storage first, because the transcript keeps the sender's local path for **Open**.
#[cfg(target_os = "android")]
pub fn send_picked_attachment(
    app_namespace: &str,
    peer_public_key_hex: &str,
    picked: &str,
) -> Result<(), String> {
    let (name, bytes) =
        super::read_picked_file(picked, crate::attach_v1::MAX_FILE_SIZE_BYTES as usize)?;
    let path = crate::attach_v1::stage_picked_file(app_namespace, &name, &bytes)?;
    send_attachment(peer_public_key_hex, &path.display().to_string())
}

pub fn delivery_summary() -> String {
    let status = crate::delivery_runtime::delivery_connection_status();
    let list = crate::delivery_runtime::delivery_mailbox_list(true);
    let connected = status.get("connected").and_then(|v| v.as_bool()).unwrap_or(false);
    let url = status
        .get("delivery_url")
        .and_then(|v| v.as_str())
        .unwrap_or("(not set)");
    let err = status
        .get("last_error")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let quota = status.get("quota").cloned().unwrap_or(Value::Null);
    let used = quota
        .get("used_bytes")
        .or_else(|| quota.get("used"))
        .and_then(|v| v.as_u64());
    let alloc = quota
        .get("allocated_bytes")
        .or_else(|| quota.get("allocated"))
        .and_then(|v| v.as_u64());
    let quota_line = match (used, alloc) {
        (Some(u), Some(a)) if a > 0 => {
            format!(
                "Quota: {} / {} ({:.0}%)\n",
                format_bytes(u),
                format_bytes(a),
                (u as f64 / a as f64) * 100.0
            )
        }
        _ => String::new(),
    };
    let rows = list
        .pointer("/snapshot/rows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let list_err = list.get("error").and_then(|v| v.as_str()).unwrap_or("");
    let mut body = format!(
        "Delivery mailbox\nConnected: {connected}\nURL: {url}\n{quota_line}Stored messages: {}\n",
        rows.len()
    );
    if !err.is_empty() {
        body.push_str(err);
        body.push('\n');
    }
    if !list_err.is_empty() {
        body.push_str(list_err);
        body.push('\n');
    }
    for row in rows.iter().take(40) {
        let mid = row
            .get("message_id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let state = row.get("state").and_then(|v| v.as_str()).unwrap_or("?");
        let size = row
            .get("size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let exp = row
            .get("expires_at_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        body.push_str(&format!(
            "· {mid}  {state}  {}  expires_ms={exp}\n",
            format_bytes(size)
        ));
    }
    if rows.len() > 40 {
        body.push_str(&format!("…and {} more\n", rows.len() - 40));
    }
    body.push_str(
        "\nQueued rows can be extended (Refresh then Extend). Expired rows need Tap to resend in chat.",
    );
    body
}

fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

/// Extend TTL for a still-queued mailbox message (default +7 days).
pub fn extend_mailbox_ttl(message_id: &str) -> Result<(), String> {
    let v = crate::delivery_runtime::delivery_extend_ttl(message_id, 7 * 24 * 3600);
    if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
        Ok(())
    } else {
        Err(v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("extend failed")
            .to_string())
    }
}

/// Resend a failed/expired outbound text, voice note, or attachment as a **new** upload.
pub fn resend_failed(peer_public_key_hex: &str, old_message_id: &str) -> Result<(), String> {
    let peer = peer_public_key_hex.trim();
    let mid = old_message_id.trim();
    if peer.is_empty() || mid.is_empty() {
        return Err("missing peer or message id".into());
    }
    let ns = crate::dm_event_handler::active_app_namespace()
        .ok_or_else(|| "not unlocked".to_string())?;
    let lines = crate::dm_transcript_store::load_merged(&ns, &[peer.to_string()], None)
        .map_err(|e| e.to_string())?;
    let line = lines
        .into_iter()
        .find(|l| {
            l.outgoing
                && l.message_id.as_deref().unwrap_or("") == mid
                && (l.delivery == "failed" || l.delivery == "pending")
        })
        .ok_or_else(|| "no failed message to resend".to_string())?;
    let kind = line.msg_kind.trim();
    if kind.is_empty() || kind == "text" {
        let text = line.text.trim();
        if text.is_empty() {
            return Err("message body empty".into());
        }
        return send_text(peer, text);
    }
    if kind == "voice" {
        let path = line
            .audio_path
            .as_deref()
            .or(line.local_path.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "voice file missing for resend".to_string())?;
        let opus = std::fs::read(path).map_err(|e| format!("read voice: {e}"))?;
        let duration_ms = line.duration_ms.unwrap_or(1).max(1);
        return send_voice_note(peer, duration_ms, opus);
    }
    if kind == "attachment_offer" {
        let path = line
            .local_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "attachment file missing for resend".to_string())?;
        return send_attachment(peer, path);
    }
    Err(format!("cannot resend msg_kind={kind}"))
}

/// One-shot quota warning for the chat chrome (clears after read).
pub fn take_delivery_quota_warning() -> Option<String> {
    crate::delivery_runtime::take_quota_warning()
}

/// Short line for chat chrome when text is queued but the mailbox is down.
/// `None` when delivery is unused or currently connected.
pub fn delivery_offline_hint() -> Option<String> {
    let status = crate::delivery_runtime::delivery_connection_status();
    let url = status
        .get("delivery_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if url.is_empty() {
        return None;
    }
    if status.get("connected").and_then(|v| v.as_bool()) == Some(true) {
        return None;
    }
    let err = status
        .get("last_error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if err.is_empty() {
        Some(
            "Delivery offline — message queued; peer will get it when the mailbox is reachable."
                .into(),
        )
    } else {
        Some(format!("Delivery offline — message queued. {err}"))
    }
}

pub fn app_log_text() -> String {
    let lines = crate::p2p::native_log::recent_lines();
    if lines.is_empty() {
        "No log lines yet.".into()
    } else {
        lines.join("\n")
    }
}

/// Start native connect in this process and register saved contacts.
pub fn start_network(app_namespace: &str) -> Result<Value, String> {
    let roster = contacts_v1::list_contacts(app_namespace).map_err(|e| e.to_string())?;
    let dm_peers: Vec<Value> = roster
        .into_iter()
        .filter(|c| c.has_public_key())
        .map(|c| json!({ "public_key_hex": c.public_key_hex }))
        .collect();
    let (coord_urls, insecure) = coord_for_namespace(app_namespace);
    let mut cfg = json!({
        "app_namespace": app_namespace,
        "bootstrap_peers": [],
        "dm_peers": dm_peers,
        "coord_base_urls": coord_urls,
        "coord_insecure_tls": insecure,
    });
    if let Some(url) = delivery_url_from_env() {
        cfg["delivery_url"] = Value::String(url);
    }
    let result = p2p_start(&cfg);
    if result.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = result
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("p2p_start failed");
        return Err(err.to_string());
    }
    let _ = p2p_sync_ui_session(true, None);
    #[cfg(target_os = "linux")]
    crate::linux_desktop_launch::install_user_autostart();
    #[cfg(target_os = "android")]
    crate::android_network::hold_multicast_lock(true);
    Ok(result)
}

/// First launch on the desktop: install login start, and ask for the password if a keystore exists.
pub fn desktop_session_start(app_namespace: &str) {
    #[cfg(target_os = "linux")]
    {
        crate::linux_desktop_launch::install_user_autostart();
        if keystore_exists(app_namespace) && !session_unlocked() {
            crate::linux_desktop_launch::notify_unlock_needed();
        }
    }
    #[cfg(target_os = "android")]
    if keystore_exists(app_namespace) && !session_unlocked() {
        crate::incoming_call_android::notify_unlock_needed();
    }
    let _ = app_namespace;
}

pub fn set_open_room(public_key_hex: Option<&str>) {
    if let Some(peer) = public_key_hex {
        crate::message_notify::clear_for_peer(peer);
    }
    let _ = p2p_sync_ui_session(true, public_key_hex);
}

/// Android background: the open room stays, and new read acks stop until the app is visible again.
/// Linux does not call this for a brief focus change.
pub fn set_app_visible(visible: bool) {
    let room = crate::p2p::live_foreground_peer_pk();
    let _ = p2p_sync_ui_session(visible, room.as_deref());
}

#[derive(Clone, Debug)]
pub struct ChatLine {
    pub outgoing: bool,
    pub text: String,
    pub delivery: String,
    pub kind: String,
    pub duration_ms: u32,
    pub audio_path: String,
    pub local_path: String,
    pub message_id: String,
    /// Attachment size when known (offer / downloaded), else 0.
    pub size_bytes: u64,
}

pub struct TranscriptPage {
    pub lines: Vec<ChatLine>,
    pub has_more: bool,
}

/// Monotonic in-memory revision of the peer's transcript (bumped on every store
/// mutation: inbound text, outbound queue, acks). The UI compares this each poll
/// and reloads the open room only when it changed — cheap, and independent of
/// whether the originating event was surfaced through `poll_event`.
pub fn transcript_revision(app_namespace: &str, peer_public_key_hex: &str) -> u64 {
    crate::dm_transcript_store::thread_revision_for_keys(
        app_namespace,
        &[peer_public_key_hex.to_string()],
    )
}

pub fn load_transcript(
    app_namespace: &str,
    peer_public_key_hex: &str,
    limit: usize,
) -> Result<TranscriptPage, String> {
    let cfg = json!({
        "app_namespace": app_namespace,
        "conversation_keys": [peer_public_key_hex],
        "limit": limit.max(1),
    });
    let v = p2p_runtime::p2p_transcript_load_merged(&cfg);
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("transcript load failed");
        return Err(err.to_string());
    }
    let lines = v
        .get("lines")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let has_more = v.get("has_more").and_then(|x| x.as_bool()).unwrap_or(false);
    Ok(TranscriptPage {
        has_more,
        lines: lines
            .into_iter()
            .map(|line| ChatLine {
                outgoing: line.get("outgoing").and_then(|x| x.as_bool()).unwrap_or(false),
                text: line
                    .get("text")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                delivery: line
                    .get("delivery")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                kind: line
                    .get("msg_kind")
                    .and_then(|x| x.as_str())
                    .unwrap_or("text")
                    .to_string(),
                duration_ms: line
                    .get("duration_ms")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u32,
                audio_path: line
                    .get("audio_path")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                local_path: line
                    .get("local_path")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                message_id: line
                    .get("message_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                size_bytes: line
                    .get("size_bytes")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
            })
            .collect(),
    })
}

pub fn send_voice_note(peer_public_key_hex: &str, duration_ms: u32, opus: Vec<u8>) -> Result<(), String> {
    note_outbound_trust(peer_public_key_hex);
    let v = p2p_runtime::p2p_send_voice_dm(peer_public_key_hex, duration_ms, opus);
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = v.get("error").and_then(|x| x.as_str()).unwrap_or("voice send failed");
        return Err(err.to_string());
    }
    Ok(())
}

pub fn voice_note_recording() -> bool {
    crate::voice_note::voice_note_recording()
}

/// Elapsed ms of the in-progress recording, or `None` when idle.
pub fn voice_note_elapsed_ms() -> Option<u32> {
    crate::voice_note::voice_note_elapsed_ms()
}

/// Drop the in-progress recording without sending.
pub fn voice_note_cancel() -> Result<(), String> {
    crate::voice_note::voice_note_cancel()
}

/// `Ok(None)` means recording started. `Ok(Some)` is the finished note.
pub fn voice_note_toggle() -> Result<Option<(u32, Vec<u8>)>, String> {
    crate::voice_note::voice_note_toggle()
}

/// Copy a downloaded attachment into the user's Downloads folder.
/// Returns a short status string suitable for the chat status line.
pub fn save_attachment(local_path: &str) -> Result<String, String> {
    let src = local_path.trim();
    if src.is_empty() || !std::path::Path::new(src).is_file() {
        return Err("Attachment file is missing".into());
    }
    let name = std::path::Path::new(src)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment")
        .to_string();
    #[cfg(target_os = "android")]
    {
        return crate::incoming_call_android::save_file_to_downloads(src, &name);
    }
    #[cfg(not(target_os = "android"))]
    {
        let dest_dir = {
            #[cfg(target_os = "windows")]
            {
                std::env::var_os("USERPROFILE")
                    .map(std::path::PathBuf::from)
                    .map(|p| p.join("Downloads"))
                    .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Downloads")))
                    .ok_or_else(|| "USERPROFILE/HOME unset".to_string())?
            }
            #[cfg(not(target_os = "windows"))]
            {
                let home = std::env::var_os("HOME").ok_or_else(|| "HOME unset".to_string())?;
                std::path::PathBuf::from(home).join("Downloads")
            }
        };
        std::fs::create_dir_all(&dest_dir).map_err(|e| format!("Downloads: {e}"))?;
        let mut dest = dest_dir.join(&name);
        if dest.exists() {
            let stem = dest
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("attachment");
            let ext = dest
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();
            for i in 1..1000 {
                let candidate = dest_dir.join(format!("{stem}-{i}{ext}"));
                if !candidate.exists() {
                    dest = candidate;
                    break;
                }
            }
        }
        std::fs::copy(src, &dest).map_err(|e| format!("Could not save attachment: {e}"))?;
        Ok(format!("Saved to {}", dest.display()))
    }
}

pub fn play_voice_file(path: &str) -> Result<String, String> {
    if crate::voice_note::play_opus_file(path)? {
        Ok("Playing".into())
    } else {
        Ok("Stopped".into())
    }
}

/// Active voice-note playback `(path, elapsed_ms, duration_ms)`, if any.
pub fn voice_play_progress() -> Option<(String, u32, u32)> {
    crate::voice_note::voice_play_progress()
}

pub fn open_local_file(path: &str) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() || !std::path::Path::new(path).is_file() {
        return Err("That file is not on this device yet.".into());
    }
    #[cfg(target_os = "android")]
    {
        return crate::incoming_call_android::open_file(path);
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(all(
        not(target_os = "android"),
        not(target_os = "windows"),
        not(target_os = "macos")
    ))]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub fn send_text(peer_public_key_hex: &str, text: &str) -> Result<(), String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("message is empty".into());
    }
    note_outbound_trust(peer_public_key_hex);
    let v = p2p_runtime::p2p_send_text_dm(peer_public_key_hex, text);
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("send failed");
        return Err(err.to_string());
    }
    Ok(())
}

pub fn poll_event() -> Option<Value> {
    if crate::desktop_wake::take_incoming_call_wake() {
        return Some(json!({ "kind": "incoming_call_wake" }));
    }
    if crate::desktop_wake::take_unlock_wake() {
        return Some(json!({ "kind": "unlock_wake" }));
    }
    p2p_poll_event()
}

fn delivery_url_from_env() -> Option<String> {
    for key in ["GHALBOL_DELIVERY_URL_LOCAL", "GHALBOL_DELIVERY_URL"] {
        if let Ok(raw) = std::env::var(key) {
            let t = raw.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn coord_for_namespace(app_namespace: &str) -> (Vec<String>, bool) {
    let insecure_env = std::env::var("GHALBOL_COORD_INSECURE_TLS")
        .ok()
        .map(|s| {
            let t = s.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    if let Ok(raw) = std::env::var("GHALBOL_COORD_URLS") {
        let urls = parse_coord_urls(raw.trim());
        if !urls.is_empty() {
            return (urls, insecure_env);
        }
    }
    let cfg = cfg(app_namespace);
    if let Ok((url, insecure_pref)) = preferences_v1::coord_settings_get(&cfg) {
        if let Some(url) = url {
            let urls = parse_coord_urls(&url);
            if !urls.is_empty() {
                return (urls, insecure_env || insecure_pref);
            }
        }
    }
    (Vec::new(), insecure_env)
}

