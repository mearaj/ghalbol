//! Attachments — E2E mailbox (delivery / LAN DM) for normal sizes; LAN mux for large.
//!
//! **WAN / delivery:** full plaintext file rides inside the sealed delivery inner
//! (`file_b64`), same rail as voice notes. No connect session, no coord.
//!
//! **LAN:** same sealed DM inner when under the mailbox cap; oversized files only
//! use the native-connect `/ghalbol/attach/1.0.0` mux (LAN peers).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const ATTACH_PROTOCOL: &str = "/ghalbol/attach/1.0.0";
/// LAN mux only — oversized files between peers already on native connect.
pub const MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024;
/// Sealed inner JSON budget for delivery + LAN DM (matches voice).
pub const ATTACH_MAX_SEALED_INNER_BYTES: usize = 3 * 1024 * 1024;
pub const ATTACH_MSG_VERSION: u32 = 2;
pub const CHUNK_SIZE_BYTES: usize = 64 * 1024;
pub const DEFAULT_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeState {
    Serving,
    Complete,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct ServeSlot {
    pub path: PathBuf,
    pub content_key: [u8; 32],
    pub sha256_plaintext: String,
    pub expires_at_ms: i64,
    pub expected_peer: String,
    pub state: ServeState,
}

#[derive(Clone, Debug)]
pub struct AttachmentOfferMeta {
    pub id: String,
    pub sender_public_key_hex: String,
    pub blob_id: String,
    pub file_name: String,
    pub mime_type: String,
    pub size_plaintext: u64,
    pub sha256_plaintext: String,
    pub content_key_b64: String,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct StagedAttachment {
    pub blob_id: String,
    pub offer_json: Value,
    pub preview: String,
    pub file_name: String,
    pub mime_type: String,
    pub size_plaintext: u64,
}

struct FetchState {
    peer: String,
    offer: AttachmentOfferMeta,
    ciphertext: Vec<u8>,
    save_path: PathBuf,
    done: std::sync::mpsc::Sender<Result<String, String>>,
}

fn sanitize_download_stem(id: &str) -> Result<String, String> {
    let t = id.trim();
    if t.is_empty() {
        return Ok("attach".to_string());
    }
    if t.contains('/') || t.contains('\\') || t.contains("..") {
        return Err("invalid download id".to_string());
    }
    if t.chars().count() > 128 {
        return Err("download id too long".to_string());
    }
    Ok(t.to_string())
}

/// Bound in-memory serve slots (LAN mux). Expired / terminal slots are dropped first.
const MAX_SERVE_SLOTS: usize = 64;
/// Bound remembered inbound offers (keyed by message id and blob id — up to 2 entries each).
const MAX_OFFER_ENTRIES: usize = 512;
/// Concurrent LAN fetches in flight for this process.
const MAX_FETCH_INFLIGHT: usize = 16;

fn serve_mx() -> &'static Mutex<HashMap<String, ServeSlot>> {
    static S: OnceLock<Mutex<HashMap<String, ServeSlot>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn offers_mx() -> &'static Mutex<HashMap<String, AttachmentOfferMeta>> {
    static S: OnceLock<Mutex<HashMap<String, AttachmentOfferMeta>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fetch_mx() -> &'static Mutex<HashMap<String, FetchState>> {
    static S: OnceLock<Mutex<HashMap<String, FetchState>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune_serve_slots(g: &mut HashMap<String, ServeSlot>, now: i64) {
    g.retain(|_, slot| {
        if slot.state == ServeState::Cancelled || slot.state == ServeState::Complete {
            return false;
        }
        if slot.expires_at_ms > 0 && now > slot.expires_at_ms {
            return false;
        }
        true
    });
    while g.len() >= MAX_SERVE_SLOTS {
        // Drop the soonest-to-expire (or already-stale) entry to make room.
        let victim = g
            .iter()
            .min_by_key(|(_, s)| {
                if s.expires_at_ms > 0 {
                    s.expires_at_ms
                } else {
                    i64::MAX
                }
            })
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                g.remove(&k);
            }
            None => break,
        }
    }
}

fn prune_offer_entries(g: &mut HashMap<String, AttachmentOfferMeta>, now: i64) {
    g.retain(|_, meta| meta.expires_at_ms <= 0 || now <= meta.expires_at_ms);
    while g.len() >= MAX_OFFER_ENTRIES {
        let victim = g
            .iter()
            .min_by_key(|(_, m)| {
                if m.expires_at_ms > 0 {
                    m.expires_at_ms
                } else {
                    i64::MAX
                }
            })
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                g.remove(&k);
            }
            None => break,
        }
    }
}

pub fn attachment_preview(file_name: &str) -> String {
    format!("📎 {}", file_name.trim().if_empty("file"))
}

trait IfEmpty {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl IfEmpty for str {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.is_empty() { fallback } else { self }
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn attach_root(app_namespace: &str) -> Result<PathBuf, String> {
    let cfg = crate::app_paths::storage_config_for_namespace(app_namespace);
    let mut p = crate::app_paths::ui_data_dir(&cfg).map_err(|e| e.to_string())?;
    p.push("attach");
    fs::create_dir_all(&p).map_err(|e| format!("attach dir: {e}"))?;
    Ok(p)
}

/// Copy picker bytes to `{attach}/outgoing/{unique}/{name}` so the file keeps its name.
#[cfg(target_os = "android")]
pub fn stage_picked_file(app_namespace: &str, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let mut p = attach_root(app_namespace)?;
    p.push("outgoing");
    p.push(format!("{}-{:08x}", now_ms(), OsRng.next_u32()));
    fs::create_dir_all(&p).map_err(|e| format!("attach outgoing dir: {e}"))?;
    p.push(sanitize_file_name(name));
    fs::write(&p, bytes).map_err(|e| format!("attach copy: {e}"))?;
    Ok(p)
}

fn downloads_root(app_namespace: &str) -> Result<PathBuf, String> {
    let mut p = attach_root(app_namespace)?;
    p.push("downloads");
    fs::create_dir_all(&p).map_err(|e| format!("attach downloads dir: {e}"))?;
    Ok(p)
}

/// Mailbox / LAN-DM inner (plaintext before identity seal) — carries the file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttachmentInner {
    pub attachment_version: u32,
    pub file_name: String,
    pub mime_type: String,
    pub size_plaintext: u64,
    pub sha256_plaintext: String,
    pub file_b64: String,
}

impl AttachmentInner {
    pub fn validate(&self) -> Result<(), String> {
        if self.attachment_version != ATTACH_MSG_VERSION {
            return Err(format!(
                "unsupported attachment_version={}",
                self.attachment_version
            ));
        }
        let name = self.file_name.trim();
        if name.is_empty() {
            return Err("attachment file_name empty".to_string());
        }
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
            return Err("attachment file_name invalid".to_string());
        }
        if self.file_b64.trim().is_empty() {
            return Err("attachment file_b64 empty".to_string());
        }
        if self.size_plaintext == 0 {
            return Err("attachment size_plaintext must be > 0".to_string());
        }
        if self.size_plaintext > MAX_FILE_SIZE_BYTES {
            return Err(format!(
                "attachment size_plaintext exceeds {MAX_FILE_SIZE_BYTES} bytes"
            ));
        }
        if self.file_name.chars().count() > 512 {
            return Err("attachment file_name too long".to_string());
        }
        if self.sha256_plaintext.trim().is_empty() {
            return Err("attachment sha256_plaintext empty".to_string());
        }
        Ok(())
    }

    pub fn file_bytes(&self) -> Result<Vec<u8>, String> {
        // Reject pathological base64 before allocating decoded buffer.
        let b64_len = self.file_b64.trim().len();
        if b64_len > (MAX_FILE_SIZE_BYTES as usize) * 2 {
            return Err("attachment file_b64 too large".to_string());
        }
        let plain = B64
            .decode(self.file_b64.trim())
            .map_err(|e| format!("file_b64: {e}"))?;
        if plain.len() as u64 != self.size_plaintext {
            return Err("attachment size mismatch".to_string());
        }
        let hash = hex::encode(Sha256::digest(&plain));
        if hash != self.sha256_plaintext.trim() {
            return Err("attachment sha256 mismatch".to_string());
        }
        Ok(plain)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|e| format!("attachment inner json: {e}"))?;
        if bytes.len() > ATTACH_MAX_SEALED_INNER_BYTES {
            return Err(format!(
                "attachment exceeds mailbox limit ({} bytes max sealed inner)",
                ATTACH_MAX_SEALED_INNER_BYTES
            ));
        }
        Ok(bytes)
    }

    pub fn to_json_value(&self) -> Result<Value, String> {
        let bytes = self.to_json_bytes()?;
        serde_json::from_slice(&bytes).map_err(|e| format!("attachment inner value: {e}"))
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ATTACH_MAX_SEALED_INNER_BYTES {
            return Err("attachment inner too large".to_string());
        }
        let inner: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("attachment inner json: {e}"))?;
        inner.validate()?;
        let _ = inner.file_bytes()?;
        Ok(inner)
    }

    pub fn from_json_value(v: &Value) -> Result<Self, String> {
        let bytes = serde_json::to_vec(v).map_err(|e| format!("attachment value: {e}"))?;
        Self::from_json_bytes(&bytes)
    }

    /// True when this JSON carries file bytes (mailbox), not a LAN mux offer.
    pub fn is_mailbox_payload(v: &Value) -> bool {
        v.get("file_b64")
            .and_then(|x| x.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    }
}

/// Pack a local file into a sealed-inner JSON for delivery or LAN DM.
pub fn pack_attachment_for_mailbox(
    file_path: &Path,
    file_name: &str,
    mime_type: &str,
) -> Result<AttachmentInner, String> {
    let meta = fs::metadata(file_path).map_err(|e| format!("file metadata: {e}"))?;
    if !meta.is_file() {
        return Err("attachment path is not a file".to_string());
    }
    if meta.len() > (ATTACH_MAX_SEALED_INNER_BYTES as u64 * 3 / 4) {
        return Err(format!(
            "attachment too large for mailbox (max ~{} MB sealed; LAN peers can send larger files)",
            ATTACH_MAX_SEALED_INNER_BYTES / (1024 * 1024)
        ));
    }
    let plain = fs::read(file_path).map_err(|e| format!("read attachment: {e}"))?;
    if plain.len() as u64 != meta.len() {
        return Err("attachment changed while reading".to_string());
    }
    if plain.is_empty() {
        return Err("attachment is empty".to_string());
    }
    let clean_name = file_name.trim().if_empty("file").to_string();
    let clean_mime = mime_type
        .trim()
        .if_empty("application/octet-stream")
        .to_string();
    let inner = AttachmentInner {
        attachment_version: ATTACH_MSG_VERSION,
        file_name: clean_name,
        mime_type: clean_mime,
        size_plaintext: plain.len() as u64,
        sha256_plaintext: hex::encode(Sha256::digest(&plain)),
        file_b64: B64.encode(&plain),
    };
    let _ = inner.to_json_bytes()?;
    Ok(inner)
}

pub fn write_attachment_file(
    app_namespace: &str,
    message_id: &str,
    file_name: &str,
    plain: &[u8],
) -> Result<String, String> {
    let mut path = downloads_root(app_namespace)?;
    path.push(format!(
        "{}-{}",
        sanitize_download_stem(message_id)?,
        sanitize_file_name(file_name)
    ));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create download dir: {e}"))?;
    }
    fs::write(&path, plain).map_err(|e| format!("write download: {e}"))?;
    Ok(path.to_string_lossy().to_string())
}

/// LAN mux only: encrypt + serve ciphertext for oversized local-network transfers.
pub fn stage_file_for_offer(
    app_namespace: &str,
    expected_peer: &str,
    blob_id: &str,
    file_path: &Path,
    file_name: &str,
    mime_type: &str,
) -> Result<StagedAttachment, String> {
    let meta = fs::metadata(file_path).map_err(|e| format!("file metadata: {e}"))?;
    if !meta.is_file() {
        return Err("attachment path is not a file".to_string());
    }
    if meta.len() > MAX_FILE_SIZE_BYTES {
        return Err(format!("attachment exceeds {} bytes", MAX_FILE_SIZE_BYTES));
    }
    let plain = fs::read(file_path).map_err(|e| format!("read attachment: {e}"))?;
    if plain.len() as u64 != meta.len() {
        return Err("attachment changed while reading".to_string());
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let sha256_plaintext = hex::encode(Sha256::digest(&plain));
    let sealed = crate::symmetric_seal::seal_symmetric(&key, &plain)?;
    let mut out = attach_root(app_namespace)?;
    out.push(format!("{blob_id}.bin"));
    fs::write(&out, &sealed).map_err(|e| format!("write attachment ciphertext: {e}"))?;
    let expires_at_ms = now_ms().saturating_add(DEFAULT_TTL_MS);
    let clean_name = file_name.trim().if_empty("file").to_string();
    let clean_mime = mime_type
        .trim()
        .if_empty("application/octet-stream")
        .to_string();
    let offer_json = json!({
        "attachment_version": 1,
        "blob_id": blob_id,
        "file_name": clean_name,
        "mime_type": clean_mime,
        "size_plaintext": meta.len(),
        "sha256_plaintext": sha256_plaintext,
        "content_key_b64": B64.encode(key),
        "expires_at_ms": expires_at_ms,
    });
    let slot = ServeSlot {
        path: out,
        content_key: key,
        sha256_plaintext,
        expires_at_ms,
        expected_peer: expected_peer.trim().to_string(),
        state: ServeState::Serving,
    };
    {
        let mut g = serve_mx()
            .lock()
            .map_err(|_| "serve table lock poisoned".to_string())?;
        prune_serve_slots(&mut g, now_ms());
        if g.len() >= MAX_SERVE_SLOTS {
            return Err("too many attachments serving".to_string());
        }
        g.insert(blob_id.to_string(), slot);
    }
    Ok(StagedAttachment {
        blob_id: blob_id.to_string(),
        preview: attachment_preview(&clean_name),
        file_name: clean_name,
        mime_type: clean_mime,
        size_plaintext: meta.len(),
        offer_json,
    })
}

pub fn remember_offer(meta: AttachmentOfferMeta) {
    if meta.blob_id.trim().is_empty() || meta.content_key_b64.trim().is_empty() {
        return;
    }
    if let Ok(mut g) = offers_mx().lock() {
        prune_offer_entries(&mut g, now_ms());
        // Two keys per offer; leave headroom so both inserts succeed under the cap.
        while g.len() + 2 > MAX_OFFER_ENTRIES {
            let victim = g.keys().next().cloned();
            match victim {
                Some(k) => {
                    g.remove(&k);
                }
                None => break,
            }
        }
        g.insert(meta.id.clone(), meta.clone());
        g.insert(meta.blob_id.clone(), meta);
    }
}

pub fn offer_for_id(id: &str) -> Option<AttachmentOfferMeta> {
    offers_mx().lock().ok()?.get(id.trim()).cloned()
}

pub fn build_fetch_request(blob_id: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "action": "fetch",
        "blob_id": blob_id,
        "offset": 0,
        "protocol": ATTACH_PROTOCOL,
    }))
    .unwrap_or_default()
}

pub fn serve_fetch_frames(peer: &str, blob_id: &str, offset: u64) -> Vec<Vec<u8>> {
    let slot = match serve_mx().lock().ok().and_then(|g| g.get(blob_id).cloned()) {
        Some(s) => s,
        None => return vec![error_frame(blob_id, "not_found")],
    };
    if !crate::public_key_util::same_contact_pk(peer, &slot.expected_peer) {
        return vec![error_frame(blob_id, "forbidden")];
    }
    if slot.expires_at_ms > 0 && now_ms() > slot.expires_at_ms {
        if let Ok(mut g) = serve_mx().lock() {
            if let Some(s) = g.get_mut(blob_id) {
                s.state = ServeState::Expired;
            }
        }
        return vec![error_frame(blob_id, "expired")];
    }
    if slot.state != ServeState::Serving {
        return vec![error_frame(blob_id, "not_serving")];
    }
    if slot.content_key.iter().all(|b| *b == 0) || slot.sha256_plaintext.trim().is_empty() {
        return vec![error_frame(blob_id, "corrupt_slot")];
    }
    let ciphertext = match fs::read(&slot.path) {
        Ok(b) => b,
        Err(_) => return vec![error_frame(blob_id, "not_found")],
    };
    let mut frames = Vec::new();
    let start = (offset as usize).min(ciphertext.len());
    for (idx, chunk) in ciphertext[start..].chunks(CHUNK_SIZE_BYTES).enumerate() {
        let off = start + idx * CHUNK_SIZE_BYTES;
        frames.push(json_frame(&json!({
            "action": "chunk",
            "blob_id": blob_id,
            "offset": off,
            "data_b64": B64.encode(chunk),
            "final": off + chunk.len() >= ciphertext.len(),
        })));
    }
    frames.push(json_frame(&json!({
        "action": "complete",
        "blob_id": blob_id,
        "sha256_ciphertext": hex::encode(Sha256::digest(&ciphertext)),
    })));
    frames
}

fn json_frame(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

fn error_frame(blob_id: &str, code: &str) -> Vec<u8> {
    json_frame(&json!({ "action": "error", "blob_id": blob_id, "code": code }))
}

/// Register a pending fetch and build the request frame.
///
/// Returns `(blob_id, request_frame)`. The caller owns delivery of the frame and
/// **must** call [`fail_fetch`] if it cannot put it on the wire — otherwise the
/// waiter on `done` is never signalled.
pub fn start_fetch(
    app_namespace: &str,
    peer: &str,
    offer_id: &str,
    save_path: Option<&str>,
    done: std::sync::mpsc::Sender<Result<String, String>>,
) -> Result<(String, Vec<u8>), String> {
    let offer = offer_for_id(offer_id).ok_or_else(|| "attachment offer not found".to_string())?;
    if !crate::public_key_util::same_contact_pk(peer, &offer.sender_public_key_hex) {
        return Err("attachment offer sender mismatch".to_string());
    }
    if offer.expires_at_ms > 0 && now_ms() > offer.expires_at_ms {
        return Err("attachment offer expired".to_string());
    }
    let path = match save_path.map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => {
            let path = PathBuf::from(p);
            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err("attachment save path invalid".to_string());
            }
            path
        }
        None => {
            let mut p = downloads_root(app_namespace)?;
            p.push(format!(
                "{}-{:08x}-{}",
                offer.blob_id,
                OsRng.next_u32(),
                sanitize_file_name(&offer.file_name)
            ));
            p
        }
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create download dir: {e}"))?;
    }
    let blob_id = offer.blob_id.clone();
    {
        let mut g = fetch_mx()
            .lock()
            .map_err(|_| "fetch table lock poisoned".to_string())?;
        if g.contains_key(&blob_id) {
            return Err("attachment fetch already in progress".to_string());
        }
        if g.len() >= MAX_FETCH_INFLIGHT {
            return Err("too many attachment fetches in progress".to_string());
        }
        g.insert(
            blob_id.clone(),
            FetchState {
                peer: peer.to_string(),
                offer,
                ciphertext: Vec::new(),
                save_path: path,
                done,
            },
        );
    }
    let req = build_fetch_request(&blob_id);
    Ok((blob_id, req))
}

/// Drop a pending fetch and report the failure to whoever is waiting on it.
pub fn fail_fetch(blob_id: &str, error: &str) -> bool {
    let Ok(mut g) = fetch_mx().lock() else {
        return false;
    };
    match g.remove(blob_id.trim()) {
        Some(st) => {
            let _ = st.done.send(Err(error.to_string()));
            true
        }
        None => false,
    }
}

const MAX_SANITIZED_FILE_NAME_CHARS: usize = 200;

fn is_windows_reserved_stem(stem: &str) -> bool {
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub(crate) fn sanitize_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '\0' | '<' | '>' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            _ => c,
        })
        .take(MAX_SANITIZED_FILE_NAME_CHARS)
        .collect();
    let trimmed = cleaned.trim().trim_end_matches(['.', ' ']);
    // Bare `.` / `..` would climb out of the unique staging directory on Path::push.
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "file".to_string();
    }
    // Windows reserved device names break create/open even under a unique parent dir.
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    if is_windows_reserved_stem(stem) {
        return format!("_{trimmed}");
    }
    trimmed.to_string()
}

pub fn handle_fetch_response(peer: &str, payload: &[u8]) -> Option<(String, String)> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
    let blob_id = v
        .get("blob_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim();
    if blob_id.is_empty() {
        return None;
    }
    match action {
        "chunk" => {
            let data = v.get("data_b64").and_then(|x| x.as_str()).unwrap_or("");
            let chunk = B64.decode(data.trim()).ok()?;
            // Reject absurd single chunks (wire DoS) before touching the buffer.
            if chunk.len() > CHUNK_SIZE_BYTES.saturating_mul(2) {
                if let Ok(mut g) = fetch_mx().lock() {
                    if let Some(st) = g.remove(blob_id) {
                        let _ = st.done.send(Err("attachment chunk too large".into()));
                    }
                }
                return None;
            }
            let offset = v.get("offset").and_then(|x| x.as_u64()).unwrap_or(0);
            let offset = usize::try_from(offset).ok()?;
            if let Ok(mut g) = fetch_mx().lock() {
                if let Some(st) = g.get_mut(blob_id) {
                    if !crate::public_key_util::same_contact_pk(peer, &st.peer) {
                        return None;
                    }
                    if offset != st.ciphertext.len() {
                        let st = g.remove(blob_id)?;
                        let _ = st.done.send(Err("attachment chunk offset mismatch".into()));
                        return None;
                    }
                    // Ciphertext ≈ plaintext + AEAD overhead; never grow past the offer.
                    let cap = (st.offer.size_plaintext as usize)
                        .saturating_add(64)
                        .min(MAX_FILE_SIZE_BYTES as usize + 64);
                    if st.ciphertext.len().saturating_add(chunk.len()) > cap {
                        let st = g.remove(blob_id)?;
                        let _ = st
                            .done
                            .send(Err("attachment ciphertext exceeds offer size".into()));
                        return None;
                    }
                    st.ciphertext.extend_from_slice(&chunk);
                }
            }
            None
        }
        "complete" => complete_fetch(blob_id).ok().flatten(),
        "error" => {
            let code = v.get("code").and_then(|x| x.as_str()).unwrap_or("error");
            if let Ok(mut g) = fetch_mx().lock() {
                if let Some(st) = g.remove(blob_id) {
                    let _ = st.done.send(Err(code.to_string()));
                }
            }
            None
        }
        _ => None,
    }
}

fn complete_fetch(blob_id: &str) -> Result<Option<(String, String)>, String> {
    let st = fetch_mx()
        .lock()
        .map_err(|_| "fetch table lock poisoned".to_string())?
        .remove(blob_id)
        .ok_or_else(|| "fetch not active".to_string())?;
    let key_vec = B64
        .decode(st.offer.content_key_b64.trim())
        .map_err(|e| format!("content key b64: {e}"))?;
    let key: [u8; 32] = key_vec
        .try_into()
        .map_err(|_| "content key length".to_string())?;
    let plain = match crate::symmetric_seal::open_symmetric(&key, &st.ciphertext) {
        Ok(p) => p,
        Err(e) => {
            let _ = st.done.send(Err(e.clone()));
            return Err(e);
        }
    };
    let hash = hex::encode(Sha256::digest(&plain));
    if hash != st.offer.sha256_plaintext {
        let e = "attachment sha256 mismatch".to_string();
        let _ = st.done.send(Err(e.clone()));
        return Err(e);
    }
    if plain.len() as u64 != st.offer.size_plaintext {
        let e = "attachment size mismatch".to_string();
        let _ = st.done.send(Err(e.clone()));
        return Err(e);
    }
    let _mime_type = st.offer.mime_type.trim();
    fs::write(&st.save_path, &plain).map_err(|e| format!("write download: {e}"))?;
    let local_path = st.save_path.to_string_lossy().to_string();
    let _ = st.done.send(Ok(local_path.clone()));
    Ok(Some((st.offer.id, local_path)))
}

pub fn complete_serve(blob_id: &str, peer: &str) -> bool {
    let Ok(mut g) = serve_mx().lock() else {
        return false;
    };
    let Some(slot) = g.get_mut(blob_id) else {
        return false;
    };
    if !crate::public_key_util::same_contact_pk(peer, &slot.expected_peer) {
        return false;
    }
    slot.state = ServeState::Complete;
    true
}

pub fn cancel_serve(blob_id: &str) -> bool {
    let Ok(mut g) = serve_mx().lock() else {
        return false;
    };
    if let Some(slot) = g.get_mut(blob_id) {
        slot.state = ServeState::Cancelled;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_and_hash_verify() {
        let key = [9u8; 32];
        let plain = b"hello attachment";
        let sealed = crate::symmetric_seal::seal_symmetric(&key, plain).unwrap();
        let opened = crate::symmetric_seal::open_symmetric(&key, &sealed).unwrap();
        assert_eq!(opened, plain);
        assert_eq!(
            hex::encode(Sha256::digest(&opened)),
            hex::encode(Sha256::digest(plain))
        );
    }

    #[test]
    fn hash_verify_rejects_tamper() {
        let expected = hex::encode(Sha256::digest(b"good"));
        let got = hex::encode(Sha256::digest(b"bad"));
        assert_ne!(expected, got);
    }

    #[test]
    fn mailbox_pack_roundtrip_hash() {
        let dir = std::env::temp_dir().join(format!("ghal_attach_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("note.txt");
        fs::write(&path, b"hello attachment mailbox").unwrap();
        let inner = pack_attachment_for_mailbox(&path, "note.txt", "text/plain").unwrap();
        assert_eq!(inner.attachment_version, ATTACH_MSG_VERSION);
        let plain = inner.file_bytes().unwrap();
        assert_eq!(plain, b"hello attachment mailbox");
        let _ = fs::remove_dir_all(&dir);
        inner.validate().unwrap();
    }

    #[test]
    fn validate_rejects_oversize_and_long_name() {
        let mut inner = AttachmentInner {
            attachment_version: ATTACH_MSG_VERSION,
            file_name: "ok.txt".into(),
            mime_type: "text/plain".into(),
            size_plaintext: MAX_FILE_SIZE_BYTES + 1,
            sha256_plaintext: "ab".repeat(32),
            file_b64: "YQ==".into(),
        };
        assert!(inner.validate().is_err());
        inner.size_plaintext = 1;
        inner.file_name = "x".repeat(513);
        assert!(inner.validate().is_err());
        inner.file_name = "../x".into();
        assert!(inner.validate().is_err());
    }

    #[test]
    fn sanitize_file_name_blocks_path_climb() {
        assert_eq!(sanitize_file_name(".."), "file");
        assert_eq!(sanitize_file_name("."), "file");
        assert_eq!(sanitize_file_name("../secret"), ".._secret");
        assert_eq!(sanitize_file_name("a/b\\c:d"), "a_b_c_d");
        assert_eq!(sanitize_file_name("  "), "file");
        let long = "n".repeat(MAX_SANITIZED_FILE_NAME_CHARS + 50);
        assert_eq!(
            sanitize_file_name(&long).chars().count(),
            MAX_SANITIZED_FILE_NAME_CHARS
        );
        assert_eq!(sanitize_file_name("NUL"), "_NUL");
        assert_eq!(sanitize_file_name("con.txt"), "_con.txt");
        assert_eq!(sanitize_file_name("ok?.bin"), "ok_.bin");
    }

    #[test]
    fn validate_rejects_empty_filename() {
        let inner = AttachmentInner {
            attachment_version: ATTACH_MSG_VERSION,
            file_name: "   ".into(),
            mime_type: "text/plain".into(),
            size_plaintext: 1,
            sha256_plaintext: hex::encode(Sha256::digest(b"a")),
            file_b64: B64.encode(b"a"),
        };
        assert!(inner.validate().is_err());
    }

    #[test]
    fn write_attachment_rejects_path_climb_message_id() {
        let err = write_attachment_file(
            "com.ghalbol.debug",
            "../escape",
            "safe.txt",
            b"x",
        )
        .unwrap_err();
        assert!(err.contains("download id"));
    }

    fn test_peer_hex() -> String {
        use secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let seed = [7u8; 32];
        let sk = SecretKey::from_byte_array(seed).unwrap();
        hex::encode(sk.public_key(&secp).serialize())
    }

    #[test]
    fn fetch_rejects_concurrent_duplicate_and_bad_offset() {
        let peer = test_peer_hex();
        let offer_id = format!("offer-{}", OsRng.next_u32());
        let blob_id = format!("blob-{}", OsRng.next_u32());
        remember_offer(AttachmentOfferMeta {
            id: offer_id.clone(),
            sender_public_key_hex: peer.clone(),
            blob_id: blob_id.clone(),
            file_name: "x.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_plaintext: 1024,
            sha256_plaintext: "00".repeat(32),
            content_key_b64: B64.encode([0u8; 32]),
            expires_at_ms: now_ms().saturating_add(60_000),
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        start_fetch(
            "com.ghalbol.debug",
            &peer,
            &offer_id,
            None,
            done_tx,
        )
        .unwrap();
        let (done_tx2, _) = std::sync::mpsc::channel();
        assert_eq!(
            start_fetch("com.ghalbol.debug", &peer, &offer_id, None, done_tx2)
                .unwrap_err(),
            "attachment fetch already in progress"
        );
        let chunk0 = json_frame(&json!({
            "action": "chunk",
            "blob_id": blob_id,
            "offset": 0,
            "data_b64": B64.encode(b"abc"),
        }));
        assert!(handle_fetch_response(&peer, &chunk0).is_none());
        let bad_off = json_frame(&json!({
            "action": "chunk",
            "blob_id": blob_id,
            "offset": 0,
            "data_b64": B64.encode(b"xyz"),
        }));
        assert!(handle_fetch_response(&peer, &bad_off).is_none());
        assert_eq!(
            done_rx.recv().unwrap().unwrap_err(),
            "attachment chunk offset mismatch"
        );
    }

    #[test]
    fn fetch_oversized_chunk_aborts() {
        let peer = test_peer_hex();
        let offer_id = format!("offer-{}", OsRng.next_u32());
        let blob_id = format!("blob-{}", OsRng.next_u32());
        remember_offer(AttachmentOfferMeta {
            id: offer_id.clone(),
            sender_public_key_hex: peer.clone(),
            blob_id: blob_id.clone(),
            file_name: "y.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_plaintext: 64,
            sha256_plaintext: "11".repeat(32),
            content_key_b64: B64.encode([1u8; 32]),
            expires_at_ms: now_ms().saturating_add(60_000),
        });
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        start_fetch("com.ghalbol.debug", &peer, &offer_id, None, done_tx).unwrap();
        let huge = vec![0u8; CHUNK_SIZE_BYTES.saturating_mul(2) + 1];
        let oversize_frame = json_frame(&json!({
            "action": "chunk",
            "blob_id": blob_id,
            "offset": 0,
            "data_b64": B64.encode(&huge),
        }));
        assert!(handle_fetch_response(&peer, &oversize_frame).is_none());
        assert_eq!(
            done_rx.recv().unwrap().unwrap_err(),
            "attachment chunk too large"
        );
    }

    #[test]
    fn offer_table_evicts_expired_and_stays_capped() {
        let peer = test_peer_hex();
        let now = now_ms();
        // Fill past the cap with already-expired offers; prune should drop them.
        for i in 0..(MAX_OFFER_ENTRIES + 8) {
            remember_offer(AttachmentOfferMeta {
                id: format!("cap-offer-{i}"),
                sender_public_key_hex: peer.clone(),
                blob_id: format!("cap-blob-{i}"),
                file_name: "z.bin".into(),
                mime_type: "application/octet-stream".into(),
                size_plaintext: 1,
                sha256_plaintext: "22".repeat(32),
                content_key_b64: B64.encode([2u8; 32]),
                expires_at_ms: now.saturating_sub(1_000),
            });
        }
        let len = offers_mx().lock().map(|g| g.len()).unwrap_or(usize::MAX);
        assert!(
            len <= MAX_OFFER_ENTRIES,
            "offer table grew past cap: {len}"
        );
        // Fresh offer still accepted after expiry sweep.
        remember_offer(AttachmentOfferMeta {
            id: "fresh-offer".into(),
            sender_public_key_hex: peer,
            blob_id: "fresh-blob".into(),
            file_name: "ok.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_plaintext: 1,
            sha256_plaintext: "33".repeat(32),
            content_key_b64: B64.encode([3u8; 32]),
            expires_at_ms: now.saturating_add(60_000),
        });
        assert!(offer_for_id("fresh-offer").is_some());
        assert!(offer_for_id("fresh-blob").is_some());
    }

    #[test]
    fn serve_table_drops_terminal_before_rejecting() {
        let mut g = HashMap::new();
        for i in 0..MAX_SERVE_SLOTS {
            g.insert(
                format!("blob-{i}"),
                ServeSlot {
                    path: PathBuf::from("/tmp/x"),
                    content_key: [0u8; 32],
                    sha256_plaintext: "aa".repeat(32),
                    expires_at_ms: now_ms().saturating_add(60_000),
                    expected_peer: "p".into(),
                    state: if i < 4 {
                        ServeState::Complete
                    } else {
                        ServeState::Serving
                    },
                },
            );
        }
        prune_serve_slots(&mut g, now_ms());
        assert!(g.len() < MAX_SERVE_SLOTS);
        assert!(g.values().all(|s| s.state == ServeState::Serving));
    }
}
