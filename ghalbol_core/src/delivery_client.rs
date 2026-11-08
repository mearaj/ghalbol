//! Persistent WebSocket client to `ghalbol_delivery`.
//!
//! URL comes from `GHALBOL_DELIVERY_URL` / `p2p_start` `delivery_url` (e.g. `wss://…` or
//! `ws://127.0.0.1:8770` on the delivery host). No DNS/loopback rewriting — set the URL you mean.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::delivery_auth::{
    extend_challenge_bytes, session_challenge_bytes, sign_delivery_challenge,
    upload_challenge_bytes,
};
use crate::delivery_msg_v1::{
    build_attachment_envelope, build_availability_envelope, build_text_envelope,
    build_voice_envelope,
};
use crate::p2p::native_log;
use crate::session_runtime::unlocked_identity_clone;

/// Matches coord HTTP `connect_timeout` in [`crate::coord::CoordHttpClient::new`].
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
/// Per-frame wait while expecting a typed JSON response (upload / inbox / auth).
const WS_RESPONSE_FRAME_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound push frames buffered while waiting for a typed reply (DoS / backlog).
const MAX_PREFETCHED_PUSH_FRAMES: usize = 512;
/// Matches `ghalbol_delivery` `DEFAULT_MAX_WS_MESSAGE_BYTES` — reject before JSON parse.
const MAX_WS_TEXT_FRAME_BYTES: usize = 12 * 1024 * 1024;
/// Matches `ghalbol_delivery::ws::process_frame` type cap.
const MAX_WS_FRAME_TYPE_LEN: usize = 64;
/// Reconnect wait cap when the delivery worker retries WSS (`delivery_runtime`).
pub const DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS: u64 = 60;

/// Exponential reconnect backoff with hard cap (pairs with `delivery_runtime` worker).
pub fn delivery_ws_reconnect_backoff_step(secs: u64) -> (u64, u64) {
    let wait = secs.min(DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS);
    let next = secs
        .saturating_mul(2)
        .min(DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS);
    (wait, next)
}

type WsWrite = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;
type WsRead = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

async fn open_ws(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
    let cfg = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_TEXT_FRAME_BYTES))
        .max_frame_size(Some(MAX_WS_TEXT_FRAME_BYTES));
    let (ws, _) = tokio_tungstenite::connect_async_with_config(url, Some(cfg), false)
        .await
        .map_err(|e| format!("ws connect: {e}"))?;
    Ok(ws)
}

pub fn ws_url_from_base(base: &str) -> String {
    let t = base.trim().trim_end_matches('/');
    if t.is_empty() {
        return String::new();
    }
    if t.ends_with("/v1/ws") {
        t.to_string()
    } else {
        format!("{t}/v1/ws")
    }
}

fn delivery_canceled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::SeqCst))
}

pub async fn connect_and_auth(
    url: &str,
    ident: &crate::DecryptedIdentity,
    cancel: Option<&'static AtomicBool>,
) -> Result<DeliverySession, String> {
    if delivery_canceled(cancel) {
        return Err("delivery stopped".into());
    }
    let wire = ident.identity_wire();
    native_log::info("delivery", format!("ws connecting url={url}"));
    let ws = tokio::time::timeout(WS_CONNECT_TIMEOUT, open_ws(url))
        .await
        .map_err(|_| {
            format!(
                "ws connect: timed out after {}s (url={url})",
                WS_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("ws connect: {e}"))?;
    if delivery_canceled(cancel) {
        return Err("delivery stopped".into());
    }
    let (mut write, mut read) = ws.split();

    write
        .send(Message::Text(
            json!({ "type": "session.open", "identity_wire": wire })
                .to_string()
                .into(),
        ))
        .await
        .map_err(|e| format!("ws send: {e}"))?;

    let mut prefetched = VecDeque::new();
    let challenge = recv_until_type(
        &mut read,
        &mut write,
        "session.challenge",
        &mut prefetched,
        cancel,
    )
    .await?;
    if delivery_canceled(cancel) {
        return Err("delivery stopped".into());
    }
    let nonce_hex = challenge
        .get("nonce_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing nonce_hex")?;
    let nonce = parse_nonce32(nonce_hex)?;
    let session_msg = session_challenge_bytes(&nonce, &wire)?;
    let sig = sign_delivery_challenge(ident, &session_msg)?;
    if delivery_canceled(cancel) {
        return Err("delivery stopped".into());
    }
    write
        .send(Message::Text(
            json!({
                "type": "session.auth",
                "identity_wire": wire,
                "nonce_hex": nonce_hex,
                "signature_hex": hex::encode(sig),
            })
            .to_string()
            .into(),
        ))
        .await
        .map_err(|e| format!("ws auth send: {e}"))?;

    let ready = recv_until_type(
        &mut read,
        &mut write,
        "session.ready",
        &mut prefetched,
        cancel,
    )
    .await?;
    native_log::info("delivery", "ws session.ready");
    let op_nonce_hex = match ready.get("op_nonce_hex").and_then(|v| v.as_str()) {
        Some(s) => {
            parse_nonce32(s)?;
            Some(s.to_string())
        }
        None => None,
    };
    Ok(DeliverySession {
        write,
        read,
        prefetched,
        op_nonce_hex,
        policy: ready.get("policy").cloned().unwrap_or(Value::Null),
        quota: ready.get("quota").cloned().unwrap_or(Value::Null),
        cancel,
    })
}

pub struct DeliverySession {
    write: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    read: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    /// Server may push `message.inbound` before `session.ready` is read — keep for `recv_push`.
    prefetched: VecDeque<Value>,
    pub op_nonce_hex: Option<String>,
    pub policy: Value,
    pub quota: Value,
    cancel: Option<&'static AtomicBool>,
}

impl DeliverySession {
    pub async fn upload_text(
        &mut self,
        ident: &crate::DecryptedIdentity,
        message_id: &str,
        recipient_wire: &str,
        text: &str,
        ttl_secs: Option<u64>,
    ) -> Result<Value, String> {
        let op_nonce_hex = self.op_nonce_hex.as_deref().ok_or("missing op_nonce_hex")?;
        let op_nonce = parse_nonce32(op_nonce_hex)?;
        let created_at_ms = now_ms();
        let envelope = build_text_envelope(ident, message_id, recipient_wire, text, created_at_ms)?;
        let recipient_norm = envelope
            .get("recipient_wire")
            .and_then(|v| v.as_str())
            .unwrap_or(recipient_wire);
        let upload_msg = upload_challenge_bytes(&op_nonce, message_id, recipient_norm)?;
        let sig = sign_delivery_challenge(ident, &upload_msg)?;
        let mut frame = json!({
            "type": "message.upload",
            "envelope": envelope,
            "op_nonce_hex": op_nonce_hex,
            "signature_hex": hex::encode(sig),
        });
        if let Some(ttl) = ttl_secs {
            frame["ttl_secs"] = json!(ttl);
        }
        self.write
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| format!("upload send: {e}"))?;
        let resp = recv_until_type(
            &mut self.read,
            &mut self.write,
            "message.upload.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        update_op_nonce_from_response(&mut self.op_nonce_hex, &resp);
        if let Some(q) = resp.get("quota") {
            self.quota = q.clone();
        }
        Ok(resp)
    }

    pub async fn upload_voice(
        &mut self,
        ident: &crate::DecryptedIdentity,
        message_id: &str,
        recipient_wire: &str,
        duration_ms: u32,
        opus_blob: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<Value, String> {
        let op_nonce_hex = self.op_nonce_hex.as_deref().ok_or("missing op_nonce_hex")?;
        let op_nonce = parse_nonce32(op_nonce_hex)?;
        let created_at_ms = now_ms();
        let envelope = build_voice_envelope(
            ident,
            message_id,
            recipient_wire,
            duration_ms,
            opus_blob,
            created_at_ms,
        )?;
        let recipient_norm = envelope
            .get("recipient_wire")
            .and_then(|v| v.as_str())
            .unwrap_or(recipient_wire);
        let upload_msg = upload_challenge_bytes(&op_nonce, message_id, recipient_norm)?;
        let sig = sign_delivery_challenge(ident, &upload_msg)?;
        let mut frame = json!({
            "type": "message.upload",
            "envelope": envelope,
            "op_nonce_hex": op_nonce_hex,
            "signature_hex": hex::encode(sig),
        });
        if let Some(ttl) = ttl_secs {
            frame["ttl_secs"] = json!(ttl);
        }
        self.write
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| format!("upload send: {e}"))?;
        let resp = recv_until_type(
            &mut self.read,
            &mut self.write,
            "message.upload.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        update_op_nonce_from_response(&mut self.op_nonce_hex, &resp);
        if let Some(q) = resp.get("quota") {
            self.quota = q.clone();
        }
        Ok(resp)
    }

    pub async fn upload_attachment(
        &mut self,
        ident: &crate::DecryptedIdentity,
        message_id: &str,
        recipient_wire: &str,
        inner: &crate::attach_v1::AttachmentInner,
        ttl_secs: Option<u64>,
    ) -> Result<Value, String> {
        let op_nonce_hex = self.op_nonce_hex.as_deref().ok_or("missing op_nonce_hex")?;
        let op_nonce = parse_nonce32(op_nonce_hex)?;
        let created_at_ms = now_ms();
        let envelope =
            build_attachment_envelope(ident, message_id, recipient_wire, inner, created_at_ms)?;
        let recipient_norm = envelope
            .get("recipient_wire")
            .and_then(|v| v.as_str())
            .unwrap_or(recipient_wire);
        let upload_msg = upload_challenge_bytes(&op_nonce, message_id, recipient_norm)?;
        let sig = sign_delivery_challenge(ident, &upload_msg)?;
        let mut frame = json!({
            "type": "message.upload",
            "envelope": envelope,
            "op_nonce_hex": op_nonce_hex,
            "signature_hex": hex::encode(sig),
        });
        if let Some(ttl) = ttl_secs {
            frame["ttl_secs"] = json!(ttl);
        }
        self.write
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| format!("upload send: {e}"))?;
        let resp = recv_until_type(
            &mut self.read,
            &mut self.write,
            "message.upload.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        update_op_nonce_from_response(&mut self.op_nonce_hex, &resp);
        if let Some(q) = resp.get("quota") {
            self.quota = q.clone();
        }
        Ok(resp)
    }

    pub async fn upload_availability(
        &mut self,
        ident: &crate::DecryptedIdentity,
        message_id: &str,
        recipient_wire: &str,
        status: &str,
        updated_at_ms: i64,
        ttl_secs: Option<u64>,
    ) -> Result<Value, String> {
        let op_nonce_hex = self.op_nonce_hex.as_deref().ok_or("missing op_nonce_hex")?;
        let op_nonce = parse_nonce32(op_nonce_hex)?;
        let created_at_ms = now_ms();
        let envelope = build_availability_envelope(
            ident,
            message_id,
            recipient_wire,
            status,
            updated_at_ms,
            created_at_ms,
        )?;
        let recipient_norm = envelope
            .get("recipient_wire")
            .and_then(|v| v.as_str())
            .unwrap_or(recipient_wire);
        let upload_msg = upload_challenge_bytes(&op_nonce, message_id, recipient_norm)?;
        let sig = sign_delivery_challenge(ident, &upload_msg)?;
        let mut frame = json!({
            "type": "message.upload",
            "envelope": envelope,
            "op_nonce_hex": op_nonce_hex,
            "signature_hex": hex::encode(sig),
        });
        if let Some(ttl) = ttl_secs {
            frame["ttl_secs"] = json!(ttl);
        }
        self.write
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| format!("upload send: {e}"))?;
        let resp = recv_until_type(
            &mut self.read,
            &mut self.write,
            "message.upload.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        update_op_nonce_from_response(&mut self.op_nonce_hex, &resp);
        if let Some(q) = resp.get("quota") {
            self.quota = q.clone();
        }
        Ok(resp)
    }

    pub async fn inbox_read(&mut self, message_id: &str, sender_wire: &str) -> Result<(), String> {
        self.write
            .send(Message::Text(
                json!({
                    "type": "inbox.read",
                    "message_id": message_id,
                    "sender_wire": sender_wire,
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|e| format!("read send: {e}"))?;
        let _ = recv_until_type(
            &mut self.read,
            &mut self.write,
            "inbox.read.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        Ok(())
    }

    pub async fn inbox_ack(&mut self, message_id: &str, sender_wire: &str) -> Result<(), String> {
        self.write
            .send(Message::Text(
                json!({
                    "type": "inbox.ack",
                    "message_id": message_id,
                    "sender_wire": sender_wire,
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|e| format!("ack send: {e}"))?;
        let _ = recv_until_type(
            &mut self.read,
            &mut self.write,
            "inbox.ack.ok",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        Ok(())
    }

    pub async fn mailbox_list(&mut self, include_expired: bool) -> Result<Value, String> {
        self.write
            .send(Message::Text(
                json!({
                    "type": "mailbox.outbox.list",
                    "include_expired": include_expired,
                })
                .to_string()
                .into(),
            ))
            .await
            .map_err(|e| format!("list send: {e}"))?;
        recv_until_type(
            &mut self.read,
            &mut self.write,
            "mailbox.outbox.snapshot",
            &mut self.prefetched,
            self.cancel,
        )
        .await
    }

    /// Extend TTL while the row is still `queued` (rejected once expired — client must resend).
    pub async fn extend_ttl(
        &mut self,
        ident: &crate::DecryptedIdentity,
        message_id: &str,
        extend_secs: u64,
    ) -> Result<Value, String> {
        let op_nonce_hex = self.op_nonce_hex.as_deref().ok_or("missing op_nonce_hex")?;
        let op_nonce = parse_nonce32(op_nonce_hex)?;
        let msg = extend_challenge_bytes(&op_nonce, message_id)?;
        let sig = sign_delivery_challenge(ident, &msg)?;
        let frame = json!({
            "type": "mailbox.ttl.extend",
            "message_id": message_id,
            "extend_secs": extend_secs,
            "op_nonce_hex": op_nonce_hex,
            "signature_hex": hex::encode(sig),
        });
        self.write
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|e| format!("extend send: {e}"))?;
        let resp = recv_until_type(
            &mut self.read,
            &mut self.write,
            "mailbox.ttl.extended",
            &mut self.prefetched,
            self.cancel,
        )
        .await?;
        update_op_nonce_from_response(&mut self.op_nonce_hex, &resp);
        Ok(resp)
    }


    pub async fn recv_push(&mut self) -> Result<Option<Value>, String> {
        if delivery_canceled(self.cancel) {
            return Err("delivery stopped".into());
        }
        if let Some(v) = self.prefetched.pop_front() {
            return Ok(Some(v));
        }
        tokio::select! {
            msg = self.read.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        let v = parse_ws_json_text(&t)?;
                        Ok(Some(v))
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = self.write.send(Message::Pong(p)).await;
                        Ok(None)
                    }
                    Some(Ok(Message::Binary(_))) => Err("ws binary frame".to_string()),
                    Some(Ok(Message::Close(_))) => Err("ws closed".to_string()),
                    Some(Err(e)) => Err(format!("ws read: {e}")),
                    None => Err("ws eof".to_string()),
                    _ => Ok(None),
                }
            }
        }
    }
}

fn parse_ws_json_text(text: &str) -> Result<Value, String> {
    if text.len() > MAX_WS_TEXT_FRAME_BYTES {
        return Err(format!(
            "ws text frame too large ({} bytes, max {})",
            text.len(),
            MAX_WS_TEXT_FRAME_BYTES
        ));
    }
    if !text.trim_start().starts_with('{') {
        return Err("ws json must be an object".to_string());
    }
    let v: Value = serde_json::from_str(text).map_err(|e| format!("json: {e}"))?;
    if !v.is_object() {
        return Err("ws json must be an object".to_string());
    }
    ws_json_type_key_valid(&v)?;
    Ok(v)
}

/// Reject malformed `type` before prefetch / typed wait loops (`ghalbol_delivery` caps at 64).
fn ws_json_type_key_valid(v: &Value) -> Result<(), String> {
    match v.get("type") {
        None => Ok(()),
        Some(Value::String(s)) if s.is_empty() => Ok(()),
        Some(Value::String(s)) if s.len() <= MAX_WS_FRAME_TYPE_LEN => Ok(()),
        Some(Value::String(s)) => Err(format!(
            "frame type too long ({} bytes, max {MAX_WS_FRAME_TYPE_LEN})",
            s.len()
        )),
        Some(_) => Err("frame type must be a string".to_string()),
    }
}

fn ws_json_type_str<'a>(v: &'a Value) -> Result<Option<&'a str>, String> {
    ws_json_type_key_valid(v)?;
    Ok(match v.get("type").and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    })
}

/// Drop oldest unrelated push while waiting for typed `protect` (never evict `protect`).
fn push_prefetch(prefetch: &mut VecDeque<Value>, frame: Value, protect: &str) {
    while prefetch.len() >= MAX_PREFETCHED_PUSH_FRAMES {
        if let Some(pos) = prefetch.iter().position(|v| {
            v.get("type").and_then(|x| x.as_str()) != Some(protect)
        }) {
            prefetch.remove(pos);
        } else {
            prefetch.pop_front();
        }
    }
    prefetch.push_back(frame);
}

fn update_op_nonce_from_response(op_nonce_hex: &mut Option<String>, frame: &Value) {
    if let Some(n) = frame.get("op_nonce_hex").and_then(|v| v.as_str()) {
        if let Ok(bytes) = parse_nonce32(n) {
            let canonical = hex::encode(bytes);
            if op_nonce_hex.as_deref() != Some(canonical.as_str()) {
                *op_nonce_hex = Some(canonical);
            }
        } else {
            native_log::warn(
                "delivery",
                format!("ignored invalid op_nonce_hex in response (kept prior nonce)"),
            );
        }
    }
}

/// Remove the first prefetched frame matching `want` without blocking on the socket.
fn take_typed_from_prefetch(prefetch: &mut VecDeque<Value>, want: &str) -> Option<Value> {
    let pos = prefetch.iter().position(|v| {
        matches!(ws_json_type_str(v), Ok(Some(ty)) if ty == want)
    })?;
    prefetch.remove(pos)
}

async fn wait_delivery_canceled(cancel: Option<&'static AtomicBool>) {
    loop {
        if delivery_canceled(cancel) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn ws_read_next_with_cancel(
    read: &mut WsRead,
    cancel: Option<&'static AtomicBool>,
) -> Result<Option<Result<Message, tokio_tungstenite::tungstenite::Error>>, String> {
    let timed = if cancel.is_some() {
        tokio::select! {
            () = wait_delivery_canceled(cancel) => {
                return Err("delivery stopped".into());
            }
            t = tokio::time::timeout(WS_RESPONSE_FRAME_TIMEOUT, read.next()) => t,
        }
    } else {
        tokio::time::timeout(WS_RESPONSE_FRAME_TIMEOUT, read.next()).await
    };
    timed.map_err(|_| {
        format!(
            "timed out waiting for ws frame ({}s)",
            WS_RESPONSE_FRAME_TIMEOUT.as_secs()
        )
    })
}

async fn recv_until_type(
    read: &mut WsRead,
    write: &mut WsWrite,
    want: &str,
    prefetch: &mut VecDeque<Value>,
    cancel: Option<&'static AtomicBool>,
) -> Result<Value, String> {
    for _ in 0..128 {
        if let Some(v) = take_typed_from_prefetch(prefetch, want) {
            return Ok(v);
        }
        if delivery_canceled(cancel) {
            return Err("delivery stopped".into());
        }
        let msg = match ws_read_next_with_cancel(read, cancel).await? {
            Some(Ok(m)) => m,
            Some(Err(e)) => return Err(format!("ws read: {e}")),
            None => return Err("ws closed while waiting for response".to_string()),
        };
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Ping(p) => {
                write
                    .send(Message::Pong(p))
                    .await
                    .map_err(|e| format!("ws pong: {e}"))?;
                continue;
            }
            Message::Binary(_) => return Err("ws binary frame".to_string()),
            Message::Close(_) => return Err("ws closed".to_string()),
            _ => continue,
        };
        let v = parse_ws_json_text(&text)?;
        let ty = ws_json_type_str(&v)?.unwrap_or("");
        if ty == "error" {
            return Err(v
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("delivery error")
                .to_string());
        }
        if ty == want {
            return Ok(v);
        }
        if !ty.is_empty() {
            push_prefetch(prefetch, v, want);
        }
    }
    Err(format!("too many unrelated frames waiting for {want}"))
}

fn parse_nonce32(hex_s: &str) -> Result<[u8; 32], String> {
    let s = hex_s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("nonce must be 32 bytes hex".to_string());
    }
    let bytes = hex::decode(s).map_err(|e| format!("nonce: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "nonce must be 32 bytes".to_string())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Runs delivery I/O on a dedicated std thread (safe from the delivery worker tokio runtime).
fn on_delivery_io_thread<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new()
        .name("delivery_io".into())
        .spawn(f)
        .map_err(|e| format!("spawn delivery_io: {e}"))?
        .join()
        .map_err(|_| "delivery_io thread panicked".to_string())?
}

/// Blocking upload for sync RPC paths (spawns short-lived connection).
pub fn blocking_upload_text(
    url: &str,
    recipient_wire: &str,
    text: &str,
    message_id: &str,
    ttl_secs: Option<u64>,
) -> Result<Value, String> {
    let url = url.to_string();
    let recipient_wire = recipient_wire.to_string();
    let text = text.to_string();
    let message_id = message_id.to_string();
    on_delivery_io_thread(move || {
        crate::rustls_init::ensure_rustls_crypto_provider();
        let ws_url = ws_url_from_base(&url);
        let ident = unlocked_identity_clone().map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio: {e}"))?;
        rt.block_on(async {
            let mut session = connect_and_auth(&ws_url, &ident, None).await?;
            session
                .upload_text(&ident, &message_id, &recipient_wire, &text, ttl_secs)
                .await
        })
    })
}

pub fn blocking_upload_voice(
    url: &str,
    recipient_wire: &str,
    duration_ms: u32,
    opus_blob: &[u8],
    message_id: &str,
    ttl_secs: Option<u64>,
) -> Result<Value, String> {
    let url = url.to_string();
    let recipient_wire = recipient_wire.to_string();
    let opus_blob = opus_blob.to_vec();
    let message_id = message_id.to_string();
    on_delivery_io_thread(move || {
        crate::rustls_init::ensure_rustls_crypto_provider();
        let ws_url = ws_url_from_base(&url);
        let ident = unlocked_identity_clone().map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio: {e}"))?;
        rt.block_on(async {
            let mut session = connect_and_auth(&ws_url, &ident, None).await?;
            session
                .upload_voice(
                    &ident,
                    &message_id,
                    &recipient_wire,
                    duration_ms,
                    &opus_blob,
                    ttl_secs,
                )
                .await
        })
    })
}

pub fn blocking_upload_attachment(
    url: &str,
    recipient_wire: &str,
    inner: &crate::attach_v1::AttachmentInner,
    message_id: &str,
    ttl_secs: Option<u64>,
) -> Result<Value, String> {
    let url = url.to_string();
    let recipient_wire = recipient_wire.to_string();
    let inner = inner.clone();
    let message_id = message_id.to_string();
    on_delivery_io_thread(move || {
        crate::rustls_init::ensure_rustls_crypto_provider();
        let ws_url = ws_url_from_base(&url);
        let ident = unlocked_identity_clone().map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio: {e}"))?;
        rt.block_on(async {
            let mut session = connect_and_auth(&ws_url, &ident, None).await?;
            session
                .upload_attachment(&ident, &message_id, &recipient_wire, &inner, ttl_secs)
                .await
        })
    })
}

pub fn blocking_upload_availability(
    url: &str,
    recipient_wire: &str,
    status: &str,
    updated_at_ms: i64,
    message_id: &str,
    ttl_secs: Option<u64>,
) -> Result<Value, String> {
    let url = url.to_string();
    let recipient_wire = recipient_wire.to_string();
    let status = status.to_string();
    let message_id = message_id.to_string();
    on_delivery_io_thread(move || {
        crate::rustls_init::ensure_rustls_crypto_provider();
        let ws_url = ws_url_from_base(&url);
        let ident = unlocked_identity_clone().map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio: {e}"))?;
        rt.block_on(async {
            let mut session = connect_and_auth(&ws_url, &ident, None).await?;
            session
                .upload_availability(
                    &ident,
                    &message_id,
                    &recipient_wire,
                    &status,
                    updated_at_ms,
                    ttl_secs,
                )
                .await
        })
    })
}

/// Fire-and-forget inbox read receipt on a fresh connection.
pub fn blocking_inbox_read(url: &str, message_id: &str, sender_wire: &str) -> Result<(), String> {
    let url = url.to_string();
    let message_id = message_id.to_string();
    let sender_wire = sender_wire.to_string();
    on_delivery_io_thread(move || {
        crate::rustls_init::ensure_rustls_crypto_provider();
        let ws_url = ws_url_from_base(&url);
        let ident = unlocked_identity_clone().map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio: {e}"))?;
        rt.block_on(async {
            let mut session = connect_and_auth(&ws_url, &ident, None).await?;
            session.inbox_read(&message_id, &sender_wire).await
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use serde_json::json;

    use super::{
        delivery_ws_reconnect_backoff_step, parse_nonce32, parse_ws_json_text, push_prefetch,
        take_typed_from_prefetch, update_op_nonce_from_response, ws_json_type_key_valid,
        ws_url_from_base, DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS, MAX_PREFETCHED_PUSH_FRAMES,
        MAX_WS_FRAME_TYPE_LEN, MAX_WS_TEXT_FRAME_BYTES,
    };

    #[test]
    fn take_typed_from_prefetch_returns_matching_without_socket() {
        let mut q = VecDeque::from([
            json!({"type": "message.inbound", "message_id": "a"}),
            json!({"type": "inbox.ack.ok", "message_id": "a"}),
        ]);
        let ack = take_typed_from_prefetch(&mut q, "inbox.ack.ok").expect("found");
        assert_eq!(
            ack.get("type").and_then(|v| v.as_str()),
            Some("inbox.ack.ok")
        );
        assert_eq!(q.len(), 1);
        assert!(take_typed_from_prefetch(&mut q, "inbox.ack.ok").is_none());
    }

    #[test]
    fn update_op_nonce_ignores_invalid_hex() {
        let mut nonce = Some("ab".repeat(32));
        let bad = json!({"op_nonce_hex": "not-hex"});
        update_op_nonce_from_response(&mut nonce, &bad);
        assert_eq!(nonce.as_deref(), Some("ab".repeat(32).as_str()));
        let good = json!({"op_nonce_hex": "CD".repeat(32)});
        update_op_nonce_from_response(&mut nonce, &good);
        assert_eq!(nonce.as_deref(), Some("cd".repeat(32).as_str()));
        update_op_nonce_from_response(&mut nonce, &good);
        assert_eq!(nonce.as_deref(), Some("cd".repeat(32).as_str()), "idempotent");
    }

    #[test]
    fn ws_url_from_base_appends_v1_ws() {
        assert_eq!(
            ws_url_from_base("wss://delivery.ghalbol.com:55003"),
            "wss://delivery.ghalbol.com:55003/v1/ws"
        );
        assert_eq!(
            ws_url_from_base("wss://delivery.ghalbol.com:55003/v1/ws"),
            "wss://delivery.ghalbol.com:55003/v1/ws"
        );
    }

    #[test]
    fn parse_nonce32_rejects_wrong_length_and_non_hex() {
        assert!(parse_nonce32("ab").is_err());
        assert!(parse_nonce32(&"g".repeat(64)).is_err());
        assert!(parse_nonce32(&"a".repeat(128)).is_err());
        let ok = parse_nonce32(&"ab".repeat(32)).unwrap();
        assert_eq!(ok.len(), 32);
    }

    #[test]
    fn parse_ws_json_rejects_oversized_non_object_and_malformed() {
        assert!(parse_ws_json_text(&"{").is_err());
        assert!(parse_ws_json_text("[]").is_err());
        assert!(parse_ws_json_text("\"x\"").is_err());
        let big = "x".repeat(MAX_WS_TEXT_FRAME_BYTES + 1);
        assert!(parse_ws_json_text(&big).is_err());
        let ok = parse_ws_json_text(r#"{"type":"ping"}"#).unwrap();
        assert_eq!(ok.get("type").and_then(|v| v.as_str()), Some("ping"));
    }

    #[test]
    fn push_prefetch_evicts_oldest_at_cap() {
        let mut q = VecDeque::new();
        for i in 0..MAX_PREFETCHED_PUSH_FRAMES + 3 {
            push_prefetch(&mut q, json!({"type": "message.inbound", "n": i}), "inbox.ack.ok");
        }
        assert_eq!(q.len(), MAX_PREFETCHED_PUSH_FRAMES);
        assert_eq!(q.front().and_then(|v| v.get("n")).and_then(|v| v.as_u64()), Some(3));
        assert_eq!(q.back().and_then(|v| v.get("n")).and_then(|v| v.as_u64()), Some(514));
    }

    #[test]
    fn push_prefetch_under_typed_wait_keeps_protected_type() {
        let mut q = VecDeque::new();
        push_prefetch(
            &mut q,
            json!({"type": "inbox.ack.ok", "message_id": "keep"}),
            "inbox.ack.ok",
        );
        for i in 0..MAX_PREFETCHED_PUSH_FRAMES + 5 {
            push_prefetch(
                &mut q,
                json!({"type": "message.inbound", "n": i}),
                "inbox.ack.ok",
            );
        }
        assert_eq!(q.len(), MAX_PREFETCHED_PUSH_FRAMES);
        assert!(
            q.iter()
                .any(|v| v.get("message_id").and_then(|x| x.as_str()) == Some("keep")),
            "must not evict typed ack while waiting for inbox.ack.ok"
        );
    }

    #[test]
    fn parse_ws_json_rejects_non_object_without_full_parse() {
        let junk = " ".repeat(4096) + "[]";
        let err = parse_ws_json_text(&junk).unwrap_err();
        assert_eq!(err, "ws json must be an object");
    }

    #[test]
    fn parse_nonce32_accepts_trimmed_hex() {
        let inner = "ab".repeat(32);
        let padded = format!("  {inner}  ");
        assert_eq!(parse_nonce32(&padded).unwrap(), parse_nonce32(&inner).unwrap());
    }

    #[test]
    fn ws_url_from_base_rejects_blank_base() {
        assert_eq!(ws_url_from_base("   "), "");
        assert_eq!(
            ws_url_from_base("  wss://h.example/  "),
            "wss://h.example/v1/ws"
        );
    }

    #[test]
    fn delivery_ws_reconnect_backoff_from_zero() {
        assert_eq!(delivery_ws_reconnect_backoff_step(0), (0, 0));
    }

    #[test]
    fn ws_json_type_rejects_non_string_and_oversized() {
        assert!(ws_json_type_key_valid(&json!({"type": 1})).is_err());
        assert!(ws_json_type_key_valid(&json!({"type": []})).is_err());
        let long = "a".repeat(MAX_WS_FRAME_TYPE_LEN + 1);
        assert!(ws_json_type_key_valid(&json!({"type": long})).is_err());
        assert!(ws_json_type_key_valid(&json!({"type": "inbox.ack.ok"})).is_ok());
        assert!(parse_ws_json_text(&format!(r#"{{"type":"{long}"}}"#)).is_err());
    }

    #[test]
    fn delivery_ws_reconnect_backoff_doubles_to_cap() {
        assert_eq!(delivery_ws_reconnect_backoff_step(1), (1, 2));
        assert_eq!(
            delivery_ws_reconnect_backoff_step(32),
            (32, DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS)
        );
        assert_eq!(
            delivery_ws_reconnect_backoff_step(DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS),
            (
                DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS,
                DELIVERY_WS_RECONNECT_BACKOFF_CAP_SECS
            )
        );
    }

    #[test]
    fn inbox_ack_ok_behind_prefetched_inbound_resumes_from_queue() {
        let mut q = VecDeque::new();
        push_prefetch(
            &mut q,
            json!({"type": "message.inbound", "message_id": "push-1"}),
            "inbox.ack.ok",
        );
        push_prefetch(
            &mut q,
            json!({"type": "message.inbound", "message_id": "push-2"}),
            "inbox.ack.ok",
        );
        push_prefetch(
            &mut q,
            json!({"type": "inbox.ack.ok", "message_id": "mid-ack"}),
            "inbox.ack.ok",
        );
        let ack = take_typed_from_prefetch(&mut q, "inbox.ack.ok").expect("ack in prefetch");
        assert_eq!(
            ack.get("message_id").and_then(|v| v.as_str()),
            Some("mid-ack")
        );
        assert_eq!(q.len(), 2, "inbound pushes remain for recv_push");
    }
}
