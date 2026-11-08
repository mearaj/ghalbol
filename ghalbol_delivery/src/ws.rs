//! WebSocket session handler.

use crate::auth::{
    ChallengeStore, extend_challenge_bytes, parse_nonce_hex, parse_signature_hex,
    session_challenge_bytes, upload_challenge_bytes, verify_signature,
};
use crate::config::DeliveryConfig;
use crate::envelope::{parse_wire_message_id, validate_envelope};
use crate::error::DeliveryError;
use crate::policy::PolicyLimits;
use crate::store::{MailboxStore, QuotaStatus};
use crate::OpsCounters;
use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};

type WsSender = mpsc::UnboundedSender<String>;

/// Per-socket limits copied from [`DeliveryConfig`].
#[derive(Clone, Debug)]
pub struct ConnLimits {
    pub max_ws_message_bytes: usize,
    pub max_frames_per_sec: u32,
    pub auth_timeout: Duration,
}

impl ConnLimits {
    pub fn from_config(cfg: &DeliveryConfig) -> Self {
        Self {
            max_ws_message_bytes: cfg.max_ws_message_bytes,
            max_frames_per_sec: cfg.max_frames_per_sec,
            auth_timeout: Duration::from_secs(cfg.auth_timeout_secs.max(1)),
        }
    }
}

#[derive(Clone)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, Vec<WsSender>>>>,
    connected_count: Arc<AtomicUsize>,
    live_sockets: Arc<AtomicUsize>,
    max_connections: usize,
    /// Bumped on each `session.ready`; cancels stale `deliver_pending_inbound` tasks.
    inbound_gen: Arc<RwLock<HashMap<String, u64>>>,
}

impl SessionRegistry {
    /// Cap concurrent sockets per identity (multi-device / reconnect storms).
    const MAX_SESSIONS_PER_IDENTITY: usize = 8;

    pub fn with_limit(max_connections: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            connected_count: Arc::new(AtomicUsize::new(0)),
            live_sockets: Arc::new(AtomicUsize::new(0)),
            max_connections: max_connections.max(1),
            inbound_gen: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn bump_inbound_generation(&self, identity_wire: &str) -> u64 {
        let mut g = self.inbound_gen.write().await;
        let entry = g.entry(identity_wire.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
        *entry
    }

    pub async fn inbound_generation(&self, identity_wire: &str) -> u64 {
        self.inbound_gen
            .read()
            .await
            .get(identity_wire)
            .copied()
            .unwrap_or(0)
    }

    pub fn live_sockets(&self) -> usize {
        self.live_sockets.load(Ordering::Relaxed)
    }

    pub fn try_admit(&self) -> bool {
        let mut current = self.live_sockets.load(Ordering::Relaxed);
        loop {
            if current >= self.max_connections {
                return false;
            }
            match self.live_sockets.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn release_admit(&self) {
        // Saturating: never wrap if a guard is dropped twice under a bug.
        let mut current = self.live_sockets.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.live_sockets.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    pub async fn register(&self, identity_wire: &str, tx: WsSender) {
        let mut g = self.inner.write().await;
        let already = g
            .get(identity_wire)
            .is_some_and(|v| v.iter().any(|s| s.same_channel(&tx)));
        if !already {
            let entry = g.entry(identity_wire.to_string()).or_default();
            while entry.len() >= Self::MAX_SESSIONS_PER_IDENTITY {
                entry.remove(0);
            }
            entry.push(tx);
        }
        Self::refresh_connected_count(&self.connected_count, &g);
    }

    pub async fn unregister(&self, identity_wire: &str, tx: &WsSender) {
        let mut g = self.inner.write().await;
        if let Some(v) = g.get_mut(identity_wire) {
            v.retain(|s| !s.same_channel(tx));
            if v.is_empty() {
                g.remove(identity_wire);
            }
        }
        Self::refresh_connected_count(&self.connected_count, &g);
        self.drop_inbound_gen_if_idle(identity_wire, &g).await;
    }

    fn refresh_connected_count(counter: &AtomicUsize, sessions: &HashMap<String, Vec<WsSender>>) {
        counter.store(
            sessions.values().map(|v| v.len()).sum(),
            Ordering::Relaxed,
        );
    }

    async fn drop_inbound_gen_if_idle(&self, identity_wire: &str, sessions: &HashMap<String, Vec<WsSender>>) {
        if !sessions.contains_key(identity_wire) {
            self.inbound_gen.write().await.remove(identity_wire);
        }
    }

    pub async fn connected_count(&self) -> usize {
        self.connected_count.load(Ordering::Relaxed)
    }

    pub async fn push(&self, identity_wire: &str, frame: Value) {
        let msg = frame.to_string();
        let mut dead: Vec<WsSender> = Vec::new();
        {
            let g = self.inner.read().await;
            if let Some(senders) = g.get(identity_wire) {
                for tx in senders {
                    if tx.send(msg.clone()).is_err() {
                        dead.push(tx.clone());
                    }
                }
            }
        }
        if dead.is_empty() {
            return;
        }
        let mut g = self.inner.write().await;
        if let Some(senders) = g.get_mut(identity_wire) {
            senders.retain(|live| !dead.iter().any(|d| d.same_channel(live)));
            if senders.is_empty() {
                g.remove(identity_wire);
            }
        }
        Self::refresh_connected_count(&self.connected_count, &g);
        self.drop_inbound_gen_if_idle(identity_wire, &g).await;
    }
}

pub struct WsState {
    pub store: Arc<MailboxStore>,
    pub policy: PolicyLimits,
    pub registry: SessionRegistry,
    pub shutdown: tokio::sync::watch::Receiver<bool>,
    pub ops: Arc<OpsCounters>,
    pub limits: ConnLimits,
}

/// Releases a `try_admit` slot even if the socket task panics.
struct AdmitGuard<'a>(&'a SessionRegistry);

impl Drop for AdmitGuard<'_> {
    fn drop(&mut self) {
        self.0.release_admit();
    }
}

pub async fn handle_socket(socket: WebSocket, state: Arc<WsState>) {
    if !state.registry.try_admit() {
        state
            .ops
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!("ws connection rejected: max_connections");
        let mut socket = socket;
        let _ = socket
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1013,
                reason: "server busy".into(),
            })))
            .await;
        return;
    }
    let _admit = AdmitGuard(&state.registry);

    let outcome = handle_socket_inner(socket, state.clone()).await;
    if let Err(err) = outcome {
        tracing::debug!(error = %err, "ws socket ended with error");
    }
}

async fn handle_socket_inner(
    socket: WebSocket,
    state: Arc<WsState>,
) -> Result<(), DeliveryError> {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (push_tx, mut push_rx) = mpsc::unbounded_channel::<String>();
    let mut authenticated: Option<String> = None;
    let mut op_nonce_hex: Option<String> = None;
    // Per-connection challenge store: parallel sockets must not clobber each other.
    let mut challenges = ChallengeStore::default();
    let mut shutdown_rx = state.shutdown.clone();
    let auth_deadline = tokio::time::sleep(state.limits.auth_timeout);
    tokio::pin!(auth_deadline);
    let mut auth_deadline_armed = true;
    let mut frame_window_start = Instant::now();
    let mut frames_in_window: u32 = 0;

    if *shutdown_rx.borrow() {
        return Ok(());
    }

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            result = shutdown_rx.changed() => {
                if result.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            _ = &mut auth_deadline, if auth_deadline_armed && authenticated.is_none() => {
                tracing::warn!("ws closed: auth timeout");
                state.ops.auth_failures.fetch_add(1, Ordering::Relaxed);
                let _ = ws_tx
                    .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: 1008,
                        reason: "auth timeout".into(),
                    })))
                    .await;
                break;
            }
            Some(push) = push_rx.recv() => {
                if ws_tx.send(Message::Text(push.into())).await.is_err() {
                    break;
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > state.limits.max_ws_message_bytes {
                            state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                frame_bytes = text.len(),
                                max = state.limits.max_ws_message_bytes,
                                "ws text frame rejected: too large"
                            );
                            let err = error_frame("bad_request", "frame too large", None);
                            let _ = ws_tx
                                .send(Message::Text(err.to_string().into()))
                                .await;
                            let _ = ws_tx
                                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                    code: 1009,
                                    reason: "frame too large".into(),
                                })))
                                .await;
                            break;
                        }
                        if !allow_frame(
                            &mut frame_window_start,
                            &mut frames_in_window,
                            state.limits.max_frames_per_sec,
                        ) {
                            state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
                            let err = error_frame("rate_limited", "too many frames", None);
                            let _ = ws_tx
                                .send(Message::Text(err.to_string().into()))
                                .await;
                            continue;
                        }
                        let response = process_frame(
                            &text,
                            &state,
                            &mut authenticated,
                            &mut op_nonce_hex,
                            &mut challenges,
                            &push_tx,
                        )
                        .await;
                        if authenticated.is_some() {
                            auth_deadline_armed = false;
                        }
                        if let Some(resp) = response {
                            if ws_tx.send(Message::Text(resp.to_string().into())).await.is_err() {
                                break;
                            }
                            if resp.get("type").and_then(|v| v.as_str()) == Some("session.ready") {
                                if let Some(id) = authenticated.as_ref() {
                                    let norm = id.clone();
                                    let inbound_gen =
                                        state.registry.bump_inbound_generation(&norm).await;
                                    let state_inbound = state.clone();
                                    tokio::spawn(async move {
                                        deliver_pending_inbound(
                                            &norm,
                                            &state_inbound,
                                            inbound_gen,
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    Some(Ok(Message::Binary(data))) => {
                        state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            frame_bytes = data.len(),
                            "ws binary frame rejected"
                        );
                        let err = error_frame("bad_request", "binary frames not supported", None);
                        let _ = ws_tx
                            .send(Message::Text(err.to_string().into()))
                            .await;
                        let _ = ws_tx
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1003,
                                reason: "unsupported data".into(),
                            })))
                            .await;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(id) = authenticated.as_ref() {
        state.registry.unregister(id, &push_tx).await;
    }
    Ok(())
}

fn allow_frame(window_start: &mut Instant, count: &mut u32, max_per_sec: u32) -> bool {
    if max_per_sec == 0 {
        return true;
    }
    let now = Instant::now();
    if now.duration_since(*window_start) >= Duration::from_secs(1) {
        *window_start = now;
        *count = 0;
    }
    if *count >= max_per_sec {
        return false;
    }
    *count += 1;
    true
}

async fn process_frame(
    text: &str,
    state: &Arc<WsState>,
    authenticated: &mut Option<String>,
    op_nonce_hex: &mut Option<String>,
    challenges: &mut ChallengeStore,
    push_tx: &WsSender,
) -> Option<Value> {
    let frame: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => {
            state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
            return Some(error_frame("bad_request", "invalid json", None));
        }
    };
    let frame_type = frame
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if frame_type.len() > 64 {
        state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
        return Some(error_frame("bad_request", "type too long", None));
    }
    let request_id = match frame.get("request_id") {
        Some(Value::String(s)) if !s.is_empty() && s.len() <= 128 => Some(Value::String(s.clone())),
        Some(Value::Number(n)) => Some(Value::Number(n.clone())),
        _ => None,
    };

    let result = match frame_type.as_str() {
        "session.open" => {
            handle_session_open(
                frame,
                state,
                authenticated,
                op_nonce_hex,
                challenges,
                push_tx,
            )
            .await
        }
        "session.auth" => {
            handle_session_auth(
                frame,
                state,
                authenticated,
                op_nonce_hex,
                challenges,
                push_tx,
            )
            .await
        }
        "message.upload" => {
            handle_upload(frame, state, authenticated, op_nonce_hex, challenges).await
        }
        "inbox.ack" => handle_inbox_ack(frame, state, authenticated).await,
        "inbox.read" => handle_inbox_read(frame, state, authenticated).await,
        "mailbox.outbox.list" => handle_outbox_list(frame, state, authenticated).await,
        "mailbox.ttl.extend" => {
            handle_extend(frame, state, authenticated, op_nonce_hex, challenges).await
        }
        "quota.status" => handle_quota(state, authenticated).await,
        "ping" => Ok(Some(json!({ "type": "pong" }))),
        _ => Err(DeliveryError::BadRequest(format!(
            "unknown type: {frame_type}"
        ))),
    };

    match result {
        Ok(opt) => opt,
        Err(e) => {
            if e.ws_code() == "unauthorized" {
                state.ops.auth_failures.fetch_add(1, Ordering::Relaxed);
            } else {
                state.ops.rejected_frames.fetch_add(1, Ordering::Relaxed);
            }
            tracing::warn!(
                frame_type = %frame_type,
                code = e.ws_code(),
                reject_reason = %e,
                "ws frame rejected"
            );
            Some(error_frame(e.ws_code(), &e.client_message(), request_id))
        }
    }
}

async fn handle_session_open(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &mut Option<String>,
    op_nonce_hex: &mut Option<String>,
    challenges: &mut ChallengeStore,
    push_tx: &WsSender,
) -> Result<Option<Value>, DeliveryError> {
    let identity_wire = frame
        .get("identity_wire")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeliveryError::BadRequest("missing identity_wire".into()))?;
    if let Some(prev) = authenticated.take() {
        state.registry.unregister(&prev, push_tx).await;
    }
    *op_nonce_hex = None;
    *challenges = ChallengeStore::default();
    let challenge = challenges.issue_session(identity_wire, Duration::from_secs(120))?;
    Ok(Some(json!({
        "type": "session.challenge",
        "nonce_hex": hex::encode(challenge.nonce),
    })))
}

async fn handle_session_auth(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &mut Option<String>,
    op_nonce_hex: &mut Option<String>,
    challenges: &mut ChallengeStore,
    push_tx: &WsSender,
) -> Result<Option<Value>, DeliveryError> {
    let identity_wire = frame
        .get("identity_wire")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeliveryError::BadRequest("missing identity_wire".into()))?;
    let nonce = parse_nonce_hex(
        frame
            .get("nonce_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing nonce_hex".into()))?,
    )?;
    let sig = parse_signature_hex(
        frame
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing signature_hex".into()))?,
    )?;
    let msg = session_challenge_bytes(&nonce, identity_wire);
    verify_signature(identity_wire, &msg, &sig)?;
    challenges.take_session_valid(identity_wire, &nonce)?;

    let norm = crate::identity::normalize_identity_wire(identity_wire)?;
    *authenticated = Some(norm.clone());
    state.registry.register(&norm, push_tx.clone()).await;

    let op_nonce = challenges.issue_op_nonce(&norm, Duration::from_secs(60))?;
    let op_nonce_hex_val = hex::encode(op_nonce);
    *op_nonce_hex = Some(op_nonce_hex_val.clone());

    let quota = state.store.quota_status(&norm)?;
    push_quota_warning(state, &norm, &quota).await;

    Ok(Some(json!({
        "type": "session.ready",
        "identity_wire": norm,
        "op_nonce_hex": op_nonce_hex_val,
        "policy": {
            "type": "policy.limits",
            "min_ttl_secs": state.policy.min_ttl_secs,
            "max_ttl_secs": state.policy.max_ttl_secs,
            "default_ttl_secs": state.policy.default_ttl_secs,
        },
        "quota": {
            "type": "quota.status",
            "allocated_bytes": quota.allocated_bytes,
            "used_bytes": quota.used_bytes,
            "pending_count": quota.pending_count,
        }
    })))
}

/// Re-parse a stored mailbox blob before fan-out on reconnect.
fn envelope_for_pending_replay(blob: &str) -> Option<Value> {
    let envelope = serde_json::from_str::<Value>(blob).ok()?;
    let sender_wire = envelope.get("sender_wire")?.as_str()?;
    validate_envelope(&envelope, sender_wire).ok()?;
    Some(envelope)
}

async fn deliver_pending_inbound(recipient_wire: &str, state: &Arc<WsState>, generation: u64) {
    if state.registry.inbound_generation(recipient_wire).await != generation {
        return;
    }
    if let Ok(rows) = state.store.pending_for_recipient(recipient_wire) {
        for (blob, message_id, expires_at_ms) in rows {
            if state.registry.inbound_generation(recipient_wire).await != generation {
                return;
            }
            let Some(envelope) = envelope_for_pending_replay(&blob) else {
                tracing::warn!(
                    recipient_wire = %recipient_wire,
                    message_id = %message_id,
                    "skipped pending replay: corrupt or invalid stored envelope"
                );
                continue;
            };
            state
                .registry
                .push(
                    recipient_wire,
                    json!({
                        "type": "message.inbound",
                        "message_id": message_id,
                        "envelope": envelope,
                        "expires_at_ms": expires_at_ms,
                    }),
                )
                .await;
        }
    }
}

async fn handle_upload(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &Option<String>,
    op_nonce_hex: &mut Option<String>,
    challenges: &mut ChallengeStore,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let envelope = frame
        .get("envelope")
        .ok_or_else(|| DeliveryError::BadRequest("missing envelope".into()))?;
    let env = validate_envelope(envelope, session)?;

    let op_nonce = parse_nonce_hex(
        frame
            .get("op_nonce_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing op_nonce_hex".into()))?,
    )?;
    let sig = parse_signature_hex(
        frame
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing signature_hex".into()))?,
    )?;
    let upload_msg = upload_challenge_bytes(&op_nonce, &env.message_id, &env.recipient_wire);
    verify_signature(session, &upload_msg, &sig)?;
    let ttl_secs = state
        .policy
        .clamp_ttl(frame.get("ttl_secs").and_then(|v| v.as_u64()))?;
    challenges.take_op_valid(session, &op_nonce)?;

    let message_id = env.message_id.clone();
    let recipient_wire = env.recipient_wire.clone();
    let envelope_push: Value = serde_json::from_str(&env.envelope_blob).map_err(|e| {
        DeliveryError::Internal(format!("stored envelope json: {e}"))
    })?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let expires_at_ms = (now_ms + (ttl_secs as i64) * 1000)
        .min(state.policy.max_expires_at_ms(now_ms));
    let upload_result = state.store.upload(env, ttl_secs, &state.policy);
    let (quota, replaced) = match upload_result {
        Ok(v) => v,
        Err(e) => {
            // Failed write must leave the same op nonce valid for retry.
            let _ = challenges.restore_op_nonce(session, op_nonce, Duration::from_secs(60));
            *op_nonce_hex = Some(hex::encode(op_nonce));
            return Err(e);
        }
    };

    let new_nonce = challenges.issue_op_nonce(session, Duration::from_secs(60))?;
    *op_nonce_hex = Some(hex::encode(new_nonce));
    state.ops.uploads_total.fetch_add(1, Ordering::Relaxed);

    state
        .registry
        .push(
            &recipient_wire,
            json!({
                "type": "message.inbound",
                "message_id": message_id,
                "envelope": envelope_push,
                "expires_at_ms": expires_at_ms,
            }),
        )
        .await;
    push_quota_warning(state, session, &quota).await;

    Ok(Some(json!({
        "type": "message.upload.ok",
        "message_id": message_id,
        "replaced": replaced,
        "op_nonce_hex": op_nonce_hex,
        "quota": {
            "type": "quota.status",
            "allocated_bytes": quota.allocated_bytes,
            "used_bytes": quota.used_bytes,
            "pending_count": quota.pending_count,
        }
    })))
}

async fn push_quota_warning(state: &Arc<WsState>, sender: &str, quota: &QuotaStatus) {
    if !quota.above_warning_threshold() {
        return;
    }
    tracing::info!(
        sender_wire = %sender,
        used_bytes = quota.used_bytes,
        allocated_bytes = quota.allocated_bytes,
        "quota warning"
    );
    state
        .registry
        .push(
            sender,
            json!({
                "type": "quota.warning",
                "allocated_bytes": quota.allocated_bytes,
                "used_bytes": quota.used_bytes,
                "pending_count": quota.pending_count,
            }),
        )
        .await;
}

async fn handle_inbox_ack(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &Option<String>,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let message_id = parse_wire_message_id(
        frame
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing message_id".into()))?,
    )?;
    let sender_wire = frame
        .get("sender_wire")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeliveryError::BadRequest("missing sender_wire".into()))?;
    let sender_norm = crate::identity::normalize_identity_wire(sender_wire)?;

    let (_sender, newly) = state
        .store
        .ack_deliver(session, &message_id, &sender_norm)?;

    if newly {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        state
            .registry
            .push(
                &sender_norm,
                json!({
                    "type": "message.ack_to_sender",
                    "message_id": message_id,
                    "recipient_wire": session,
                    "delivered_at_ms": now,
                }),
            )
            .await;
    }

    Ok(Some(json!({
        "type": "inbox.ack.ok",
        "message_id": message_id,
    })))
}

async fn handle_inbox_read(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &Option<String>,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let message_id = parse_wire_message_id(
        frame
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing message_id".into()))?,
    )?;
    let sender_wire = frame
        .get("sender_wire")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeliveryError::BadRequest("missing sender_wire".into()))?;
    let sender_norm = crate::identity::normalize_identity_wire(sender_wire)?;

    let (_sender, newly) = state
        .store
        .ack_read(session, &message_id, &sender_norm)?;

    if newly {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        state
            .registry
            .push(
                &sender_norm,
                json!({
                    "type": "message.read_to_sender",
                    "message_id": message_id,
                    "recipient_wire": session,
                    "read_at_ms": now,
                }),
            )
            .await;
    }

    Ok(Some(json!({
        "type": "inbox.read.ok",
        "message_id": message_id,
    })))
}

async fn handle_outbox_list(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &Option<String>,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let include_expired = frame
        .get("include_expired")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let rows = state.store.list_outbox(session, include_expired)?;
    Ok(Some(json!({
        "type": "mailbox.outbox.snapshot",
        "rows": rows,
    })))
}

async fn handle_extend(
    frame: Value,
    state: &Arc<WsState>,
    authenticated: &Option<String>,
    op_nonce_hex: &mut Option<String>,
    challenges: &mut ChallengeStore,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let message_id = parse_wire_message_id(
        frame
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing message_id".into()))?,
    )?;
    let extend_secs = frame
        .get("extend_secs")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DeliveryError::BadRequest("missing extend_secs".into()))?;
    if extend_secs < state.policy.min_ttl_secs || extend_secs > state.policy.max_ttl_secs {
        return Err(DeliveryError::TtlInvalid(
            "extend_secs outside policy bounds".into(),
        ));
    }

    let op_nonce = parse_nonce_hex(
        frame
            .get("op_nonce_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing op_nonce_hex".into()))?,
    )?;
    let sig = parse_signature_hex(
        frame
            .get("signature_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DeliveryError::BadRequest("missing signature_hex".into()))?,
    )?;
    let extend_msg = extend_challenge_bytes(&op_nonce, &message_id);
    verify_signature(session, &extend_msg, &sig)?;
    challenges.take_op_valid(session, &op_nonce)?;

    let row = match state
        .store
        .extend_ttl(session, &message_id, extend_secs, &state.policy)
    {
        Ok(row) => row,
        Err(e) => {
            let _ = challenges.restore_op_nonce(session, op_nonce, Duration::from_secs(60));
            *op_nonce_hex = Some(hex::encode(op_nonce));
            return Err(e);
        }
    };

    let new_nonce = challenges.issue_op_nonce(session, Duration::from_secs(60))?;
    *op_nonce_hex = Some(hex::encode(new_nonce));

    Ok(Some(json!({
        "type": "mailbox.ttl.extended",
        "row": row,
        "op_nonce_hex": op_nonce_hex,
    })))
}

async fn handle_quota(
    state: &Arc<WsState>,
    authenticated: &Option<String>,
) -> Result<Option<Value>, DeliveryError> {
    let session = authenticated
        .as_ref()
        .ok_or_else(|| DeliveryError::Unauthorized("session not ready".into()))?;
    let quota = state.store.quota_status(session)?;
    Ok(Some(json!({
        "type": "quota.status",
        "allocated_bytes": quota.allocated_bytes,
        "used_bytes": quota.used_bytes,
        "pending_count": quota.pending_count,
    })))
}

fn error_frame(code: &str, message: &str, request_id: Option<Value>) -> Value {
    let mut v = json!({
        "type": "error",
        "code": code,
        "message": message,
    });
    if let Some(rid) = request_id {
        v["request_id"] = rid;
    }
    v
}

pub fn spawn_ttl_sweeper(
    store: Arc<MailboxStore>,
    registry: SessionRegistry,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    ops: Arc<OpsCounters>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        if *shutdown.borrow() {
            return;
        }
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if let Ok(expired) = store.sweep_expired() {
                        let n = expired.len() as u64;
                        if n > 0 {
                            ops.messages_expired.fetch_add(n, Ordering::Relaxed);
                        }
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        for (sender, message_id, recipient) in expired {
                            registry
                                .push(
                                    &sender,
                                    json!({
                                        "type": "message.expired",
                                        "message_id": message_id,
                                        "recipient_wire": recipient,
                                        "expired_at_ms": now,
                                    }),
                                )
                                .await;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admit_slots_are_bounded_and_released() {
        let reg = SessionRegistry::with_limit(2);
        assert!(reg.try_admit());
        assert!(reg.try_admit());
        assert!(!reg.try_admit());
        assert_eq!(reg.live_sockets(), 2);
        reg.release_admit();
        assert_eq!(reg.live_sockets(), 1);
        assert!(reg.try_admit());
        assert!(!reg.try_admit());
    }

    #[test]
    fn admit_guard_releases_on_drop() {
        let reg = SessionRegistry::with_limit(1);
        assert!(reg.try_admit());
        {
            let _g = AdmitGuard(&reg);
            assert!(!reg.try_admit());
        }
        assert_eq!(reg.live_sockets(), 0);
        assert!(reg.try_admit());
        reg.release_admit();
    }

    #[tokio::test]
    async fn inbound_generation_invalidates_stale_reconnect_tasks() {
        let reg = SessionRegistry::with_limit(4);
        let wire = "02".repeat(33);
        let g1 = reg.bump_inbound_generation(&wire).await;
        assert_eq!(g1, 1);
        let g2 = reg.bump_inbound_generation(&wire).await;
        assert_eq!(g2, 2);
        assert_eq!(reg.inbound_generation(&wire).await, 2);
        assert_ne!(g1, g2);
    }

    #[tokio::test]
    async fn unregister_drops_inbound_gen_when_last_session_gone() {
        let reg = SessionRegistry::with_limit(4);
        let wire = "02".repeat(33);
        reg.bump_inbound_generation(&wire).await;
        let (tx, _rx) = mpsc::unbounded_channel();
        reg.register(&wire, tx.clone()).await;
        reg.unregister(&wire, &tx).await;
        assert_eq!(reg.inbound_generation(&wire).await, 0);
        assert_eq!(reg.connected_count().await, 0);
    }

    #[tokio::test]
    async fn push_prunes_disconnected_senders_from_registry() {
        let reg = SessionRegistry::with_limit(8);
        let wire = "02".repeat(33);
        let (live_tx, mut live_rx) = mpsc::unbounded_channel();
        let (dead_tx, dead_rx) = mpsc::unbounded_channel();
        reg.register(&wire, live_tx).await;
        reg.register(&wire, dead_tx).await;
        drop(dead_rx);
        reg.push(&wire, json!({"type": "ping"})).await;
        assert_eq!(reg.connected_count().await, 1);
        let _ = live_rx.try_recv().expect("live session receives push");
    }

    #[test]
    fn pending_replay_skips_non_envelope_json() {
        assert!(super::envelope_for_pending_replay("not-json").is_none());
        assert!(super::envelope_for_pending_replay(r#"{"foo":1}"#).is_none());
    }
}
