//! WAN call byte bridge — pairs two outbound WebSocket connections (`docs/GHALBOL_CONNECT_V1.md`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};

use crate::auth::ChallengePurpose;
use crate::bridge_auth::verify_bridge_request_signature;
use crate::error::{ApiResult, ServerError};
use crate::identity::{check_identity_param_len, normalize_identity_wire};
use crate::json_extract::ApiJson;
use crate::routes::RouteState;

#[derive(Clone)]
pub struct BridgeRegistry {
    inner: Arc<Mutex<BridgeInner>>,
    max_secs: u64,
    /// Unpaired pending lifetime — short so failed dials do not fill `max_per_peer`
    /// for hours (docs: pairing completes in seconds; session TTL is separate).
    pending_secs: u64,
    max_bytes: u64,
    max_per_peer: usize,
    idle_secs: u64,
}

struct BridgeInner {
    pending: HashMap<String, PendingBridge>,
    active: HashMap<String, ActiveBridge>,
}

#[derive(Clone)]
struct PendingBridge {
    bridge_id: String,
    caller_wire: String,
    callee_wire: String,
    call_id: String,
    caller_token: String,
    callee_token: String,
    expires: Instant,
}

struct ActiveBridge {
    caller_wire: String,
    callee_wire: String,
    call_id: String,
    caller_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    callee_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    /// Frames received before the peer side connected — Noise msg1 must not be dropped.
    to_caller: Vec<Vec<u8>>,
    to_callee: Vec<Vec<u8>>,
    bytes_relayed: u64,
    /// True once both sockets have joined — after that, a missing peer tx means hangup.
    was_paired: bool,
    notify: Arc<Notify>,
}

impl BridgeRegistry {
    pub fn from_env() -> Self {
        let max_secs = std::env::var("GHALBOL_BRIDGE_MAX_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4 * 3600);
        let max_bytes = std::env::var("GHALBOL_BRIDGE_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let max_per_peer = std::env::var("GHALBOL_BRIDGE_MAX_PER_PEER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let idle_secs = std::env::var("GHALBOL_BRIDGE_IDLE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        // Unpaired pending default 90s — not session max (4h). Override: GHALBOL_BRIDGE_PENDING_SECS.
        let pending_secs = std::env::var("GHALBOL_BRIDGE_PENDING_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90)
            .clamp(15, max_secs.max(15));
        Self {
            inner: Arc::new(Mutex::new(BridgeInner {
                pending: HashMap::new(),
                active: HashMap::new(),
            })),
            max_secs,
            pending_secs,
            max_bytes,
            max_per_peer,
            idle_secs,
        }
    }

    fn pending_ttl(&self) -> Duration {
        Duration::from_secs(self.pending_secs)
    }

    pub async fn purge_expired(&self) {
        let mut g = self.inner.lock().await;
        purge_locked(&mut g);
    }

    /// Drop stale unpaired entries for this caller so a new invite can proceed
    /// (docs: one call path; retries must not be blocked by dead pending).
    #[cfg(test)]
    async fn drop_caller_pending_for_replace(&self, caller: &str, callee: &str, call_id: &str) {
        let mut g = self.inner.lock().await;
        drop_replaceable_locked(&mut g, caller, callee, call_id);
    }

    #[cfg(test)]
    async fn count_for_peer(&self, wire: &str) -> usize {
        let g = self.inner.lock().await;
        count_locked(&g, wire)
    }

    /// Purge, replace, cap check, and insert under one lock.
    /// Separate locks let concurrent admits all pass the cap.
    async fn admit(
        &self,
        caller: &str,
        callee: &str,
        call_id: &str,
    ) -> Result<(String, String), ServerError> {
        if caller.eq_ignore_ascii_case(callee) {
            return Err(ServerError::BadRequest(
                "bridge caller and callee must differ".into(),
            ));
        }
        validate_call_id(call_id)?;
        let mut g = self.inner.lock().await;
        purge_locked(&mut g);
        drop_replaceable_locked(&mut g, caller, callee, call_id);
        if count_locked(&g, caller) >= self.max_per_peer
            || count_locked(&g, callee) >= self.max_per_peer
        {
            return Err(ServerError::BadRequest("bridge limit per identity".into()));
        }
        if g.pending.len() >= MAX_TOTAL_PENDING_BRIDGES {
            return Err(ServerError::RateLimited("bridge pending capacity".into()));
        }
        let bridge_id = random_bridge_id();
        let caller_token = random_token();
        let callee_token = random_token();
        g.pending.insert(
            bridge_id.clone(),
            PendingBridge {
                bridge_id: bridge_id.clone(),
                caller_wire: caller.to_string(),
                callee_wire: callee.to_string(),
                call_id: call_id.to_string(),
                caller_token: caller_token.clone(),
                callee_token,
                expires: Instant::now() + self.pending_ttl(),
            },
        );
        Ok((bridge_id, caller_token))
    }

    /// Undo [`admit`] when challenge consumption fails after insert (replay safety).
    async fn revoke_admitted(&self, bridge_id: &str) {
        let mut g = self.inner.lock().await;
        g.pending.remove(bridge_id);
        if let Some(active) = g.active.remove(bridge_id) {
            active.notify.notify_waiters();
        }
    }
}

fn same_party(wire: &str, want: &str) -> bool {
    wire.eq_ignore_ascii_case(want)
}

fn active_admit_allowed(g: &BridgeInner, bridge_id: &str) -> bool {
    g.active.contains_key(bridge_id) || g.active.len() < MAX_TOTAL_ACTIVE_BRIDGES
}

fn count_locked(g: &BridgeInner, wire: &str) -> usize {
    let mut ids = std::collections::HashSet::new();
    for (id, bridge) in &g.pending {
        if same_party(&bridge.caller_wire, wire) || same_party(&bridge.callee_wire, wire) {
            ids.insert(id.clone());
        }
    }
    for (id, bridge) in &g.active {
        if same_party(&bridge.caller_wire, wire) || same_party(&bridge.callee_wire, wire) {
            ids.insert(id.clone());
        }
    }
    ids.len()
}

fn purge_locked(g: &mut BridgeInner) {
    let now = Instant::now();
    let expired: Vec<String> = g
        .pending
        .iter()
        .filter(|(_, bridge)| bridge.expires <= now)
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired {
        g.pending.remove(&id);
        let unpaired = g.active.get(&id).is_some_and(|active| !active.was_paired);
        if unpaired {
            if let Some(active) = g.active.remove(&id) {
                active.notify.notify_waiters();
            }
        }
    }
}

fn drop_replaceable_locked(g: &mut BridgeInner, caller: &str, callee: &str, call_id: &str) {
    let drop_pending: Vec<String> = g
        .pending
        .iter()
        .filter(|(_, bridge)| {
            same_party(&bridge.caller_wire, caller)
                && (bridge.call_id == call_id || same_party(&bridge.callee_wire, callee))
        })
        .map(|(id, _)| id.clone())
        .collect();
    let drop_active: Vec<String> = g
        .active
        .iter()
        .filter(|(_, bridge)| {
            !bridge.was_paired
                && same_party(&bridge.caller_wire, caller)
                && (bridge.call_id == call_id || same_party(&bridge.callee_wire, callee))
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in drop_pending {
        g.pending.remove(&id);
    }
    for id in drop_active {
        if let Some(active) = g.active.remove(&id) {
            active.notify.notify_waiters();
        }
    }
}

/// Global cap on unpaired pending rows (register storms / many callers).
pub(crate) const MAX_TOTAL_PENDING_BRIDGES: usize = 4_096;
/// Max items returned per callee poll (many callers must not blow JSON).
pub(crate) const MAX_BRIDGE_PENDING_RESPONSE: usize = 32;

pub(crate) const MAX_CALL_ID_LEN: usize = 128;

/// Bounds half-open and paired relay rows (pending has its own cap).
pub(crate) const MAX_TOTAL_ACTIVE_BRIDGES: usize = 4_096;

/// Reject empty, oversized, or control-character call ids before crypto or relay work.
pub(crate) fn validate_call_id(raw: &str) -> ApiResult<&str> {
    let call_id = raw.trim();
    if call_id.is_empty() {
        return Err(ServerError::BadRequest("call_id empty".into()));
    }
    if call_id.len() > MAX_CALL_ID_LEN {
        return Err(ServerError::BadRequest("call_id invalid".into()));
    }
    if call_id.chars().any(|c| c.is_control()) {
        return Err(ServerError::BadRequest("call_id invalid".into()));
    }
    Ok(call_id)
}
const MAX_WS_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_UNPAIRED_BUFFER_BYTES: usize = 256 * 1024;
const MAX_UNPAIRED_BUFFER_FRAMES: usize = 64;
const MAX_CONNECT_ID_LEN: usize = 64;
const MAX_CONNECT_TOKEN_LEN: usize = 128;
/// Per-leg outbound queue while the WebSocket sender is slower than the peer.
const MAX_RELAY_OUTBOUND_FRAMES: usize = 64;

fn try_forward_to_peer(
    peer_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    data: &[u8],
) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
    peer_tx.try_send(data.to_vec())
}

fn tokens_equal(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Drop one bridge leg. After pairing, the first leg to leave tears down the session
/// so `max_per_peer` slots are not held until idle timeout.
fn detach_bridge_role(g: &mut BridgeInner, bridge_id: &str, role: &str) {
    let notify = {
        let Some(active) = g.active.get_mut(bridge_id) else {
            g.pending.remove(bridge_id);
            return;
        };
        if role == "caller" {
            active.caller_tx = None;
        } else {
            active.callee_tx = None;
        }
        let remove = active.was_paired
            || (active.caller_tx.is_none() && active.callee_tx.is_none());
        if remove {
            let notify = Arc::clone(&active.notify);
            g.active.remove(bridge_id);
            Some(notify)
        } else {
            None
        }
    };
    if g.active.get(bridge_id).is_none() {
        g.pending.remove(bridge_id);
    }
    if let Some(notify) = notify {
        notify.notify_waiters();
    }
}

fn push_unpaired(buf: &mut Vec<Vec<u8>>, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    if data.len() > MAX_UNPAIRED_BUFFER_BYTES || buf.len() >= MAX_UNPAIRED_BUFFER_FRAMES {
        return false;
    }
    let used: usize = buf.iter().map(|frame| frame.len()).sum();
    if used.saturating_add(data.len()) > MAX_UNPAIRED_BUFFER_BYTES {
        return false;
    }
    buf.push(data.to_vec());
    true
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn random_bridge_id() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[derive(Deserialize)]
pub struct BridgeRequestBody {
    pub peer_identity_wire: String,
    pub call_id: String,
    pub nonce_hex: String,
    pub signature_hex: String,
    #[serde(default)]
    pub caller_identity_wire: Option<String>,
}

#[derive(Serialize)]
pub struct BridgeRequestResponse {
    pub bridge_id: String,
    pub token: String,
    pub connect_url: String,
}

#[derive(Deserialize)]
pub struct BridgeConnectQuery {
    pub bridge_id: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct BridgePendingItem {
    pub bridge_id: String,
    pub call_id: String,
    pub caller_identity_wire: String,
    pub token: String,
    pub connect_url: String,
}

#[derive(Serialize)]
pub struct BridgePendingResponse {
    pub pending: Vec<BridgePendingItem>,
}

pub async fn post_bridge_request(
    State(state): State<Arc<RouteState>>,
    ApiJson(req): ApiJson<BridgeRequestBody>,
) -> ApiResult<axum::Json<BridgeRequestResponse>> {
    let caller_raw = req
        .caller_identity_wire
        .as_deref()
        .ok_or_else(|| ServerError::BadRequest("caller_identity_wire required".into()))?;
    check_identity_param_len(caller_raw.trim())?;
    let caller = normalize_identity_wire(caller_raw)?;
    check_identity_param_len(req.peer_identity_wire.trim())?;
    let callee = normalize_identity_wire(&req.peer_identity_wire)?;
    let call_id = validate_call_id(&req.call_id)?;
    let nonce = crate::auth::decode_nonce_hex(&req.nonce_hex)?;
    let sig = crate::auth::decode_signature_hex(&req.signature_hex)?;
    {
        let mut ch = state.challenges.lock().await;
        // Peek first so a bad signature does not burn the caller's bridge challenge.
        ch.peek_valid(ChallengePurpose::Bridge, &caller, &nonce)?;
        verify_bridge_request_signature(&caller, &nonce, &callee, call_id, &sig)?;
    }

    let registry = state.app.bridge.clone();
    // One lock: replace, cap check, insert. Split locks raced past max_per_peer.
    let (bridge_id, caller_token) = registry.admit(&caller, &callee, call_id).await?;

    {
        let mut ch = state.challenges.lock().await;
        if let Err(e) = ch.take_valid(ChallengePurpose::Bridge, &caller, &nonce) {
            drop(ch);
            registry.revoke_admitted(&bridge_id).await;
            return Err(e);
        }
    }
    tracing::info!(
        bridge_id = %bridge_id,
        caller = %caller,
        callee = %callee,
        call_id = %call_id,
        "bridge requested"
    );

    let connect_url = bridge_connect_ws_url(&state.app.config.public_base_url);
    Ok(axum::Json(BridgeRequestResponse {
        bridge_id,
        token: caller_token,
        connect_url,
    }))
}

fn bridge_connect_ws_url(public_base_url: &str) -> String {
    let base = public_base_url.trim_end_matches('/');
    let ws = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{ws}/v1/bridge/connect")
}

pub async fn get_bridge_pending(
    State(state): State<Arc<RouteState>>,
    Query(q): Query<BridgePendingQuery>,
) -> ApiResult<axum::Json<BridgePendingResponse>> {
    check_identity_param_len(&q.identity_wire)?;
    let wire = normalize_identity_wire(&q.identity_wire)?;
    {
        let mut limits = state.bridge_poll_limits.lock().await;
        if !limits.allow(&wire) {
            return Err(ServerError::RateLimited("bridge poll rate limit".into()));
        }
    }
    let registry = state.app.bridge.clone();
    registry.purge_expired().await;
    let connect_url = bridge_connect_ws_url(&state.app.config.public_base_url);
    let g = registry.inner.lock().await;
    let w = wire.to_ascii_lowercase();
    let pending: Vec<BridgePendingItem> = g
        .pending
        .values()
        .filter(|b| b.callee_wire.to_ascii_lowercase() == w)
        .take(MAX_BRIDGE_PENDING_RESPONSE)
        .map(|b| BridgePendingItem {
            bridge_id: b.bridge_id.clone(),
            call_id: b.call_id.clone(),
            caller_identity_wire: b.caller_wire.clone(),
            token: b.callee_token.clone(),
            connect_url: connect_url.clone(),
        })
        .collect();
    Ok(axum::Json(BridgePendingResponse { pending }))
}

#[derive(Deserialize)]
pub struct BridgePendingQuery {
    pub identity_wire: String,
}

pub async fn ws_bridge_connect(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RouteState>>,
    Query(q): Query<BridgeConnectQuery>,
) -> impl IntoResponse {
    let registry = state.app.bridge.clone();
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_bridge_socket(socket, registry, q))
}

async fn handle_bridge_socket(socket: WebSocket, registry: BridgeRegistry, q: BridgeConnectQuery) {
    let bridge_id = q.bridge_id.trim().to_string();
    let token = q.token.trim().to_string();
    if bridge_id.is_empty()
        || token.is_empty()
        || bridge_id.len() > MAX_CONNECT_ID_LEN
        || token.len() > MAX_CONNECT_TOKEN_LEN
    {
        return;
    }

    let role = {
        let g = registry.inner.lock().await;
        if let Some(p) = g.pending.get(&bridge_id) {
            if tokens_equal(&p.caller_token, &token) {
                Some(("caller", p.clone()))
            } else if tokens_equal(&p.callee_token, &token) {
                Some(("callee", p.clone()))
            } else {
                None
            }
        } else if let Some(_a) = g.active.get(&bridge_id) {
            // Pending already cleared after first pair — reject late duplicates.
            None
        } else {
            None
        }
    };
    let Some((role, pending)) = role else {
        tracing::warn!(bridge_id = %bridge_id, "bridge connect rejected — bad token or unknown bridge");
        return;
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(MAX_RELAY_OUTBOUND_FRAMES);
    let notify = Arc::new(Notify::new());
    let (paired, flush_to_self, cancel) = {
        let mut g = registry.inner.lock().await;
        if !active_admit_allowed(&g, &bridge_id) {
            tracing::warn!(bridge_id = %bridge_id, "bridge connect rejected — active capacity");
            return;
        }
        let (paired, flush, cancel) = {
            let active = g
                .active
                .entry(bridge_id.clone())
                .or_insert_with(|| ActiveBridge {
                    caller_wire: pending.caller_wire.clone(),
                    callee_wire: pending.callee_wire.clone(),
                    call_id: pending.call_id.clone(),
                    caller_tx: None,
                    callee_tx: None,
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: false,
                    notify: Arc::clone(&notify),
                });
            if role == "caller" {
                if active.caller_tx.is_some() {
                    tracing::warn!(bridge_id = %bridge_id, "bridge connect rejected — caller already attached");
                    return;
                }
                active.caller_tx = Some(tx.clone());
            } else if active.callee_tx.is_some() {
                tracing::warn!(bridge_id = %bridge_id, "bridge connect rejected — callee already attached");
                return;
            } else {
                active.callee_tx = Some(tx.clone());
            }
            let paired = active.caller_tx.is_some() && active.callee_tx.is_some();
            if paired {
                active.was_paired = true;
            }
            // Buffered frames waiting for *this* role (sent by the other side early).
            let flush = if role == "caller" {
                std::mem::take(&mut active.to_caller)
            } else {
                std::mem::take(&mut active.to_callee)
            };
            let cancel = Arc::clone(&active.notify);
            (paired, flush, cancel)
        };
        if paired {
            g.pending.remove(&bridge_id);
        }
        (paired, flush, cancel)
    };

    if paired {
        tracing::info!(bridge_id = %bridge_id, "bridge paired");
    }

    // Deliver any frames the peer sent before we connected (critical for Noise XX msg1).
    for bytes in flush_to_self {
        if tx.try_send(bytes).is_err() {
            tracing::warn!(bridge_id = %bridge_id, role = %role, "bridge relay queue full on connect");
            let mut g = registry.inner.lock().await;
            detach_bridge_role(&mut g, &bridge_id, role);
            return;
        }
    }

    let (mut ws_tx, mut ws_rx) = socket.split();
    let relay_cancel = Arc::clone(&cancel);
    let relay_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                // Outbound stalled (slow/dead peer). Wake the read loop now — do not hold
                // `active` until idle timeout while the peer leg is still paired.
                relay_cancel.notify_waiters();
                break;
            }
        }
    });

    let started = Instant::now();
    let idle = Duration::from_secs(registry.idle_secs);
    let max_duration = Duration::from_secs(registry.max_secs);
    let mut last_activity = Instant::now();
    loop {
        tokio::select! {
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.is_empty() {
                            continue;
                        }
                        last_activity = Instant::now();
                        let forward = {
                            let mut g = registry.inner.lock().await;
                            if let Some(a) = g.active.get_mut(&bridge_id) {
                                let len = data.len() as u64;
                                a.bytes_relayed = a.bytes_relayed.saturating_add(len);
                                if registry.max_bytes > 0 && a.bytes_relayed > registry.max_bytes {
                                    None // signal over budget
                                } else if role == "caller" {
                                    if let Some(peer) = a.callee_tx.clone() {
                                        Some(Ok(peer))
                                    } else if a.was_paired {
                                        None // peer hung up
                                    } else if push_unpaired(&mut a.to_callee, &data) {
                                        Some(Err(())) // buffered
                                    } else {
                                        None
                                    }
                                } else if let Some(peer) = a.caller_tx.clone() {
                                    Some(Ok(peer))
                                } else if a.was_paired {
                                    None
                                } else if push_unpaired(&mut a.to_caller, &data) {
                                    Some(Err(()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        match forward {
                            None => break,
                            Some(Ok(peer_tx)) => {
                                if try_forward_to_peer(&peer_tx, &data).is_err() {
                                    tracing::warn!(
                                        bridge_id = %bridge_id,
                                        role = %role,
                                        "bridge relay backpressure — closing leg"
                                    );
                                    break;
                                }
                            }
                            Some(Err(())) => {}
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if last_activity.elapsed() > idle {
                    break;
                }
            }
            _ = cancel.notified() => break,
        }
        if started.elapsed() > max_duration {
            break;
        }
    }

    relay_task.abort();
    {
        let mut g = registry.inner.lock().await;
        detach_bridge_role(&mut g, &bridge_id, role);
    }
    tracing::info!(
        bridge_id = %bridge_id,
        role = %role,
        duration_ms = started.elapsed().as_millis(),
        "bridge closed"
    );
}

/// Issue a bridge challenge nonce (reuse registration challenge store pattern).
pub async fn bridge_challenge(
    State(state): State<Arc<RouteState>>,
    ApiJson(req): ApiJson<BridgeChallengeRequest>,
) -> ApiResult<axum::Json<BridgeChallengeResponse>> {
    check_identity_param_len(req.caller_identity_wire.trim())?;
    let pk = normalize_identity_wire(&req.caller_identity_wire)?;
    let mut ch = state.challenges.lock().await;
    ch.purge_expired();
    let pending = ch.issue(
        ChallengePurpose::Bridge,
        &pk,
        state.app.config.challenge_ttl,
    )?;
    let expires_in_secs = pending
        .expires_at
        .checked_duration_since(Instant::now())
        .map(|d| d.as_secs().max(1))
        .unwrap_or(1);
    Ok(axum::Json(BridgeChallengeResponse {
        caller_identity_wire: pk,
        nonce_hex: hex::encode(pending.nonce),
        expires_in_secs,
        message_domain: "ghalbol:bridge:request:v1",
    }))
}

#[derive(Deserialize)]
pub struct BridgeChallengeRequest {
    pub caller_identity_wire: String,
}

#[derive(Serialize)]
pub struct BridgeChallengeResponse {
    pub caller_identity_wire: String,
    pub nonce_hex: String,
    pub expires_in_secs: u64,
    pub message_domain: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn registry_for_test(max_per_peer: usize, pending_secs: u64) -> BridgeRegistry {
        BridgeRegistry {
            inner: Arc::new(Mutex::new(BridgeInner {
                pending: HashMap::new(),
                active: HashMap::new(),
            })),
            max_secs: 3600,
            pending_secs,
            max_bytes: 0,
            max_per_peer,
            idle_secs: 120,
        }
    }

    #[tokio::test]
    async fn purge_expired_pending_and_peer_counts() {
        let reg = registry_for_test(2, 1);
        let now = Instant::now();
        {
            let mut g = reg.inner.lock().await;
            g.pending.insert(
                "b1".into(),
                PendingBridge {
                    bridge_id: "b1".into(),
                    caller_wire: "aa".into(),
                    callee_wire: "bb".into(),
                    call_id: "c1".into(),
                    caller_token: "t1".into(),
                    callee_token: "t2".into(),
                    expires: now + Duration::from_secs(60),
                },
            );
            g.pending.insert(
                "b-old".into(),
                PendingBridge {
                    bridge_id: "b-old".into(),
                    caller_wire: "aa".into(),
                    callee_wire: "cc".into(),
                    call_id: "c-old".into(),
                    caller_token: "t3".into(),
                    callee_token: "t4".into(),
                    expires: now - Duration::from_secs(1),
                },
            );
        }
        assert_eq!(reg.count_for_peer("aa").await, 2);
        reg.purge_expired().await;
        assert_eq!(reg.count_for_peer("aa").await, 1);
        assert_eq!(reg.count_for_peer("bb").await, 1);
        assert_eq!(reg.count_for_peer("cc").await, 0);
    }

    #[tokio::test]
    async fn drop_caller_pending_replaces_same_callee() {
        let reg = registry_for_test(4, 90);
        let now = Instant::now();
        {
            let mut g = reg.inner.lock().await;
            g.pending.insert(
                "old".into(),
                PendingBridge {
                    bridge_id: "old".into(),
                    caller_wire: "caller".into(),
                    callee_wire: "callee".into(),
                    call_id: "c-old".into(),
                    caller_token: "a".into(),
                    callee_token: "b".into(),
                    expires: now + Duration::from_secs(90),
                },
            );
        }
        reg.drop_caller_pending_for_replace("caller", "callee", "c-new")
            .await;
        assert_eq!(reg.count_for_peer("caller").await, 0);
    }

    #[tokio::test]
    async fn concurrent_admits_do_not_exceed_per_peer_cap() {
        let reg = registry_for_test(4, 90);
        let mut tasks = Vec::new();
        for i in 0..12 {
            let reg = reg.clone();
            tasks.push(tokio::spawn(async move {
                reg.admit("caller", &format!("callee-{i}"), &format!("c-{i}"))
                    .await
                    .is_ok()
            }));
        }
        let mut ok = 0;
        for task in tasks {
            if task.await.unwrap() {
                ok += 1;
            }
        }
        assert_eq!(ok, 4);
        assert_eq!(reg.count_for_peer("caller").await, 4);
    }

    #[tokio::test]
    async fn replace_frees_a_slot_and_expired_pending_drops_half_open() {
        let reg = registry_for_test(1, 90);
        let (id, _token) = reg.admit("caller", "callee", "c1").await.unwrap();
        assert!(reg.admit("caller", "other", "c2").await.is_err());
        let (replaced, _) = reg.admit("caller", "callee", "c3").await.unwrap();
        assert_ne!(id, replaced);
        assert_eq!(pending_ids(&reg).await, vec![replaced.clone()]);

        {
            let mut g = reg.inner.lock().await;
            let pending = g.pending.get(&replaced).unwrap().clone();
            let (tx, _rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
            g.active.insert(
                replaced.clone(),
                ActiveBridge {
                    caller_wire: pending.caller_wire.clone(),
                    callee_wire: pending.callee_wire.clone(),
                    call_id: pending.call_id.clone(),
                    caller_tx: Some(tx),
                    callee_tx: None,
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: false,
                    notify: Arc::new(Notify::new()),
                },
            );
            g.pending.get_mut(&replaced).unwrap().expires = Instant::now() - Duration::from_secs(1);
        }
        reg.purge_expired().await;
        assert_eq!(reg.count_for_peer("caller").await, 0);
        assert!(reg.inner.lock().await.active.is_empty());
    }

    async fn pending_ids(self_reg: &BridgeRegistry) -> Vec<String> {
        let g = self_reg.inner.lock().await;
        let mut ids: Vec<String> = g.pending.keys().cloned().collect();
        ids.sort();
        ids
    }

    #[test]
    fn validate_call_id_rejects_control_and_oversized() {
        assert_eq!(validate_call_id("ok-id").unwrap(), "ok-id");
        assert!(validate_call_id("").is_err());
        assert!(validate_call_id("   ").is_err());
        assert!(validate_call_id("bad\nid").is_err());
        let huge = "x".repeat(MAX_CALL_ID_LEN + 1);
        assert!(validate_call_id(&huge).is_err());
    }

    fn minimal_active(caller: &str, callee: &str, call_id: &str) -> ActiveBridge {
        ActiveBridge {
            caller_wire: caller.into(),
            callee_wire: callee.into(),
            call_id: call_id.into(),
            caller_tx: None,
            callee_tx: None,
            to_caller: Vec::new(),
            to_callee: Vec::new(),
            bytes_relayed: 0,
            was_paired: false,
            notify: Arc::new(Notify::new()),
        }
    }

    #[test]
    fn active_admit_allowed_respects_global_cap() {
        let mut g = BridgeInner {
            pending: HashMap::new(),
            active: HashMap::new(),
        };
        assert!(active_admit_allowed(&g, "new"));
        for i in 0..MAX_TOTAL_ACTIVE_BRIDGES {
            g.active.insert(
                format!("k-{i}"),
                minimal_active(&format!("c-{i}"), "r", &format!("call-{i}")),
            );
        }
        assert_eq!(g.active.len(), MAX_TOTAL_ACTIVE_BRIDGES);
        assert!(!active_admit_allowed(&g, "fresh"));
        g.active.insert("fresh".into(), minimal_active("c", "r", "call"));
        assert!(active_admit_allowed(&g, "fresh"));
    }

    #[test]
    fn push_unpaired_respects_frame_and_byte_caps() {
        let mut buf = Vec::new();
        let chunk = vec![1u8; 1024];
        for _ in 0..MAX_UNPAIRED_BUFFER_FRAMES {
            assert!(push_unpaired(&mut buf, &chunk));
        }
        assert!(!push_unpaired(&mut buf, &chunk));
        assert_eq!(buf.len(), MAX_UNPAIRED_BUFFER_FRAMES);

        let mut buf = Vec::new();
        assert!(!push_unpaired(&mut buf, &vec![0u8; MAX_UNPAIRED_BUFFER_BYTES + 1]));
        let half = vec![2u8; MAX_UNPAIRED_BUFFER_BYTES / 2 + 1];
        assert!(push_unpaired(&mut buf, &half));
        assert!(!push_unpaired(&mut buf, &half));
    }

    #[tokio::test]
    async fn paired_bridge_frees_slots_when_first_leg_detaches() {
        let reg = registry_for_test(4, 90);
        let (bridge_id, _caller_tok) = reg.admit("caller", "callee", "c-pair").await.unwrap();
        let notify = Arc::new(Notify::new());
        let (caller_tx, _caller_rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
        let (callee_tx, _callee_rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
        {
            let mut g = reg.inner.lock().await;
            let pending = g.pending.get(&bridge_id).unwrap().clone();
            g.active.insert(
                bridge_id.clone(),
                ActiveBridge {
                    caller_wire: pending.caller_wire.clone(),
                    callee_wire: pending.callee_wire.clone(),
                    call_id: pending.call_id.clone(),
                    caller_tx: Some(caller_tx),
                    callee_tx: Some(callee_tx),
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: true,
                    notify: Arc::clone(&notify),
                },
            );
            g.pending.remove(&bridge_id);
        }
        assert_eq!(reg.count_for_peer("caller").await, 1);
        {
            let mut g = reg.inner.lock().await;
            detach_bridge_role(&mut g, &bridge_id, "caller");
        }
        assert_eq!(reg.count_for_peer("caller").await, 0);
        assert_eq!(reg.count_for_peer("callee").await, 0);
        assert!(reg.inner.lock().await.active.is_empty());
    }

    #[tokio::test]
    async fn global_pending_cap_blocks_new_admits() {
        let reg = registry_for_test(4, 90);
        let now = Instant::now();
        {
            let mut g = reg.inner.lock().await;
            for i in 0..MAX_TOTAL_PENDING_BRIDGES {
                g.pending.insert(
                    format!("fill-{i}"),
                    PendingBridge {
                        bridge_id: format!("fill-{i}"),
                        caller_wire: format!("caller-{i}"),
                        callee_wire: "remote".into(),
                        call_id: format!("c-{i}"),
                        caller_token: "a".into(),
                        callee_token: "b".into(),
                        expires: now + Duration::from_secs(90),
                    },
                );
            }
        }
        let err = reg.admit("fresh-caller", "fresh-callee", "c-new").await;
        assert!(matches!(
            err,
            Err(ServerError::RateLimited(ref m)) if m.contains("pending capacity")
        ));
    }

    #[tokio::test]
    async fn callee_pending_poll_respects_response_cap() {
        let reg = registry_for_test(128, 90);
        for i in 0..48u8 {
            reg.admit(&format!("caller-{i}"), "victim", &format!("cap-{i}"))
                .await
                .unwrap();
        }
        let g = reg.inner.lock().await;
        let w = "victim".to_ascii_lowercase();
        let listed: Vec<_> = g
            .pending
            .values()
            .filter(|b| b.callee_wire.to_ascii_lowercase() == w)
            .take(MAX_BRIDGE_PENDING_RESPONSE)
            .collect();
        assert_eq!(listed.len(), MAX_BRIDGE_PENDING_RESPONSE);
        assert!(g.pending.len() >= 48);
    }

    #[test]
    fn relay_queue_blocks_when_peer_outbound_is_full() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        assert!(try_forward_to_peer(&tx, &[1]).is_ok());
        assert!(try_forward_to_peer(&tx, &[2]).is_err());
    }

    #[tokio::test]
    async fn admit_revoke_does_not_leave_peer_count() {
        let reg = registry_for_test(2, 90);
        let (id, _) = reg.admit("caller", "callee", "c1").await.unwrap();
        assert_eq!(reg.count_for_peer("caller").await, 1);
        reg.revoke_admitted(&id).await;
        assert_eq!(reg.count_for_peer("caller").await, 0);
        assert!(reg.inner.lock().await.pending.is_empty());
    }

    /// Simulates the relay outbound task signaling `cancel` when WebSocket send fails.
    #[tokio::test]
    async fn relay_outbound_failure_wakes_bridge_session() {
        let cancel = Arc::new(Notify::new());
        let wait = cancel.notified();
        let relay_cancel = Arc::clone(&cancel);
        tokio::spawn(async move {
            relay_cancel.notify_waiters();
        });
        tokio::time::timeout(Duration::from_millis(200), wait)
            .await
            .expect("relay failure should wake session waiters");
    }

    #[tokio::test]
    async fn purge_expired_half_open_active_wakes_attached_leg() {
        let reg = registry_for_test(4, 90);
        let notify = Arc::new(Notify::new());
        let bridge_id = "half-open".to_string();
        let expired = Instant::now() - Duration::from_secs(5);
        let (caller_tx, _caller_rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
        {
            let mut g = reg.inner.lock().await;
            g.pending.insert(
                bridge_id.clone(),
                PendingBridge {
                    bridge_id: bridge_id.clone(),
                    caller_wire: "caller".into(),
                    callee_wire: "callee".into(),
                    call_id: "c-expire".into(),
                    caller_token: "ct".into(),
                    callee_token: "kt".into(),
                    expires: expired,
                },
            );
            g.active.insert(
                bridge_id.clone(),
                ActiveBridge {
                    caller_wire: "caller".into(),
                    callee_wire: "callee".into(),
                    call_id: "c-expire".into(),
                    caller_tx: Some(caller_tx),
                    callee_tx: None,
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: false,
                    notify: Arc::clone(&notify),
                },
            );
        }
        let wait = notify.notified();
        reg.purge_expired().await;
        tokio::time::timeout(Duration::from_millis(500), wait)
            .await
            .expect("purge should wake attached leg");
        assert!(reg.inner.lock().await.active.is_empty());
        assert_eq!(reg.count_for_peer("caller").await, 0);
    }

    #[tokio::test]
    async fn pending_expire_then_new_admit_and_replace_combo() {
        let reg = registry_for_test(2, 1);
        let (stale_id, _) = reg.admit("caller", "callee", "call-stale").await.unwrap();
        assert_eq!(reg.count_for_peer("caller").await, 1);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        reg.purge_expired().await;
        assert!(reg.inner.lock().await.pending.is_empty());
        assert_eq!(reg.count_for_peer("caller").await, 0);

        let (fresh_id, _) = reg.admit("caller", "callee", "call-fresh").await.unwrap();
        assert_ne!(stale_id, fresh_id);
        assert_eq!(reg.count_for_peer("caller").await, 1);

        let (chained_id, _) = reg.admit("caller", "callee", "call-chain").await.unwrap();
        assert_ne!(chained_id, fresh_id);
        assert_eq!(reg.count_for_peer("caller").await, 1);
        let pending = reg.inner.lock().await.pending.get(&chained_id).cloned();
        assert!(pending.is_some());
        assert!(reg.inner.lock().await.pending.get(&fresh_id).is_none());

        let notify = Arc::new(Notify::new());
        let (tx, _rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
        {
            let mut g = reg.inner.lock().await;
            let p = g.pending.get(&chained_id).unwrap().clone();
            g.active.insert(
                chained_id.clone(),
                ActiveBridge {
                    caller_wire: p.caller_wire,
                    callee_wire: p.callee_wire,
                    call_id: p.call_id,
                    caller_tx: Some(tx),
                    callee_tx: None,
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: false,
                    notify: Arc::clone(&notify),
                },
            );
            g.pending.get_mut(&chained_id).unwrap().expires =
                Instant::now() - Duration::from_secs(1);
        }
        reg.purge_expired().await;
        assert_eq!(reg.count_for_peer("caller").await, 0);
        assert!(reg.inner.lock().await.active.is_empty());

        let (after_id, _) = reg.admit("caller", "callee", "call-after").await.unwrap();
        assert_eq!(reg.count_for_peer("caller").await, 1);
        assert!(reg.inner.lock().await.pending.contains_key(&after_id));
    }

    #[tokio::test]
    async fn paired_relay_backpressure_frees_both_peers() {
        let reg = registry_for_test(4, 90);
        let notify = Arc::new(Notify::new());
        let (caller_leg_tx, _caller_leg_rx) = tokio::sync::mpsc::channel(1);
        let caller_forward = caller_leg_tx.clone();
        let (callee_leg_tx, _callee_leg_rx) = tokio::sync::mpsc::channel(MAX_RELAY_OUTBOUND_FRAMES);
        let bridge_id = "bp".to_string();
        {
            let mut g = reg.inner.lock().await;
            g.active.insert(
                bridge_id.clone(),
                ActiveBridge {
                    caller_wire: "caller".into(),
                    callee_wire: "callee".into(),
                    call_id: "c-bp".into(),
                    caller_tx: Some(caller_leg_tx),
                    callee_tx: Some(callee_leg_tx),
                    to_caller: Vec::new(),
                    to_callee: Vec::new(),
                    bytes_relayed: 0,
                    was_paired: true,
                    notify: Arc::clone(&notify),
                },
            );
        }
        assert_eq!(reg.count_for_peer("caller").await, 1);
        assert_eq!(reg.count_for_peer("callee").await, 1);

        assert!(try_forward_to_peer(&caller_forward, &[1]).is_ok());
        assert!(try_forward_to_peer(&caller_forward, &[2]).is_err());

        let wait = notify.notified();
        {
            let mut g = reg.inner.lock().await;
            detach_bridge_role(&mut g, &bridge_id, "callee");
        }
        tokio::time::timeout(Duration::from_millis(500), wait)
            .await
            .expect("detach should wake peer leg");
        assert_eq!(reg.count_for_peer("caller").await, 0);
        assert_eq!(reg.count_for_peer("callee").await, 0);
    }
}
