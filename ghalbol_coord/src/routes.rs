use crate::AppState;
use crate::auth::{
    ChallengePurpose, ChallengeStore, decode_nonce_hex, decode_signature_hex,
    verify_registration_signature,
};
use crate::bridge::{bridge_challenge, get_bridge_pending, post_bridge_request, ws_bridge_connect};
use crate::error::{ApiResult, ServerError};
use crate::identity::{check_identity_param_len, normalize_identity_wire, percent_decode_uri_component};
use crate::json_extract::ApiJson;
use crate::limits::{KeyedRateLimit, bridge_poll_limiter, heartbeat_limiter};
use crate::presence::{PeerEndpoint, PeerRecord, is_public_routable_ipv4};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

fn spawn_join_err(_: tokio::task::JoinError) -> ServerError {
    ServerError::Internal("internal error".into())
}

/// Challenge store (ephemeral; not persisted) plus per-identity request budgets.
pub struct RouteState {
    pub app: Arc<AppState>,
    pub challenges: Mutex<ChallengeStore>,
    pub heartbeat_limits: Mutex<KeyedRateLimit>,
    pub bridge_poll_limits: Mutex<KeyedRateLimit>,
}

pub fn router(app: Arc<AppState>) -> Router {
    let state = Arc::new(RouteState {
        app: Arc::clone(&app),
        challenges: Mutex::new(ChallengeStore::default()),
        heartbeat_limits: Mutex::new(heartbeat_limiter()),
        bridge_poll_limits: Mutex::new(bridge_poll_limiter()),
    });

    Router::new()
        .route("/health", get(health))
        .route("/v1/register/challenge", post(register_challenge))
        .route("/v1/register", post(register))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/peers/{identity_wire}", get(get_peer))
        .route("/v1/peers", get(list_peers))
        .route("/v1/bridge/challenge", post(bridge_challenge))
        .route("/v1/bridge/request", post(post_bridge_request))
        .route("/v1/bridge/pending", get(get_bridge_pending))
        .route("/v1/bridge/connect", get(ws_bridge_connect))
        .with_state(state)
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
    database: bool,
    bridge: bool,
}

async fn health(State(state): State<Arc<RouteState>>) -> Json<HealthResponse> {
    let db = Arc::clone(&state.app.presence);
    let database = tokio::task::spawn_blocking(move || db.ping())
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some();
    Json(HealthResponse {
        ok: database,
        service: "ghalbol_coord",
        database,
        bridge: true,
    })
}

#[derive(Deserialize)]
struct ChallengeRequest {
    public_key_hex: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    public_key_hex: String,
    nonce_hex: String,
    expires_in_secs: u64,
    message_domain: &'static str,
}

async fn register_challenge(
    State(state): State<Arc<RouteState>>,
    ApiJson(req): ApiJson<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    check_identity_param_len(req.public_key_hex.trim())?;
    let pk = normalize_identity_wire(&req.public_key_hex)?;
    let mut ch = state.challenges.lock().await;
    ch.purge_expired();
    let pending = ch.issue(
        ChallengePurpose::Register,
        &pk,
        state.app.config.challenge_ttl,
    )?;
    let expires_in_secs = pending
        .expires_at
        .checked_duration_since(Instant::now())
        .map(|d| d.as_secs().max(1))
        .unwrap_or(1);
    Ok(Json(ChallengeResponse {
        public_key_hex: pk,
        nonce_hex: hex::encode(pending.nonce),
        expires_in_secs,
        message_domain: "ghalbol:register:v1",
    }))
}

#[derive(Deserialize)]
struct RegisterRequest {
    public_key_hex: String,
    nonce_hex: String,
    signature_hex: String,
    endpoints: Vec<PeerEndpoint>,
    #[serde(default)]
    transport_capabilities: Vec<String>,
    ipv6: Option<String>,
    ipv4: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    ok: bool,
    peer: PeerRecord,
}

async fn register(
    State(state): State<Arc<RouteState>>,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    check_identity_param_len(req.public_key_hex.trim())?;
    let pk = normalize_identity_wire(&req.public_key_hex)?;
    let caps = clean_capabilities(req.transport_capabilities)?;
    let ipv4 = clean_ip_hint(req.ipv4, false)?;
    let ipv6 = clean_ip_hint(req.ipv6, true)?;
    validate_endpoints(&req.endpoints)?;
    let endpoints = req.endpoints;
    let nonce = decode_nonce_hex(&req.nonce_hex)?;
    let sig = decode_signature_hex(&req.signature_hex)?;

    {
        let mut ch = state.challenges.lock().await;
        // Peek first so a bad signature does not burn the victim's challenge.
        ch.peek_valid(ChallengePurpose::Register, &pk, &nonce)?;
        verify_registration_signature(&pk, &nonce, &sig)?;
    }

    let store = Arc::clone(&state.app.presence);
    let pk_for_store = pk.clone();
    let peer = tokio::task::spawn_blocking(move || {
        store.merge_client_register(pk_for_store, endpoints, caps, ipv6, ipv4)
    })
    .await
    .map_err(spawn_join_err)??;

    {
        let mut ch = state.challenges.lock().await;
        ch.take_valid(ChallengePurpose::Register, &pk, &nonce)?;
    }

    tracing::info!(
        public_key = %peer.public_key_hex,
        endpoints = peer.endpoints.len(),
        "peer registered"
    );
    Ok(Json(RegisterResponse { ok: true, peer }))
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    public_key_hex: String,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    ok: bool,
    peer: PeerRecord,
}

async fn heartbeat(
    State(state): State<Arc<RouteState>>,
    ApiJson(req): ApiJson<HeartbeatRequest>,
) -> ApiResult<Json<HeartbeatResponse>> {
    let wire = req.public_key_hex.trim();
    check_identity_param_len(wire)?;
    {
        let mut limits = state.heartbeat_limits.lock().await;
        if !limits.allow(wire) {
            return Err(ServerError::RateLimited("heartbeat rate limit".into()));
        }
    }
    let pk = normalize_identity_wire(wire)?;
    let store = Arc::clone(&state.app.presence);
    let ttl = state.app.config.presence_ttl;
    let peer = tokio::task::spawn_blocking(move || store.heartbeat(&pk, ttl))
        .await
        .map_err(spawn_join_err)??;
    tracing::debug!(public_key = %peer.public_key_hex, "heartbeat");
    Ok(Json(HeartbeatResponse { ok: true, peer }))
}

async fn get_peer(
    State(state): State<Arc<RouteState>>,
    Path(identity_wire): Path<String>,
) -> ApiResult<Json<PeerRecord>> {
    check_identity_param_len(&identity_wire)?;
    let store = Arc::clone(&state.app.presence);
    let ttl = state.app.config.presence_ttl;
    let decoded = percent_decode_uri_component(&identity_wire);
    check_identity_param_len(&decoded)?;
    if decoded.trim().is_empty() {
        return Err(ServerError::BadRequest("identity empty".into()));
    }
    let pk = normalize_identity_wire(&decoded)?;
    let peer = tokio::task::spawn_blocking(move || store.get(&pk, ttl))
        .await
        .map_err(spawn_join_err)??;
    Ok(Json(peer))
}

#[derive(Serialize)]
struct PeerListResponse {
    peers: Vec<PeerRecord>,
}

async fn list_peers(State(state): State<Arc<RouteState>>) -> ApiResult<Json<PeerListResponse>> {
    let store = Arc::clone(&state.app.presence);
    let ttl = state.app.config.presence_ttl;
    let peers = tokio::task::spawn_blocking(move || store.list_online(ttl))
        .await
        .map_err(spawn_join_err)??;
    Ok(Json(PeerListResponse { peers }))
}

fn clean_capabilities(caps: Vec<String>) -> ApiResult<Vec<String>> {
    let caps = if caps.is_empty() {
        vec!["tcp".into(), "sync-v1".into()]
    } else {
        caps
    };
    if caps.len() > 16 {
        return Err(ServerError::BadRequest(
            "too many transport capabilities".into(),
        ));
    }
    for cap in &caps {
        if cap.is_empty()
            || cap.len() > 64
            || cap.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(ServerError::BadRequest(
                "invalid transport capability".into(),
            ));
        }
    }
    Ok(caps)
}

fn clean_ip_hint(value: Option<String>, v6: bool) -> ApiResult<Option<String>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 64 {
        return Err(ServerError::BadRequest("ip hint too long".into()));
    }
    if v6 {
        let ip: std::net::Ipv6Addr = trimmed
            .parse()
            .map_err(|_| ServerError::BadRequest("ipv6 hint invalid".into()))?;
        Ok(Some(ip.to_string()))
    } else {
        let ip: std::net::Ipv4Addr = trimmed
            .parse()
            .map_err(|_| ServerError::BadRequest("ipv4 hint invalid".into()))?;
        Ok(Some(ip.to_string()))
    }
}

const MAX_ENDPOINT_SCHEME_LEN: usize = 8;

fn validate_endpoints(endpoints: &[PeerEndpoint]) -> ApiResult<()> {
    if endpoints.is_empty() {
        return Err(ServerError::BadRequest("endpoints empty".into()));
    }
    if endpoints.len() > 24 {
        return Err(ServerError::BadRequest("too many endpoints".into()));
    }
    for ep in endpoints {
        let scheme = ep.scheme.trim();
        if scheme.is_empty() || scheme.len() > MAX_ENDPOINT_SCHEME_LEN {
            return Err(ServerError::BadRequest("invalid endpoint scheme".into()));
        }
        match scheme {
            "tcp" | "quic" => {
                if ep.host.trim().is_empty() || ep.host.len() > 15 {
                    return Err(ServerError::BadRequest("endpoint host empty".into()));
                }
                if ep.port == 0 {
                    return Err(ServerError::BadRequest("endpoint port required".into()));
                }
                if !is_public_routable_ipv4(&ep.host) {
                    return Err(ServerError::BadRequest(
                        "coord register accepts public routable IPv4 TCP or QUIC only — \
                         LAN uses mDNS; WAN text uses delivery server"
                            .into(),
                    ));
                }
            }
            _ => {
                return Err(ServerError::BadRequest("unsupported endpoint scheme".into()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod register_tests {
    use super::*;
    use crate::auth::{ChallengePurpose, ChallengeStore, registration_message_digest};
    use crate::presence::{PeerEndpoint, PresenceStore};
    use secp256k1::{Secp256k1, SecretKey};

    fn secp_pk(seed: u8) -> (SecretKey, String) {
        let sk = SecretKey::from_byte_array([seed; 32]).expect("key");
        let secp = Secp256k1::new();
        let wire = hex::encode(sk.public_key(&secp).serialize());
        (sk, wire)
    }

    fn sample_ep(host: &str) -> Vec<PeerEndpoint> {
        vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: host.into(),
            port: 41_234,
        }]
    }

    #[test]
    fn presence_capacity_rejection_does_not_consume_register_challenge() {
        let store = PresenceStore::open_in_memory().expect("db");
        let ep = sample_ep("203.0.113.60");
        for seed in 0u8..4 {
            let pk = secp_pk(seed + 60).1;
            store
                .merge_client_register(pk, ep.clone(), vec!["tcp".into()], None, None)
                .expect("under cap");
        }
        let (sk, pk) = secp_pk(99);
        let mut ch = ChallengeStore::default();
        let challenge = ch
            .issue(
                ChallengePurpose::Register,
                &pk,
                std::time::Duration::from_secs(120),
            )
            .unwrap();
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(
            registration_message_digest(&challenge.nonce, &pk),
            &sk,
        );
        ch.peek_valid(ChallengePurpose::Register, &pk, &challenge.nonce)
            .unwrap();
        verify_registration_signature(&pk, &challenge.nonce, &sig.serialize_der()).unwrap();
        let capped = store.merge_client_register(
            pk.clone(),
            sample_ep("203.0.113.99"),
            vec!["tcp".into()],
            None,
            None,
        );
        assert!(matches!(capped, Err(ServerError::RateLimited(_))));
        ch.take_valid(ChallengePurpose::Register, &pk, &challenge.nonce)
            .expect("challenge must survive presence capacity rejection");
    }
}

#[cfg(test)]
mod route_http_tests {
    use super::*;
    use crate::auth::registration_message_digest;
    use crate::identity::MAX_IDENTITY_PARAM_LEN;
    use crate::{AppState, ServerConfig};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn short_ttl_app() -> axum::Router {
        let mut config = ServerConfig::default();
        config.challenge_ttl = Duration::from_millis(1);
        let state = Arc::new(AppState::open_in_memory(config).expect("db"));
        router(state)
    }

    async fn post_json(
        app: &axum::Router,
        uri: &str,
        body: serde_json::Value,
        content_type: bool,
    ) -> axum::response::Response {
        let mut req = Request::builder().method("POST").uri(uri);
        if content_type {
            req = req.header("content-type", "application/json");
        }
        app.clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn error_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["error"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn register_challenge_requires_json_content_type() {
        let app = test_router();
        let (_sk, pk) = secp_pair(41);
        let resp = post_json(
            &app,
            "/v1/register/challenge",
            serde_json::json!({ "public_key_hex": pk }),
            false,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(error_text(resp).await.contains("content-type"));
    }

    #[tokio::test]
    async fn expired_challenge_valid_register_body_returns_unauthorized() {
        let app = short_ttl_app();
        let (sk, pk_hex) = secp_pair(42);
        let secp = Secp256k1::new();

        let ch = post_json(
            &app,
            "/v1/register/challenge",
            serde_json::json!({ "public_key_hex": pk_hex }),
            true,
        )
        .await;
        assert_eq!(ch.status(), StatusCode::OK);
        let ch_body = axum::body::to_bytes(ch.into_body(), 4096).await.unwrap();
        let ch_json: serde_json::Value = serde_json::from_slice(&ch_body).unwrap();
        let nonce_hex = ch_json["nonce_hex"].as_str().unwrap();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&hex::decode(nonce_hex).unwrap());
        let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);

        tokio::time::sleep(Duration::from_millis(10)).await;

        let reg = post_json(
            &app,
            "/v1/register",
            serde_json::json!({
                "public_key_hex": pk_hex,
                "nonce_hex": nonce_hex,
                "signature_hex": hex::encode(sig.serialize_der()),
                "endpoints": [{ "scheme": "tcp", "host": "203.0.113.42", "port": 41234 }]
            }),
            true,
        )
        .await;
        assert_eq!(reg.status(), StatusCode::UNAUTHORIZED);
        let err = error_text(reg).await;
        assert!(err.contains("expired"));
        assert!(!err.to_lowercase().contains("join"));
    }

    #[tokio::test]
    async fn lookup_empty_identity_is_bad_request() {
        let app = test_router();
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/peers/%20")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(error_text(resp).await.contains("identity empty"));
    }

    #[tokio::test]
    async fn heartbeat_oversized_identity_wire_rejected_before_store() {
        let app = test_router();
        let huge = "ab".repeat(MAX_IDENTITY_PARAM_LEN + 1);
        let resp = post_json(
            &app,
            "/v1/heartbeat",
            serde_json::json!({ "public_key_hex": huge }),
            true,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err = error_text(resp).await;
        assert!(err.contains("too long"));
    }

    fn test_router() -> axum::Router {
        let state = Arc::new(AppState::open_in_memory(ServerConfig::default()).expect("db"));
        router(state)
    }

    fn secp_pair(seed: u8) -> (SecretKey, String) {
        let sk = SecretKey::from_byte_array([seed; 32]).expect("key");
        let secp = Secp256k1::new();
        let pk = hex::encode(sk.public_key(&secp).serialize());
        (sk, pk)
    }
}

