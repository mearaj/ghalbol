//! In-process HTTP surface checks only — not P2P/WAN/LAN connectivity.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ghalbol_coord::{
    AppState, ServerConfig, MAX_IDENTITY_PARAM_LEN, MAX_REQUEST_BODY_BYTES, router,
};
use std::sync::Arc;
use tower::ServiceExt;

fn test_app() -> axum::Router {
    let config = ServerConfig::default();
    let state = Arc::new(AppState::open_in_memory(config).expect("in-memory db"));
    router(state)
}

async fn json_request(app: &axum::Router, method: &str, uri: &str) -> axum::response::Response {
    let req = Request::builder().method(method).uri(uri);
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn post_raw(app: &axum::Router, uri: &str, body: &str, content_type: bool) -> axum::response::Response {
    let mut req = Request::builder().method("POST").uri(uri);
    if content_type {
        req = req.header("content-type", "application/json");
    }
    app.clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn malformed_json_returns_bad_request_body() {
    let app = test_app();
    let resp = post_raw(&app, "/v1/heartbeat", "{not json", true).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert!(v["error"].as_str().unwrap().contains("json"));
}

#[tokio::test]
async fn oversized_peer_path_identity_is_rejected() {
    let app = test_app();
    let huge = "a".repeat(MAX_IDENTITY_PARAM_LEN + 64);
    let resp = json_request(&app, "GET", &format!("/v1/peers/{huge}")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert!(v["error"].as_str().unwrap().contains("too long"));
}

#[tokio::test]
async fn oversized_endpoint_scheme_is_rejected() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(26);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let resp = post_json(
        &app,
        "/v1/register",
        serde_json::json!({
            "public_key_hex": pk_hex,
            "nonce_hex": nonce_hex,
            "signature_hex": hex::encode(sig.serialize_der()),
            "endpoints": [{ "scheme": "x".repeat(32), "host": "203.0.113.26", "port": 9 }]
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("scheme"));
    assert!(!err.contains("xxxx"));
}

#[tokio::test]
async fn internal_errors_do_not_echo_join_details() {
    let app = test_app();
    let resp = post_json(
        &app,
        "/v1/heartbeat",
        serde_json::json!({ "public_key_hex": "not-a-real-key" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    let err = v["error"].as_str().unwrap().to_lowercase();
    assert!(!err.contains("join"));
}

#[tokio::test]
async fn oversized_signature_hex_is_rejected_without_burning_challenge() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(13);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let sig_hex = hex::encode(sig.serialize_der());
    let huge_sig = format!("{:0>258}", "ab");
    let rejected = post_json(
        &app,
        "/v1/register",
        register_body(&pk_hex, &nonce_hex, &huge_sig, "203.0.113.13"),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let v = json_body(rejected).await;
    assert!(v["error"]
        .as_str()
        .unwrap()
        .contains("signature length invalid"));

    let ok = post_json(
        &app,
        "/v1/register",
        register_body(&pk_hex, &nonce_hex, &sig_hex, "203.0.113.13"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_ok_with_database() {
    let app = test_app();
    let resp = json_request(&app, "GET", "/health").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json_body(resp).await;
    assert_eq!(v["ok"], true);
    assert_eq!(v["database"], true);
    assert_eq!(v["bridge"], true);
}

#[tokio::test]
async fn register_and_lookup_roundtrip() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::{Secp256k1, SecretKey};

    let app = test_app();
    let sk = SecretKey::from_byte_array([7u8; 32]).expect("key");
    let secp = Secp256k1::new();
    let pk_hex = hex::encode(sk.public_key(&secp).serialize());

    let ch_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register/challenge")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "public_key_hex": pk_hex }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ch_resp.status(), StatusCode::OK);
    let ch = json_body(ch_resp).await;
    let nonce_hex = ch["nonce_hex"].as_str().unwrap();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&hex::decode(nonce_hex).unwrap());
    let digest = registration_message_digest(&nonce, &pk_hex);
    let sig = secp.sign_ecdsa(digest, &sk);

    let reg_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "public_key_hex": pk_hex,
                        "nonce_hex": nonce_hex,
                        "signature_hex": hex::encode(sig.serialize_der()),
                        "endpoints": [{
                            "scheme": "tcp",
                            "host": "203.0.113.50",
                            "port": 41234
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reg_resp.status(), StatusCode::OK);

    let lookup = json_request(&app, "GET", &format!("/v1/peers/{pk_hex}")).await;
    assert_eq!(lookup.status(), StatusCode::OK);
    let v = json_body(lookup).await;
    assert_eq!(v["public_key_hex"], pk_hex);
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn secp_identity(seed: u8) -> (secp256k1::SecretKey, String) {
    let sk = secp256k1::SecretKey::from_byte_array([seed; 32]).expect("key");
    let secp = secp256k1::Secp256k1::new();
    let pk = hex::encode(sk.public_key(&secp).serialize());
    (sk, pk)
}

async fn issue_register_nonce(app: &axum::Router, pk_hex: &str) -> (String, [u8; 32]) {
    let ch_resp = post_json(
        app,
        "/v1/register/challenge",
        serde_json::json!({ "public_key_hex": pk_hex }),
    )
    .await;
    assert_eq!(ch_resp.status(), StatusCode::OK);
    let ch = json_body(ch_resp).await;
    let nonce_hex = ch["nonce_hex"].as_str().unwrap().to_string();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&hex::decode(&nonce_hex).unwrap());
    (nonce_hex, nonce)
}

fn register_body(pk_hex: &str, nonce_hex: &str, sig_hex: &str, host: &str) -> serde_json::Value {
    serde_json::json!({
        "public_key_hex": pk_hex,
        "nonce_hex": nonce_hex,
        "signature_hex": sig_hex,
        "endpoints": [{ "scheme": "tcp", "host": host, "port": 41234 }]
    })
}

#[tokio::test]
async fn wrong_nonce_and_bad_signature_do_not_burn_register_challenge() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(9);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;

    let wrong = post_json(
        &app,
        "/v1/register",
        register_body(&pk_hex, &"00".repeat(32), "30440220", "203.0.113.9"),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let digest = registration_message_digest(&nonce, &pk_hex);
    let bad_sig = secp.sign_ecdsa(
        digest,
        &secp256k1::SecretKey::from_byte_array([3u8; 32]).unwrap(),
    );
    let bad = post_json(
        &app,
        "/v1/register",
        register_body(
            &pk_hex,
            &nonce_hex,
            &hex::encode(bad_sig.serialize_der()),
            "203.0.113.9",
        ),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let ok = post_json(
        &app,
        "/v1/register",
        register_body(
            &pk_hex,
            &nonce_hex,
            &hex::encode(sig.serialize_der()),
            "203.0.113.9",
        ),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn bridge_challenge_does_not_replace_register_nonce() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(10);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let bridge = post_json(
        &app,
        "/v1/bridge/challenge",
        serde_json::json!({ "caller_identity_wire": pk_hex }),
    )
    .await;
    assert_eq!(bridge.status(), StatusCode::OK);
    let bridge_nonce = json_body(bridge).await["nonce_hex"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(bridge_nonce, nonce_hex);

    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let ok = post_json(
        &app,
        "/v1/register",
        register_body(
            &pk_hex,
            &nonce_hex,
            &hex::encode(sig.serialize_der()),
            "203.0.113.10",
        ),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn private_endpoint_is_rejected_without_burning_the_challenge() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(11);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let sig_hex = hex::encode(sig.serialize_der());
    let rejected = post_json(
        &app,
        "/v1/register",
        register_body(&pk_hex, &nonce_hex, &sig_hex, "192.168.1.9"),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let ok = post_json(
        &app,
        "/v1/register",
        register_body(&pk_hex, &nonce_hex, &sig_hex, "203.0.113.11"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn heartbeat_rate_limit_rejects_the_burst() {
    use ghalbol_coord::HEARTBEAT_MAX_HITS;
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(12);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let registered = post_json(
        &app,
        "/v1/register",
        register_body(
            &pk_hex,
            &nonce_hex,
            &hex::encode(sig.serialize_der()),
            "203.0.113.12",
        ),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::OK);

    for _ in 0..HEARTBEAT_MAX_HITS {
        let beat = post_json(
            &app,
            "/v1/heartbeat",
            serde_json::json!({ "public_key_hex": pk_hex }),
        )
        .await;
        assert_eq!(beat.status(), StatusCode::OK);
    }
    let limited = post_json(
        &app,
        "/v1/heartbeat",
        serde_json::json!({ "public_key_hex": pk_hex }),
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

async fn issue_bridge_nonce(app: &axum::Router, caller: &str) -> (String, [u8; 32]) {
    let ch_resp = post_json(
        app,
        "/v1/bridge/challenge",
        serde_json::json!({ "caller_identity_wire": caller }),
    )
    .await;
    assert_eq!(ch_resp.status(), StatusCode::OK);
    let ch = json_body(ch_resp).await;
    let nonce_hex = ch["nonce_hex"].as_str().unwrap().to_string();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&hex::decode(&nonce_hex).unwrap());
    (nonce_hex, nonce)
}

fn sign_bridge_request_secp(
    sk: &secp256k1::SecretKey,
    nonce: &[u8; 32],
    caller: &str,
    callee: &str,
    call_id: &str,
) -> String {
    use ghalbol_coord::bridge_request_bytes;
    use secp256k1::Secp256k1;
    use sha2::{Digest, Sha256};
    let msg = bridge_request_bytes(nonce, caller, callee, call_id).unwrap();
    let hash = Sha256::digest(&msg);
    let digest = secp256k1::Message::from_digest(hash.into());
    let sig = Secp256k1::new().sign_ecdsa(digest, sk);
    hex::encode(sig.serialize_der())
}

async fn post_bridge_request(
    app: &axum::Router,
    caller: &str,
    callee: &str,
    call_id: &str,
    nonce_hex: &str,
    sig_hex: &str,
) -> axum::response::Response {
    post_json(
        app,
        "/v1/bridge/request",
        serde_json::json!({
            "caller_identity_wire": caller,
            "peer_identity_wire": callee,
            "call_id": call_id,
            "nonce_hex": nonce_hex,
            "signature_hex": sig_hex,
        }),
    )
    .await
}

#[tokio::test]
async fn bridge_bad_signature_does_not_burn_challenge() {
    use secp256k1::Secp256k1;

    let app = test_app();
    let (caller_sk, caller) = secp_identity(22);
    let (_callee_sk, callee) = secp_identity(23);
    let call_id = "bridge-sig-burn";
    let (nonce_hex, nonce) = issue_bridge_nonce(&app, &caller).await;
    let secp = Secp256k1::new();
    let bad = secp.sign_ecdsa(
        secp256k1::Message::from_digest([0u8; 32]),
        &secp256k1::SecretKey::from_byte_array([44u8; 32]).unwrap(),
    );
    let reject = post_bridge_request(
        &app,
        &caller,
        &callee,
        call_id,
        &nonce_hex,
        &hex::encode(bad.serialize_der()),
    )
    .await;
    assert_eq!(reject.status(), StatusCode::UNAUTHORIZED);

    let good_sig = sign_bridge_request_secp(&caller_sk, &nonce, &caller, &callee, call_id);
    let ok = post_bridge_request(&app, &caller, &callee, call_id, &nonce_hex, &good_sig).await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_replay_after_success_is_rejected() {
    use ghalbol_coord::registration_message_digest;
    use secp256k1::Secp256k1;

    let app = test_app();
    let (sk, pk_hex) = secp_identity(24);
    let secp = Secp256k1::new();
    let (nonce_hex, nonce) = issue_register_nonce(&app, &pk_hex).await;
    let sig = secp.sign_ecdsa(registration_message_digest(&nonce, &pk_hex), &sk);
    let body = register_body(
        &pk_hex,
        &nonce_hex,
        &hex::encode(sig.serialize_der()),
        "203.0.113.24",
    );
    let ok = post_json(&app, "/v1/register", body.clone()).await;
    assert_eq!(ok.status(), StatusCode::OK);
    let replay = post_json(&app, "/v1/register", body).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversized_nonce_hex_rejected_without_decoding_megabytes() {
    let app = test_app();
    let (pk_hex, _) = {
        let (_sk, pk) = secp_identity(25);
        (pk, ())
    };
    let huge = "ab".repeat(65);
    let resp = post_json(
        &app,
        "/v1/register",
        serde_json::json!({
            "public_key_hex": pk_hex,
            "nonce_hex": huge,
            "signature_hex": "30440220",
            "endpoints": [{ "scheme": "tcp", "host": "203.0.113.25", "port": 1 }]
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert!(v["error"].as_str().unwrap().contains("nonce_hex"));
    let pad = "a".repeat(MAX_REQUEST_BODY_BYTES);
    let over = post_json(
        &app,
        "/v1/register",
        serde_json::json!({
            "public_key_hex": pad,
            "nonce_hex": "00".repeat(32),
            "signature_hex": "30440220",
            "endpoints": [{ "scheme": "tcp", "host": "203.0.113.25", "port": 1 }]
        }),
    )
    .await;
    assert_eq!(over.status(), StatusCode::BAD_REQUEST);
    let v = json_body(over).await;
    assert!(v["error"].as_str().unwrap().contains("too large"));
}

#[tokio::test]
async fn bridge_per_peer_limit_does_not_burn_challenge() {
    let app = test_app();
    let (caller_sk, caller) = secp_identity(20);
    for i in 0..4u8 {
        let (_sk, callee) = secp_identity(30 + i);
        let call_id = format!("call-limit-{i}");
        let (nonce_hex, nonce) = issue_bridge_nonce(&app, &caller).await;
        let sig = sign_bridge_request_secp(&caller_sk, &nonce, &caller, &callee, &call_id);
        let resp = post_bridge_request(&app, &caller, &callee, &call_id, &nonce_hex, &sig).await;
        assert_eq!(resp.status(), StatusCode::OK, "bridge admit {i}");
    }
    let (_sk, callee_extra) = secp_identity(40);
    let (nonce_hex, nonce) = issue_bridge_nonce(&app, &caller).await;
    let sig_limit = sign_bridge_request_secp(
        &caller_sk,
        &nonce,
        &caller,
        &callee_extra,
        "call-limit-extra",
    );
    let limited = post_bridge_request(
        &app,
        &caller,
        &callee_extra,
        "call-limit-extra",
        &nonce_hex,
        &sig_limit,
    )
    .await;
    assert_eq!(limited.status(), StatusCode::BAD_REQUEST);
    let retry = post_bridge_request(
        &app,
        &caller,
        &callee_extra,
        "call-limit-extra",
        &nonce_hex,
        &sig_limit,
    )
    .await;
    assert_eq!(
        retry.status(),
        StatusCode::BAD_REQUEST,
        "capped admit must not consume the challenge (not 401)"
    );
    let (_sk, callee_first) = secp_identity(30);
    let sig_replace = sign_bridge_request_secp(
        &caller_sk,
        &nonce,
        &caller,
        &callee_first,
        "call-replace-frees-slot",
    );
    let replace = post_bridge_request(
        &app,
        &caller,
        &callee_first,
        "call-replace-frees-slot",
        &nonce_hex,
        &sig_replace,
    )
    .await;
    assert_eq!(
        replace.status(),
        StatusCode::OK,
        "same nonce still valid after capped admit"
    );
}

#[tokio::test]
async fn bridge_challenge_rejects_oversized_identity_before_issue() {
    let app = test_app();
    let huge = "ab".repeat(MAX_IDENTITY_PARAM_LEN + 1);
    let resp = post_json(
        &app,
        "/v1/bridge/challenge",
        serde_json::json!({ "caller_identity_wire": huge }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert!(v["error"].as_str().unwrap().contains("too long"));
}

#[tokio::test]
async fn bridge_request_rejects_control_character_call_id() {
    let app = test_app();
    let (caller_sk, caller) = secp_identity(27);
    let (_sk, callee) = secp_identity(28);
    let (nonce_hex, nonce) = issue_bridge_nonce(&app, &caller).await;
    let sig = sign_bridge_request_secp(&caller_sk, &nonce, &caller, &callee, "ok-call");
    let resp = post_json(
        &app,
        "/v1/bridge/request",
        serde_json::json!({
            "caller_identity_wire": caller,
            "peer_identity_wire": callee,
            "call_id": "bad\ncall",
            "nonce_hex": nonce_hex,
            "signature_hex": sig,
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = json_body(resp).await;
    assert!(v["error"].as_str().unwrap().contains("call_id"));
}
