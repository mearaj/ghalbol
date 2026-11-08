//! Client ↔ delivery-server integration (op nonce restore + retry).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ghalbol_core::delivery_client::connect_and_auth;
use ghalbol_delivery::{AppState, DeliveryConfig, app};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

async fn start_delivery_server(cfg: DeliveryConfig) -> String {
    let state = AppState::new_in_memory(cfg).expect("state");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn client_reuses_op_nonce_after_quota_rejected_upload() {
    let mut cfg = DeliveryConfig::default();
    // Room for one small mailbox row; oversize plaintext fails after op-nonce consume + restore.
    cfg.quota_bytes_per_peer = 900;
    let url = start_delivery_server(cfg).await;
    let (_ks_a, sender) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    let (_ks_b, recipient) = ghalbol_core::create_keystore_v1("pw2", None).unwrap();
    let mut session = connect_and_auth(&url, &sender, None).await.expect("connect");
    let op_before = session.op_nonce_hex.clone().expect("op nonce");
    let oversized = "x".repeat(8_192);
    let fail = session
        .upload_text(
            &sender,
            "quota-fail-mid",
            &recipient.identity_wire(),
            &oversized,
            None,
        )
        .await;
    assert!(fail.is_err(), "expected quota rejection, got {fail:?}");
    assert_eq!(
        session.op_nonce_hex.as_deref(),
        Some(op_before.as_str()),
        "client must keep restored op nonce after rejected upload"
    );
    session
        .upload_text(
            &sender,
            "quota-ok-mid",
            &recipient.identity_wire(),
            "ok",
            None,
        )
        .await
        .expect("retry upload on same session");
    assert_ne!(
        session.op_nonce_hex.as_deref(),
        Some(op_before.as_str()),
        "successful upload must rotate op nonce"
    );
}

async fn ws_url_mock_session_ready(op_nonce_hex: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let op = op_nonce_hex.to_string();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = accept_async(tcp).await.unwrap();
        let (mut write, mut read) = ws.split();
        let open = read.next().await.transpose().unwrap().unwrap();
        let open_text = open.into_text().unwrap();
        let open_v: serde_json::Value = serde_json::from_str(&open_text).unwrap();
        let wire = open_v["identity_wire"].as_str().unwrap().to_string();
        let nonce = [0x11u8; 32];
        let challenge = json!({
            "type": "session.challenge",
            "nonce_hex": hex::encode(nonce),
        });
        write
            .send(Message::Text(challenge.to_string().into()))
            .await
            .unwrap();
        let auth = read.next().await.transpose().unwrap().unwrap();
        let _ = auth.into_text().unwrap();
        let ready = json!({
            "type": "session.ready",
            "op_nonce_hex": op,
            "policy": serde_json::Value::Null,
            "quota": serde_json::Value::Null,
        });
        write
            .send(Message::Text(ready.to_string().into()))
            .await
            .unwrap();
        let _ = wire; // silence unused in spawned task
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn connect_rejects_invalid_op_nonce_in_session_ready() {
    let url = ws_url_mock_session_ready("not-valid-op-nonce").await;
    let (_ks, id) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    match connect_and_auth(&url, &id, None).await {
        Err(e) => assert!(
            e.contains("nonce must be 32 bytes hex"),
            "unexpected err: {e}"
        ),
        Ok(_) => panic!("expected invalid session.ready op_nonce to fail connect"),
    }
}

async fn ws_url_mock_stall_after_session_open() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = accept_async(tcp).await.unwrap();
        let (_write, mut read) = ws.split();
        let _open = read.next().await.transpose().unwrap();
        std::future::pending::<()>().await;
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn connect_and_auth_respects_cancel_while_waiting_for_challenge() {
    static STOP: AtomicBool = AtomicBool::new(false);
    STOP.store(false, Ordering::SeqCst);
    let url = ws_url_mock_stall_after_session_open().await;
    let (_ks, id) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    let stop = &STOP;
    let url_clone = url.clone();
    let join = tokio::spawn(async move { connect_and_auth(&url_clone, &id, Some(stop)).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    STOP.store(true, Ordering::SeqCst);
    let outcome = tokio::time::timeout(Duration::from_secs(3), join)
        .await
        .expect("cancel should not wait full frame timeout")
        .expect("join");
    match outcome {
        Err(e) => assert_eq!(e, "delivery stopped"),
        Ok(_) => panic!("expected cancel mid-handshake waiting for challenge"),
    }
}

#[tokio::test]
async fn connect_and_auth_respects_cancel_before_handshake() {
    static STOP: AtomicBool = AtomicBool::new(false);
    STOP.store(true, Ordering::SeqCst);
    let url = ws_url_mock_session_ready(&"ab".repeat(32)).await;
    let (_ks, id) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    match connect_and_auth(&url, &id, Some(&STOP)).await {
        Err(e) => assert_eq!(e, "delivery stopped"),
        Ok(_) => panic!("expected cancel to abort connect"),
    }
    STOP.store(false, Ordering::SeqCst);
}
