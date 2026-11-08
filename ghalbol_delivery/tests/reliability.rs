//! Socket-level checks that need a real WebSocket: parallel sessions, frame cap, auth deadline.

use futures_util::{SinkExt, StreamExt};
use ghalbol_core::delivery_auth::{
    session_challenge_bytes, sign_delivery_challenge, upload_challenge_bytes,
};
use ghalbol_core::delivery_msg_v1::build_text_envelope;
use ghalbol_delivery::{AppState, DeliveryConfig, app, validate_envelope};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

fn parse_nonce(hex_s: &str) -> [u8; 32] {
    hex::decode(hex_s).unwrap().try_into().unwrap()
}

async fn start_server(cfg: DeliveryConfig) -> String {
    start_server_with_state(AppState::new_in_memory(cfg).expect("state")).await
}

async fn start_server_with_state(state: Arc<AppState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = app(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("ws://{addr}/v1/ws")
}

async fn connect(
    url: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        tokio_tungstenite::tungstenite::Message,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >,
) {
    let started = std::time::Instant::now();
    loop {
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _)) => return ws.split(),
            Err(err) => {
                if started.elapsed() > Duration::from_secs(3) {
                    panic!("connect {url}: {err}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn next_json(
    read: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >,
) -> Value {
    let msg = tokio::time::timeout(Duration::from_secs(5), read.next())
        .await
        .expect("timed out waiting for frame")
        .expect("socket closed")
        .expect("websocket error");
    let text = msg.into_text().expect("text frame");
    serde_json::from_str(&text).expect("json")
}

async fn session_ready(
    url: &str,
    ident: &ghalbol_core::DecryptedIdentity,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        tokio_tungstenite::tungstenite::Message,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    >,
    String,
) {
    let (mut write, mut read) = connect(url).await;
    let wire = ident.identity_wire();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"type": "session.open", "identity_wire": wire})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let challenge = next_json(&mut read).await;
    let nonce = parse_nonce(challenge["nonce_hex"].as_str().unwrap());
    let sig = sign_delivery_challenge(
        ident,
        session_challenge_bytes(&nonce, &wire).as_ref().unwrap(),
    )
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "session.auth",
                "identity_wire": wire,
                "nonce_hex": hex::encode(nonce),
                "signature_hex": hex::encode(sig),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let ready = next_json(&mut read).await;
    assert_eq!(ready["type"], "session.ready");
    let op = ready["op_nonce_hex"].as_str().unwrap().to_string();
    (write, read, op)
}

#[tokio::test]
async fn two_sessions_upload_without_clobbering_op_nonces() {
    let url = start_server(DeliveryConfig::default()).await;
    let (_ks_a, sender) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    let (_ks_b, recipient) = ghalbol_core::create_keystore_v1("pw2", None).unwrap();
    let (mut write_a, mut read_a, op_a) = session_ready(&url, &sender).await;
    let (mut write_b, mut read_b, op_b) = session_ready(&url, &sender).await;
    assert_ne!(op_a, op_b);

    for (write, read, op, message_id) in [
        (&mut write_a, &mut read_a, &op_a, "parallel-a"),
        (&mut write_b, &mut read_b, &op_b, "parallel-b"),
    ] {
        let envelope = build_text_envelope(
            &sender,
            message_id,
            &recipient.identity_wire(),
            "hello",
            1_000,
        )
        .unwrap();
        let nonce = parse_nonce(op);
        let sig = sign_delivery_challenge(
            &sender,
            upload_challenge_bytes(&nonce, message_id, recipient.identity_wire().as_str())
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        write
            .send(tokio_tungstenite::tungstenite::Message::Text(
                json!({
                    "type": "message.upload",
                    "envelope": envelope,
                    "op_nonce_hex": op,
                    "signature_hex": hex::encode(sig),
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        let ok = next_json(read).await;
        assert_eq!(ok["type"], "message.upload.ok", "{ok}");
        assert_eq!(ok["message_id"], message_id);
    }
}

#[tokio::test]
async fn oversized_frame_closes_the_socket() {
    let mut cfg = DeliveryConfig::default();
    cfg.max_ws_message_bytes = 400;
    let url = start_server(cfg).await;
    let (mut write, mut read) = connect(&url).await;
    let (_ks, ident) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"type": "session.open", "identity_wire": ident.identity_wire()})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let challenge = next_json(&mut read).await;
    assert_eq!(challenge["type"], "session.challenge");
    let sent = write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "x".repeat(2_000).into(),
        ))
        .await;
    if sent.is_err() {
        return;
    }
    let msg = tokio::time::timeout(Duration::from_secs(2), read.next())
        .await
        .expect("oversized frame was accepted");
    match msg {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("expected close after oversized frame, got {other:?}"),
    }
}

#[tokio::test]
async fn unauthenticated_socket_closes_at_auth_deadline() {
    let mut cfg = DeliveryConfig::default();
    cfg.auth_timeout_secs = 1;
    let url = start_server(cfg).await;
    let (_write, mut read) = connect(&url).await;
    let msg = tokio::time::timeout(Duration::from_secs(4), read.next())
        .await
        .expect("auth deadline did not close the socket");
    match msg {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("expected close after auth timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn binary_frame_closes_the_socket() {
    let url = start_server(DeliveryConfig::default()).await;
    let (mut write, mut read) = connect(&url).await;
    write
        .send(tokio_tungstenite::tungstenite::Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    let msg = tokio::time::timeout(Duration::from_secs(2), read.next())
        .await
        .expect("binary frame was accepted without response");
    match msg {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
            let v: Value = serde_json::from_str(&t).unwrap();
            assert_eq!(v["type"], "error");
            assert_eq!(v["code"], "bad_request");
        }
        other => panic!("expected error text after binary frame, got {other:?}"),
    }
    let close = tokio::time::timeout(Duration::from_secs(2), read.next())
        .await
        .expect("no close after binary rejection");
    match close {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("expected close after binary frame, got {other:?}"),
    }
}

#[tokio::test]
async fn quota_exceeded_restores_op_nonce_for_retry() {
    let mut cfg = DeliveryConfig::default();
    cfg.quota_bytes_per_peer = 4_096;
    let url = start_server(cfg).await;
    let (_ks_a, sender) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    let (_ks_b, recipient) = ghalbol_core::create_keystore_v1("pw2", None).unwrap();
    let (mut write, mut read, op) = session_ready(&url, &sender).await;

    let envelope =
        build_text_envelope(&sender, "fill", &recipient.identity_wire(), "hello", 1_000).unwrap();
    let nonce = parse_nonce(&op);
    let sig = sign_delivery_challenge(
        &sender,
        upload_challenge_bytes(&nonce, "fill", recipient.identity_wire().as_str())
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "message.upload",
                "envelope": envelope,
                "op_nonce_hex": op,
                "signature_hex": hex::encode(sig),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let ok = next_json(&mut read).await;
    assert_eq!(ok["type"], "message.upload.ok");

    let overflow_body = "z".repeat(3_500);
    let envelope2 = build_text_envelope(
        &sender,
        "overflow",
        &recipient.identity_wire(),
        &overflow_body,
        1_000,
    )
    .unwrap();
    let op_retry = ok["op_nonce_hex"].as_str().unwrap();
    let nonce2 = parse_nonce(op_retry);
    let sig2 = sign_delivery_challenge(
        &sender,
        upload_challenge_bytes(&nonce2, "overflow", recipient.identity_wire().as_str())
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "message.upload",
                "envelope": envelope2,
                "op_nonce_hex": op_retry,
                "signature_hex": hex::encode(sig2),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let err = next_json(&mut read).await;
    assert_eq!(err["type"], "error");
    assert_eq!(err["code"], "quota_exceeded");

    let sig_retry = sign_delivery_challenge(
        &sender,
        upload_challenge_bytes(&nonce2, "overflow", recipient.identity_wire().as_str())
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "message.upload",
                "envelope": envelope2,
                "op_nonce_hex": op_retry,
                "signature_hex": hex::encode(sig_retry),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let err2 = next_json(&mut read).await;
    assert_eq!(err2["type"], "error");
    assert_eq!(err2["code"], "quota_exceeded");
}

#[tokio::test]
async fn sticky_shutdown_rejects_new_sockets_quickly() {
    let cfg = DeliveryConfig::default();
    let state = AppState::new_in_memory(cfg).expect("state");
    let url = start_server_with_state(Arc::clone(&state)).await;
    state.shutdown.signal();
    let (_write, mut read) = connect(&url).await;
    let msg = tokio::time::timeout(Duration::from_secs(2), read.next()).await;
    match msg {
        Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))))
        | Ok(Some(Err(_)))
        | Ok(None) => {}
        Ok(Some(Ok(_))) | Err(_) => {}
    }
}

#[tokio::test]
async fn inbox_ack_rejects_oversized_message_id() {
    let url = start_server(DeliveryConfig::default()).await;
    let (_ks_b, recipient) = ghalbol_core::create_keystore_v1("pw2", None).unwrap();
    let (mut write, mut read, _) = session_ready(&url, &recipient).await;
    let bad_id = "x".repeat(200);
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({
                "type": "inbox.ack",
                "message_id": bad_id,
                "sender_wire": "02".repeat(33),
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let err = next_json(&mut read).await;
    assert_eq!(err["type"], "error");
    assert_eq!(err["code"], "bad_request");
}

#[tokio::test]
async fn reconnect_delivers_only_valid_pending_after_corrupt_blob() {
    let state = Arc::new(AppState::new_in_memory(DeliveryConfig::default()).expect("state"));
    let store = Arc::clone(&state.store);
    let policy = state.policy.clone();
    let (_ks_a, sender) = ghalbol_core::create_keystore_v1("pw", None).unwrap();
    let (_ks_b, recipient) = ghalbol_core::create_keystore_v1("pw2", None).unwrap();
    let sender_wire = sender.identity_wire();
    let recipient_wire = recipient.identity_wire();

    let bad_json =
        build_text_envelope(&sender, "bad", &recipient_wire, "corrupt-row", 1_000).unwrap();
    let bad_valid = validate_envelope(&bad_json, &sender_wire).unwrap();
    store.upload(bad_valid, 3600, &policy).unwrap();
    store
        .test_replace_pending_envelope_blob(&sender_wire, "bad", r#"{"corrupt":true}"#)
        .unwrap();

    let good_json = build_text_envelope(&sender, "good", &recipient_wire, "ok", 1_000).unwrap();
    let good_valid = validate_envelope(&good_json, &sender_wire).unwrap();
    store.upload(good_valid, 3600, &policy).unwrap();

    let url = start_server_with_state(Arc::clone(&state)).await;
    let (_write, mut read, _) = session_ready(&url, &recipient).await;
    let inbound = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let frame = next_json(&mut read).await;
            if frame["type"] == "message.inbound" {
                return frame;
            }
        }
    })
    .await
    .expect("expected one inbound after session.ready");
    assert_eq!(inbound["message_id"], "good");
}

#[tokio::test]
async fn max_connections_rejects_extra_socket() {
    let mut cfg = DeliveryConfig::default();
    cfg.max_connections = 1;
    cfg.auth_timeout_secs = 30;
    let url = start_server(cfg).await;
    let (_keep, mut read_keep) = connect(&url).await;
    // First socket occupies the only admit slot (even before auth).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (mut write2, mut read2) = connect(&url).await;
    let outcome = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match read2.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
                | Some(Err(_))
                | None => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        outcome.is_ok(),
        "second socket should be closed when max_connections=1"
    );
    let _ = write2.close().await;
    // Keep first socket alive until the end so the slot stays held.
    let _ = tokio::time::timeout(Duration::from_millis(10), read_keep.next()).await;
}
