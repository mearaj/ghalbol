use axum::body::Body;
use ghalbol_delivery::{AppState, DeliveryConfig, app};
use tower::ServiceExt;

#[tokio::test]
async fn health_ok() {
    let mut cfg = DeliveryConfig::default();
    cfg.data_dir = std::env::temp_dir().join("ghalbol_delivery_test");
    let state = AppState::new(cfg).expect("state");
    let response = app(state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["service"], "ghalbol_delivery");
    assert_eq!(json["ok"], true);
    assert_eq!(json["rejected_frames"], 0);
    assert_eq!(json["rejected_connections"], 0);
    assert_eq!(json["auth_failures"], 0);
    assert_eq!(json["uploads_total"], 0);
    assert!(json["messages_expired"].is_number());
    assert!(json["live_sockets"].is_number());
}
