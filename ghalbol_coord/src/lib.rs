//! Ghal Bol coordination server — presence and endpoint discovery only.
//!
//! Does not store message content or transcripts. See workspace `README.md`.

mod auth;
mod bridge;
mod bridge_auth;
mod config;
mod db;
mod error;
mod godaddy_ddns;
pub mod identity;
mod json_extract;
mod limits;
mod presence;
mod routes;

pub use auth::{registration_challenge_bytes, registration_message_digest};
pub use bridge_auth::bridge_request_bytes;
pub use bridge::BridgeRegistry;
pub use config::ServerConfig;
pub use error::ServerError;
pub use godaddy_ddns::{DdnsConfig, spawn_ddns_task};
pub use identity::MAX_IDENTITY_PARAM_LEN;
pub use limits::HEARTBEAT_MAX_HITS;
pub use presence::{PeerEndpoint, PeerRecord, PresenceStore};

use axum::Router;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use tokio::sync::{Semaphore, watch};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Max JSON body size for API requests (64 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

/// Concurrent HTTP work. Further requests are refused with 429.
pub const MAX_INFLIGHT_REQUESTS: usize = 512;

/// Shared application state.
pub struct AppState {
    pub config: ServerConfig,
    pub presence: Arc<PresenceStore>,
    pub bridge: BridgeRegistry,
    shutdown_tx: watch::Sender<bool>,
    /// Keeps the watch channel open so `send` stores the flag with no other subscribers.
    _shutdown_rx: watch::Receiver<bool>,
}

impl AppState {
    fn assemble(config: ServerConfig, presence: PresenceStore) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            presence: Arc::new(presence),
            bridge: BridgeRegistry::from_env(),
            shutdown_tx,
            _shutdown_rx: shutdown_rx,
        }
    }

    pub fn open(config: ServerConfig) -> Result<Self, ServerError> {
        let presence = PresenceStore::open(&config.database_path)?;
        tracing::info!(db = %config.database_path.display(), "sqlite ready");
        Ok(Self::assemble(config, presence))
    }

    /// Used by integration tests (`:memory:` SQLite).
    pub fn open_in_memory(config: ServerConfig) -> Result<Self, ServerError> {
        Ok(Self::assemble(config, PresenceStore::open_in_memory()?))
    }

    /// Sticky shutdown. Late subscribers still observe it (unlike `Notify::notify_waiters`).
    pub fn request_shutdown(&self) {
        // `send_replace` keeps the value even when no receivers are subscribed yet.
        self.shutdown_tx.send_replace(true);
    }

    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }
}

/// HTTP router (handlers only).
pub fn router(state: Arc<AppState>) -> Router {
    routes::router(state)
}

/// Production app: routes + body limit + in-flight cap + request tracing.
pub fn app(state: Arc<AppState>) -> Router {
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS));
    router(state)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let inflight = Arc::clone(&inflight);
                async move {
                    match inflight.try_acquire_owned() {
                        Ok(permit) => {
                            let _permit = permit;
                            let response: Response = next.run(req).await;
                            response
                        }
                        Err(_) => {
                            error::ServerError::RateLimited("too many in-flight requests".into())
                                .into_response()
                        }
                    }
                }
            },
        ))
        .layer(TraceLayer::new_for_http())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::time::Duration;
    use tower::ServiceExt;

    #[tokio::test]
    async fn oversized_json_body_is_rejected_by_app_stack() {
        let state = Arc::new(AppState::open_in_memory(ServerConfig::default()).unwrap());
        let app = app(state);
        let pad = "a".repeat(MAX_REQUEST_BODY_BYTES);
        let body = format!(r#"{{"public_key_hex":"{pad}"}}"#);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/heartbeat")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::PAYLOAD_TOO_LARGE
                || resp.status() == StatusCode::BAD_REQUEST,
            "unexpected status {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn shutdown_is_visible_to_late_subscribers() {
        let state = AppState::open_in_memory(ServerConfig::default()).unwrap();
        state.request_shutdown();
        let mut rx = state.shutdown_rx();
        assert!(*rx.borrow());
        let got = tokio::time::timeout(Duration::from_secs(1), rx.wait_for(|v| *v))
            .await
            .expect("late subscriber must observe shutdown")
            .expect("watch sender still open");
        assert!(*got);
    }
}
