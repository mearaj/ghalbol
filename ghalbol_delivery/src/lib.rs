//! Ghal Bol delivery server — temporary encrypted message mailbox.
//!
//! See `docs/GHALBOL_DELIVERY.md` and `docs/GHALBOL_DELIVERY_WIRE_V1.md`.

mod auth;
mod config;
mod db;
mod envelope;
mod error;
mod identity;
mod instance;
mod mailbox_ops;
mod policy;
mod routes;
mod store;
mod ws;

pub use config::{DeliveryConfig, DELIVERY_DATA_DIR, DATA_NAMESPACE, default_data_dir};
pub use error::{DeliveryError, Result};
pub use envelope::{parse_wire_message_id, ValidatedEnvelope, validate_envelope};
pub use instance::instance_id;
pub use mailbox_ops::{export_mailbox, import_mailbox, mailbox_stats, MailboxStats};
pub use policy::PolicyLimits;
pub use routes::{router, spawn_background_tasks};
pub use store::MailboxStore;

use axum::Router;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use ws::SessionRegistry;

/// Process-lifetime counters exposed on `GET /health`.
#[derive(Debug, Default)]
pub struct OpsCounters {
    pub rejected_frames: AtomicU64,
    pub auth_failures: AtomicU64,
    pub uploads_total: AtomicU64,
    pub messages_expired: AtomicU64,
    pub rejected_connections: AtomicU64,
}

/// Notifies sockets and the TTL sweeper to stop. `signal` sticks for late subscribers.
pub struct ShutdownHandle {
    tx: tokio::sync::watch::Sender<bool>,
}

impl ShutdownHandle {
    fn new() -> Self {
        let (tx, _rx) = tokio::sync::watch::channel(false);
        Self { tx }
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.tx.subscribe()
    }

    pub fn signal(&self) {
        // Sticky: late subscribers must observe shutdown already requested.
        let _ = self.tx.send_replace(true);
    }
}

/// Shared application state.
pub struct AppState {
    pub config: DeliveryConfig,
    pub store: Arc<MailboxStore>,
    pub policy: PolicyLimits,
    pub registry: SessionRegistry,
    pub shutdown: ShutdownHandle,
    pub ops: Arc<OpsCounters>,
}

impl AppState {
    pub fn new(config: DeliveryConfig) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data_dir)?;
        let db_path = config.data_dir.join("mailbox.db");
        let conn = db::open_and_migrate(&db_path)?;
        assemble(config, conn)
    }

    pub fn new_in_memory(config: DeliveryConfig) -> Result<Arc<Self>> {
        assemble(config, db::open_memory()?)
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.config.data_dir
    }
}

fn assemble(mut config: DeliveryConfig, conn: rusqlite::Connection) -> Result<Arc<AppState>> {
    config.normalize();
    let store = MailboxStore::shared(conn, &config);
    let policy = PolicyLimits::from_config(&config);
    let registry = SessionRegistry::with_limit(config.max_connections);
    Ok(Arc::new(AppState {
        config,
        store,
        policy,
        registry,
        shutdown: ShutdownHandle::new(),
        ops: Arc::new(OpsCounters::default()),
    }))
}

pub fn app(state: Arc<AppState>) -> Router {
    spawn_background_tasks(state.clone());
    router(state)
}
