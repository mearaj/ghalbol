//! Shared process-wide coord runtime state and accessors.

use crate::coord::{CoordEndpoint, CoordHttpClient};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;

pub(super) const MAX_COORD_ENDPOINTS: usize = 16;
/// Max coord/relay servers in the configured list (TRANSPORT.md).
pub(super) const MAX_COORD_SERVERS: usize = 8;

pub(super) struct CoordGlobals {
    pub(super) base_urls: Mutex<Vec<String>>,
    pub(super) insecure_tls: AtomicBool,
    pub(super) endpoints: Mutex<Vec<CoordEndpoint>>,
    /// Coord servers where the last register+heartbeat cycle succeeded.
    pub(super) registered_on: Mutex<HashSet<String>>,
    /// Bootstrap relay we last reserved on (prefer matching circuit for coord register).
    pub(super) preferred_relay_peer_id: Mutex<Option<String>>,
    /// libp2p local peer id — coord POST TCP must terminate on this id.
    pub(super) local_peer_id: Mutex<Option<String>>,
    /// `host:port` keys from `GET /v1/relay` — never POST these as peer TCP.
    pub(super) relay_bootstrap_tcp: Mutex<HashSet<String>>,
    pub(super) heartbeat_stop: AtomicBool,
    pub(super) heartbeat_join: Mutex<Option<JoinHandle<()>>>,
}

pub(super) static COORD: OnceLock<CoordGlobals> = OnceLock::new();
/// Serializes challenge + register HTTP (parallel calls cause nonce mismatch on the server).
pub(super) static COORD_REG_HTTP: OnceLock<Mutex<()>> = OnceLock::new();
pub(super) static COORD_REG_WORKER_BUSY: AtomicBool = AtomicBool::new(false);
pub(super) static COORD_REG_PENDING: AtomicBool = AtomicBool::new(false);
pub(super) static COORD_REGISTERED: AtomicBool = AtomicBool::new(false);
pub(super) static COORD_LAST_OK_MS: AtomicU64 = AtomicU64::new(0);
pub(super) static COORD_LAST_REG_ATTEMPT_MS: AtomicU64 = AtomicU64::new(0);
/// Avoid flapping `coord_registered` on one transient mobile-data failure.
pub(super) static COORD_CONSEC_FAILS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
pub(super) static RELAY_PRESENCE_CHECK_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(not(test))]
pub(super) static RELAY_PRESENCE_POLL_LAST_END_MS: AtomicU64 = AtomicU64::new(0);

/// Fast poll after reservation (coord HTTP flap ~seconds); slow poll until mirror or circuit down.
#[cfg(not(test))]
pub(super) const RELAY_PRESENCE_POLL_FAST_MS: u64 = 500;
#[cfg(not(test))]
pub(super) const RELAY_PRESENCE_POLL_FAST_ATTEMPTS: u32 = 12;
#[cfg(not(test))]
pub(super) const RELAY_PRESENCE_POLL_SLOW_MS: u64 = 2_000;
#[cfg(not(test))]
pub(super) const RELAY_PRESENCE_POLL_SLOW_ATTEMPTS: u32 = 30;
pub(super) const RELAY_PRESENCE_RESCHEDULE_MIN_MS: u64 = 5_000;
/// When already registered, relay self-poll is guardrail-only — do not spawn every coord_tick.
pub(super) const RELAY_PRESENCE_RESCHEDULE_REGISTERED_MS: u64 = 30_000;
/// Cap recover_coord / degraded-tick relay polls during coord HTTP flap (TRANSPORT.md § storm throttle).
pub(super) const COORD_RECOVERY_MIN_MS: u64 = 15_000;
/// Throttle repeated heartbeat-failure warnings when many threads overlap during recovery.
pub(super) const COORD_HEARTBEAT_FAIL_LOG_MIN_MS: u64 = 30_000;

pub(super) static COORD_RECOVERY_LAST_MS: AtomicU64 = AtomicU64::new(0);
pub(super) static COORD_HEARTBEAT_FAIL_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);
pub(super) static RELAY_PRESENCE_VISIBLE_LOG_LAST_MS: AtomicU64 = AtomicU64::new(0);

/// Backoff repeated coord peer lookups from the daemon/UI RPC path.
/// Key: peer public_key_hex.
pub(super) static COORD_LOOKUP_BACKOFF: OnceLock<Mutex<HashMap<String, CoordLookupBackoff>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(super) struct CoordLookupBackoff {
    pub(super) next_allowed_ms: u64,
    pub(super) step_ms: u64,
}

pub(super) fn lookup_backoff_map() -> &'static Mutex<HashMap<String, CoordLookupBackoff>> {
    COORD_LOOKUP_BACKOFF.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Min gap between full challenge+register cycles when already registered (reduces coord HTTP 401 storms).
pub(super) const MIN_REGISTER_INTERVAL_MS: u64 = 10_000;
/// Retry sooner when never successfully registered.
pub(super) const MIN_REGISTER_RETRY_MS: u64 = 2_000;
pub(super) const HEARTBEAT_INTERVAL_SECS: u64 = 25;
/// If no successful heartbeat/self-lookup in this window, force re-register (server TTL ~90s).
pub(super) const PRESENCE_STALE_MS: u64 = 70_000;

pub(super) fn coord_reg_http_lock() -> &'static Mutex<()> {
    COORD_REG_HTTP.get_or_init(|| Mutex::new(()))
}

pub(super) fn coord_globals() -> &'static CoordGlobals {
    COORD.get_or_init(|| CoordGlobals {
        base_urls: Mutex::new(Vec::new()),
        insecure_tls: AtomicBool::new(false),
        endpoints: Mutex::new(Vec::new()),
        registered_on: Mutex::new(HashSet::new()),
        preferred_relay_peer_id: Mutex::new(None),
        local_peer_id: Mutex::new(None),
        relay_bootstrap_tcp: Mutex::new(HashSet::new()),
        heartbeat_stop: AtomicBool::new(false),
        heartbeat_join: Mutex::new(None),
    })
}

/// Legacy no-op — native connect uses identity wire, not libp2p PeerId.
pub fn coord_set_local_peer_id(peer: String) {
    if let Ok(mut g) = coord_globals().local_peer_id.lock() {
        *g = Some(peer);
    }
}

pub(super) fn coord_local_peer_id() -> Option<String> {
    coord_globals()
        .local_peer_id
        .lock()
        .ok()
        .and_then(|g| g.clone())
}

pub(super) fn coord_relay_bootstrap_tcp_keys() -> HashSet<String> {
    coord_globals()
        .relay_bootstrap_tcp
        .lock()
        .ok()
        .map(|g| g.clone())
        .unwrap_or_default()
}

/// Remember relay bootstrap host:ports from `GET /v1/relay` (never POST as peer TCP).
pub fn coord_note_relay_bootstrap_addrs(addrs: &[String]) {
    let keys = crate::p2p::network_transport::relay_bootstrap_tcp_keys(addrs);
    if keys.is_empty() {
        return;
    }
    if let Ok(mut g) = coord_globals().relay_bootstrap_tcp.lock() {
        g.extend(keys);
    }
}

pub(super) fn client_for(base: &str) -> Result<CoordHttpClient, String> {
    CoordHttpClient::new(base, coord_globals().insecure_tls.load(Ordering::Relaxed))
        .map_err(|e| e.to_string())
}

pub(super) fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
