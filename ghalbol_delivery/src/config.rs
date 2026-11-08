use std::net::SocketAddr;
use std::path::PathBuf;

/// Delivery server data root — separate from the mobile app (`com.ghalbol`).
pub const DATA_NAMESPACE: &str = "com.ghalbol.delivery";

/// Subdirectory under the app data root for delivery server files.
pub const DELIVERY_DATA_DIR: &str = "ghalbol_delivery";

pub const DEFAULT_MAX_WS_MESSAGE_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_WS_MESSAGE_BYTES_CAP: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;
pub const DEFAULT_MAX_FRAMES_PER_SEC: u32 = 200;
pub const DEFAULT_AUTH_TIMEOUT_SECS: u64 = 30;
/// Caps adversarial “many tiny queued messages” storms (byte quota alone is not enough).
pub const DEFAULT_MAX_PENDING_MESSAGES_PER_PEER: u64 = 8192;
/// Non-queued outbox metadata rows per sender (delivered / read / expired).
pub const DEFAULT_MAX_TERMINAL_ROWS_PER_PEER: u64 = 8192;

/// Runtime configuration for the delivery server.
#[derive(Clone, Debug)]
pub struct DeliveryConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub default_ttl_secs: u64,
    pub quota_bytes_per_peer: u64,
    pub max_ws_message_bytes: usize,
    pub max_connections: usize,
    pub max_frames_per_sec: u32,
    pub auth_timeout_secs: u64,
    pub max_pending_messages_per_peer: u64,
    pub max_terminal_rows_per_peer: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8770".parse().expect("valid default listen"),
            data_dir: default_data_dir(),
            tls_cert: None,
            tls_key: None,
            min_ttl_secs: 3600,
            max_ttl_secs: 30 * 24 * 3600,
            default_ttl_secs: 7 * 24 * 3600,
            quota_bytes_per_peer: 500 * 1024 * 1024,
            max_ws_message_bytes: DEFAULT_MAX_WS_MESSAGE_BYTES,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_frames_per_sec: DEFAULT_MAX_FRAMES_PER_SEC,
            auth_timeout_secs: DEFAULT_AUTH_TIMEOUT_SECS,
            max_pending_messages_per_peer: DEFAULT_MAX_PENDING_MESSAGES_PER_PEER,
            max_terminal_rows_per_peer: DEFAULT_MAX_TERMINAL_ROWS_PER_PEER,
        }
    }
}

/// `~/.local/share/com.ghalbol.delivery/ghalbol_delivery/` on Linux.
pub fn default_data_dir() -> PathBuf {
    let mut base = directories::ProjectDirs::from_path(PathBuf::from(DATA_NAMESPACE))
        .map(|d| d.data_local_dir().to_path_buf())
        .unwrap_or_else(fallback_data_root);
    base.push(DELIVERY_DATA_DIR);
    base
}

fn fallback_data_root() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".local/share")
        .join(DATA_NAMESPACE)
        .join(DELIVERY_DATA_DIR)
}

impl DeliveryConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_LISTEN") {
            if let Ok(addr) = s.parse() {
                cfg.listen = addr;
            } else {
                tracing::warn!(listen = %s, "GHALBOL_DELIVERY_LISTEN invalid; using default");
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_DATA_DIR") {
            let t = s.trim();
            if !t.is_empty() {
                cfg.data_dir = PathBuf::from(t);
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_TLS_CERT") {
            let t = s.trim();
            if !t.is_empty() {
                cfg.tls_cert = Some(PathBuf::from(t));
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_TLS_KEY") {
            let t = s.trim();
            if !t.is_empty() {
                cfg.tls_key = Some(PathBuf::from(t));
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_MIN_TTL_SECS") {
            if let Ok(v) = s.parse() {
                cfg.min_ttl_secs = v;
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_MAX_TTL_SECS") {
            if let Ok(v) = s.parse() {
                cfg.max_ttl_secs = v;
            }
        }
        if let Ok(s) = std::env::var("GHALBOL_DELIVERY_DEFAULT_TTL_SECS") {
            if let Ok(v) = s.parse() {
                cfg.default_ttl_secs = v;
            }
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_QUOTA_BYTES_PER_PEER") {
            cfg.quota_bytes_per_peer = v;
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_MAX_WS_MESSAGE_BYTES") {
            cfg.max_ws_message_bytes = usize::try_from(v).unwrap_or(MAX_WS_MESSAGE_BYTES_CAP);
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_MAX_CONNECTIONS") {
            cfg.max_connections = usize::try_from(v).unwrap_or(DEFAULT_MAX_CONNECTIONS);
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_MAX_FRAMES_PER_SEC") {
            cfg.max_frames_per_sec = u32::try_from(v).unwrap_or(DEFAULT_MAX_FRAMES_PER_SEC);
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_AUTH_TIMEOUT_SECS") {
            cfg.auth_timeout_secs = v;
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_MAX_PENDING_MESSAGES_PER_PEER") {
            cfg.max_pending_messages_per_peer = v;
        }
        if let Some(v) = env_u64("GHALBOL_DELIVERY_MAX_TERMINAL_ROWS_PER_PEER") {
            cfg.max_terminal_rows_per_peer = v;
        }
        cfg.normalize();
        cfg
    }

    pub fn normalize(&mut self) {
        if self.min_ttl_secs == 0 {
            tracing::warn!("min ttl was 0; using 1");
            self.min_ttl_secs = 1;
        }
        if self.max_ttl_secs < self.min_ttl_secs {
            tracing::warn!(
                min = self.min_ttl_secs,
                max = self.max_ttl_secs,
                "max ttl below min; raising max"
            );
            self.max_ttl_secs = self.min_ttl_secs;
        }
        if self.default_ttl_secs < self.min_ttl_secs || self.default_ttl_secs > self.max_ttl_secs
        {
            let clamped = self
                .default_ttl_secs
                .clamp(self.min_ttl_secs, self.max_ttl_secs);
            tracing::warn!(
                default = self.default_ttl_secs,
                clamped,
                "default ttl outside policy; clamping"
            );
            self.default_ttl_secs = clamped;
        }
        if self.quota_bytes_per_peer == 0 {
            tracing::warn!("quota was 0; restoring default");
            self.quota_bytes_per_peer = 500 * 1024 * 1024;
        }
        if self.max_ws_message_bytes == 0 {
            self.max_ws_message_bytes = DEFAULT_MAX_WS_MESSAGE_BYTES;
        } else if self.max_ws_message_bytes > MAX_WS_MESSAGE_BYTES_CAP {
            tracing::warn!(
                configured = self.max_ws_message_bytes,
                cap = MAX_WS_MESSAGE_BYTES_CAP,
                "websocket message cap too high; clamping"
            );
            self.max_ws_message_bytes = MAX_WS_MESSAGE_BYTES_CAP;
        }
        if self.max_connections == 0 {
            self.max_connections = DEFAULT_MAX_CONNECTIONS;
        } else if self.max_connections > 100_000 {
            self.max_connections = 100_000;
        }
        if self.max_frames_per_sec == 0 {
            self.max_frames_per_sec = DEFAULT_MAX_FRAMES_PER_SEC;
        }
        if self.auth_timeout_secs == 0 {
            self.auth_timeout_secs = DEFAULT_AUTH_TIMEOUT_SECS;
        }
        if self.max_pending_messages_per_peer == 0 {
            self.max_pending_messages_per_peer = DEFAULT_MAX_PENDING_MESSAGES_PER_PEER;
        } else if self.max_pending_messages_per_peer > 1_000_000 {
            self.max_pending_messages_per_peer = 1_000_000;
        }
        if self.max_terminal_rows_per_peer == 0 {
            self.max_terminal_rows_per_peer = DEFAULT_MAX_TERMINAL_ROWS_PER_PEER;
        } else if self.max_terminal_rows_per_peer > 1_000_000 {
            self.max_terminal_rows_per_peer = 1_000_000;
        }
    }
}

fn env_u64(name: &str) -> Option<u64> {
    let Ok(raw) = std::env::var(name) else {
        return None;
    };
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    match t.parse() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(var = name, value = %t, "invalid integer; ignoring");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_repairs_inverted_ttl_and_zero_quota() {
        let mut cfg = DeliveryConfig::default();
        cfg.min_ttl_secs = 100;
        cfg.max_ttl_secs = 10;
        cfg.default_ttl_secs = 7 * 24 * 3600;
        cfg.quota_bytes_per_peer = 0;
        cfg.max_ws_message_bytes = MAX_WS_MESSAGE_BYTES_CAP + 10;
        cfg.normalize();
        assert_eq!(cfg.max_ttl_secs, 100);
        assert_eq!(cfg.default_ttl_secs, 100);
        assert_eq!(cfg.quota_bytes_per_peer, 500 * 1024 * 1024);
        assert_eq!(cfg.max_ws_message_bytes, MAX_WS_MESSAGE_BYTES_CAP);
    }
}
