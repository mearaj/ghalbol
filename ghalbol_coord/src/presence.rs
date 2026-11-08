//! Peer presence and reachable endpoints — persisted in SQLite.

use crate::db;
use crate::error::{ApiResult, ServerError};
use crate::identity::normalize_identity_wire;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One transport endpoint the peer can be reached on (TCP for WAN presence mirror).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// Registered peer record returned to callers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub public_key_hex: String,
    pub endpoints: Vec<PeerEndpoint>,
    pub transport_capabilities: Vec<String>,
    pub ipv6: Option<String>,
    pub ipv4: Option<String>,
    pub last_heartbeat_unix_ms: u64,
}

/// SQLite-backed presence store (`Send` + `Sync` via mutex).
#[derive(Clone)]
pub struct PresenceStore {
    conn: Arc<Mutex<Connection>>,
}

impl PresenceStore {
    pub fn open(path: &Path) -> Result<Self, ServerError> {
        let conn = db::open_and_migrate(path)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Self, ServerError> {
        let conn = db::open_memory()?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn filter_wan_presence_endpoints(&self, endpoints: Vec<PeerEndpoint>) -> Vec<PeerEndpoint> {
        endpoints
            .into_iter()
            .filter(|e| is_wan_dialable_endpoint(e))
            .collect()
    }

    /// Client POST /v1/register — merge public TCP endpoints.
    pub fn merge_client_register(
        &self,
        public_key_hex: String,
        client_endpoints: Vec<PeerEndpoint>,
        transport_capabilities: Vec<String>,
        ipv6: Option<String>,
        ipv4: Option<String>,
    ) -> Result<PeerRecord, ServerError> {
        let key = normalize_identity_wire(&public_key_hex)?;
        let endpoints = self.filter_wan_presence_endpoints(client_endpoints);
        self.upsert(key, endpoints, transport_capabilities, ipv6, ipv4)
    }

    pub fn upsert(
        &self,
        public_key_hex: String,
        endpoints: Vec<PeerEndpoint>,
        transport_capabilities: Vec<String>,
        ipv6: Option<String>,
        ipv4: Option<String>,
    ) -> Result<PeerRecord, ServerError> {
        let key = normalize_identity_wire(&public_key_hex)?;
        let mut endpoints = self.filter_wan_presence_endpoints(endpoints);
        endpoints.truncate(MAX_STORED_ENDPOINTS);
        let mut transport_capabilities = transport_capabilities;
        transport_capabilities.truncate(MAX_STORED_CAPS);
        let ipv6 = trim_ip_hint(ipv6);
        let ipv4 = trim_ip_hint(ipv4);
        let endpoints_json = serde_json::to_string(&endpoints)
            .map_err(|e| ServerError::Internal(format!("endpoints json: {e}")))?;
        let caps_json = serde_json::to_string(&transport_capabilities)
            .map_err(|e| ServerError::Internal(format!("capabilities json: {e}")))?;
        let conn = self.conn.lock().map_err(lock_err)?;
        // Stamp inside the lock so a slower writer cannot rewind a newer heartbeat.
        let now_ms = unix_ms_now();
        self.write_peer(
            &conn,
            &key,
            &endpoints_json,
            &caps_json,
            ipv6,
            ipv4,
            now_ms,
            endpoints,
            transport_capabilities,
        )
    }

    fn write_peer(
        &self,
        conn: &Connection,
        key: &str,
        endpoints_json: &str,
        caps_json: &str,
        ipv6: Option<String>,
        ipv4: Option<String>,
        now_ms: u64,
        endpoints: Vec<PeerEndpoint>,
        transport_capabilities: Vec<String>,
    ) -> Result<PeerRecord, ServerError> {
        #[cfg(not(test))]
        const MAX_STORED_PEERS: usize = 50_000;
        #[cfg(test)]
        const MAX_STORED_PEERS: usize = 4;
        let stamp = unix_ms_as_i64(now_ms);
        let row_exists: bool = conn
            .query_row(
                "SELECT 1 FROM peers WHERE public_key_hex = ?1",
                [key],
                |_| Ok(()),
            )
            .is_ok();
        if !row_exists {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))
                .map_err(|e| ServerError::from(e))?;
            if count >= MAX_STORED_PEERS as i64 {
                return Err(ServerError::RateLimited("presence capacity".into()));
            }
        }
        conn.execute(
            "INSERT INTO peers (
                public_key_hex, endpoints_json, transport_capabilities_json,
                ipv6, ipv4, last_heartbeat_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(public_key_hex) DO UPDATE SET
                endpoints_json = excluded.endpoints_json,
                transport_capabilities_json = excluded.transport_capabilities_json,
                ipv6 = excluded.ipv6,
                ipv4 = excluded.ipv4,
                last_heartbeat_unix_ms = MAX(peers.last_heartbeat_unix_ms, excluded.last_heartbeat_unix_ms)",
            params![key, endpoints_json, caps_json, ipv6, ipv4, stamp],
        )?;
        let stored: i64 = conn.query_row(
            "SELECT last_heartbeat_unix_ms FROM peers WHERE public_key_hex = ?1",
            [key],
            |row| row.get(0),
        )?;
        Ok(PeerRecord {
            public_key_hex: key.to_string(),
            endpoints,
            transport_capabilities,
            ipv6,
            ipv4,
            last_heartbeat_unix_ms: unix_ms_from_i64(stored),
        })
    }

    /// Refresh a peer that is still inside `ttl` and still has a dialable endpoint.
    /// An expired row stays expired until a signed register — an unauthenticated
    /// heartbeat must not resurrect stale addresses.
    pub fn heartbeat(&self, public_key_hex: &str, ttl: Duration) -> ApiResult<PeerRecord> {
        self.heartbeat_at(public_key_hex, ttl, unix_ms_now())
    }

    fn heartbeat_at(
        &self,
        public_key_hex: &str,
        ttl: Duration,
        now_ms: u64,
    ) -> ApiResult<PeerRecord> {
        let key = normalize_identity_wire(public_key_hex)?;
        let cutoff = cutoff_at(now_ms, ttl);
        let conn = self.conn.lock().map_err(lock_err)?;
        let existing = match self.fetch_one(&conn, &key, cutoff) {
            Ok(r) => r,
            Err(ServerError::NotFound(_)) => {
                return Err(ServerError::NotFound(
                    "peer not registered or presence expired".into(),
                ));
            }
            Err(e) => return Err(e),
        };
        let visible = self.prepare_peer_lookup(existing)?;
        conn.execute(
            "UPDATE peers SET last_heartbeat_unix_ms = MAX(last_heartbeat_unix_ms, ?1)
             WHERE public_key_hex = ?2",
            params![unix_ms_as_i64(now_ms), key],
        )?;
        Ok(PeerRecord {
            last_heartbeat_unix_ms: now_ms.max(visible.last_heartbeat_unix_ms),
            ..visible
        })
    }

    #[cfg(test)]
    fn upsert_at(
        &self,
        public_key_hex: String,
        endpoints: Vec<PeerEndpoint>,
        mut transport_capabilities: Vec<String>,
        ipv6: Option<String>,
        ipv4: Option<String>,
        now_ms: u64,
    ) -> Result<PeerRecord, ServerError> {
        let key = normalize_identity_wire(&public_key_hex)?;
        let mut endpoints = self.filter_wan_presence_endpoints(endpoints);
        endpoints.truncate(MAX_STORED_ENDPOINTS);
        transport_capabilities.truncate(MAX_STORED_CAPS);
        let ipv6 = trim_ip_hint(ipv6);
        let ipv4 = trim_ip_hint(ipv4);
        let endpoints_json = serde_json::to_string(&endpoints)
            .map_err(|e| ServerError::Internal(format!("endpoints json: {e}")))?;
        let caps_json = serde_json::to_string(&transport_capabilities)
            .map_err(|e| ServerError::Internal(format!("capabilities json: {e}")))?;
        let conn = self.conn.lock().map_err(lock_err)?;
        self.write_peer(
            &conn,
            &key,
            &endpoints_json,
            &caps_json,
            ipv6,
            ipv4,
            now_ms,
            endpoints,
            transport_capabilities,
        )
    }

    #[cfg(test)]
    fn insert_legacy_bloated_endpoints_json(
        &self,
        public_key_hex: &str,
        ms: i64,
    ) -> Result<(), ServerError> {
        let flood: Vec<PeerEndpoint> = (0..32)
            .map(|i| PeerEndpoint {
                scheme: "tcp".into(),
                host: format!("203.0.113.{}", 50 + (i % 50)),
                port: 40_000 + i as u16,
            })
            .collect();
        let endpoints_json = serde_json::to_string(&flood)
            .map_err(|e| ServerError::Internal(format!("endpoints json: {e}")))?;
        let caps: Vec<String> = (0..64).map(|i| format!("cap-{i}")).collect();
        let caps_json = serde_json::to_string(&caps)
            .map_err(|e| ServerError::Internal(format!("capabilities json: {e}")))?;
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO peers (
                public_key_hex, endpoints_json, transport_capabilities_json,
                ipv6, ipv4, last_heartbeat_unix_ms
             ) VALUES (?1, ?2, ?3, NULL, NULL, ?4)",
            params![public_key_hex, endpoints_json, caps_json, ms],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn insert_corrupt_endpoints_json(&self, public_key_hex: &str, ms: i64) -> Result<(), ServerError> {
        let caps = serde_json::to_string(&vec!["tcp".to_string()])
            .map_err(|e| ServerError::Internal(format!("capabilities json: {e}")))?;
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO peers (
                public_key_hex, endpoints_json, transport_capabilities_json,
                ipv6, ipv4, last_heartbeat_unix_ms
             ) VALUES (?1, ?2, ?3, NULL, NULL, ?4)",
            params![public_key_hex, "not-json", caps, ms],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn insert_heartbeat_ms(&self, public_key_hex: &str, ms: i64) -> Result<(), ServerError> {
        let endpoints = serde_json::to_string(&vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.50".into(),
            port: 1,
        }])
        .map_err(|e| ServerError::Internal(format!("endpoints json: {e}")))?;
        let caps = serde_json::to_string(&vec!["tcp".to_string()])
            .map_err(|e| ServerError::Internal(format!("capabilities json: {e}")))?;
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.execute(
            "INSERT INTO peers (
                public_key_hex, endpoints_json, transport_capabilities_json,
                ipv6, ipv4, last_heartbeat_unix_ms
             ) VALUES (?1, ?2, ?3, NULL, NULL, ?4)",
            params![public_key_hex, endpoints, caps, ms],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn peer_count(&self) -> Result<i64, ServerError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        Ok(conn.query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?)
    }

    pub fn get(&self, public_key_hex: &str, ttl: Duration) -> ApiResult<PeerRecord> {
        self.get_at(public_key_hex, ttl, unix_ms_now())
    }

    fn get_at(&self, public_key_hex: &str, ttl: Duration, now_ms: u64) -> ApiResult<PeerRecord> {
        let key = normalize_identity_wire(public_key_hex)?;
        let cutoff = cutoff_at(now_ms, ttl);
        let conn = self.conn.lock().map_err(lock_err)?;
        match self.fetch_one(&conn, &key, cutoff) {
            Ok(r) => self.prepare_peer_lookup(r),
            Err(ServerError::NotFound(_)) => Err(ServerError::NotFound(
                "peer not registered or presence expired".into(),
            )),
            Err(e) => Err(e),
        }
    }

    pub fn get_stored(&self, public_key_hex: &str) -> ApiResult<PeerRecord> {
        let key = normalize_identity_wire(public_key_hex)?;
        let conn = self.conn.lock().map_err(lock_err)?;
        self.fetch_one(&conn, &key, 0)
    }

    pub fn list_online(&self, ttl: Duration) -> Result<Vec<PeerRecord>, ServerError> {
        let cutoff = heartbeat_cutoff_ms(ttl);
        let conn = self.conn.lock().map_err(lock_err)?;
        let mut stmt = conn.prepare(
            "SELECT public_key_hex, endpoints_json, transport_capabilities_json,
                    ipv6, ipv4, last_heartbeat_unix_ms
             FROM peers
             WHERE last_heartbeat_unix_ms >= ?1
             ORDER BY last_heartbeat_unix_ms DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cutoff as i64, MAX_LISTED_PEERS], |row| {
            row_to_peer_record(row).map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    e.to_string(),
                )))
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            let r = row?;
            if let Ok(r) = self.prepare_peer_lookup(r) {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn prepare_peer_lookup(&self, mut r: PeerRecord) -> ApiResult<PeerRecord> {
        r.endpoints = self.filter_wan_presence_endpoints(r.endpoints);
        bound_stored_lists(&mut r);
        if r.endpoints.is_empty() {
            return Err(ServerError::NotFound(
                "peer not registered or presence expired".into(),
            ));
        }
        Ok(r)
    }

    pub fn purge_expired(&self, ttl: Duration) -> Result<u64, ServerError> {
        self.purge_expired_at(ttl, unix_ms_now())
    }

    fn purge_expired_at(&self, ttl: Duration, now_ms: u64) -> Result<u64, ServerError> {
        let cutoff = cutoff_at(now_ms, ttl);
        let conn = self.conn.lock().map_err(lock_err)?;
        let n = conn.execute(
            "DELETE FROM peers WHERE last_heartbeat_unix_ms < ?1",
            [unix_ms_as_i64(cutoff)],
        )?;
        Ok(n as u64)
    }

    pub fn ping(&self) -> Result<(), ServerError> {
        let conn = self.conn.lock().map_err(lock_err)?;
        conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }

    fn fetch_one(
        &self,
        conn: &Connection,
        public_key_hex: &str,
        cutoff_ms: u64,
    ) -> ApiResult<PeerRecord> {
        let mut stmt = conn.prepare(
            "SELECT public_key_hex, endpoints_json, transport_capabilities_json,
                    ipv6, ipv4, last_heartbeat_unix_ms
             FROM peers
             WHERE public_key_hex = ?1 AND last_heartbeat_unix_ms >= ?2",
        )?;
        let mut rows = stmt.query(params![public_key_hex, cutoff_ms as i64])?;
        if let Some(row) = rows.next()? {
            return row_to_peer_record(row);
        }
        Err(ServerError::NotFound("peer not registered".into()))
    }
}

fn row_to_peer_record(row: &rusqlite::Row<'_>) -> ApiResult<PeerRecord> {
    let endpoints_json: String = row.get(1).map_err(ServerError::from)?;
    let caps_json: String = row.get(2).map_err(ServerError::from)?;
    let endpoints: Vec<PeerEndpoint> =
        serde_json::from_str(&endpoints_json).map_err(stored_json_not_found)?;
    let transport_capabilities: Vec<String> =
        serde_json::from_str(&caps_json).map_err(stored_json_not_found)?;
    Ok(PeerRecord {
        public_key_hex: row.get(0).map_err(ServerError::from)?,
        endpoints,
        transport_capabilities,
        ipv6: row.get(3).map_err(ServerError::from)?,
        ipv4: row.get(4).map_err(ServerError::from)?,
        last_heartbeat_unix_ms: unix_ms_from_i64(row.get(5).map_err(ServerError::from)?),
    })
}

fn stored_json_not_found(_err: serde_json::Error) -> ServerError {
    ServerError::NotFound("peer not registered or presence expired".into())
}

/// List responses stay bounded if the table is large.
const MAX_LISTED_PEERS: i64 = 2_000;

const MAX_STORED_ENDPOINTS: usize = 8;
const MAX_STORED_CAPS: usize = 16;
const MAX_IP_HINT_LEN: usize = 64;

fn trim_ip_hint(ip: Option<String>) -> Option<String> {
    let Some(raw) = ip else {
        return None;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bounded = if trimmed.len() > MAX_IP_HINT_LEN {
        &trimmed[..MAX_IP_HINT_LEN]
    } else {
        trimmed
    };
    Some(bounded.to_string())
}

fn bound_stored_lists(r: &mut PeerRecord) {
    r.endpoints.truncate(MAX_STORED_ENDPOINTS);
    r.transport_capabilities.truncate(MAX_STORED_CAPS);
}

fn heartbeat_cutoff_ms(ttl: Duration) -> u64 {
    cutoff_at(unix_ms_now(), ttl)
}

fn cutoff_at(now_ms: u64, ttl: Duration) -> u64 {
    now_ms.saturating_sub(ttl_to_ms(ttl))
}

fn ttl_to_ms(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)
}

fn unix_ms_as_i64(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// Negative SQLite values are stale, not "far in the future".
fn unix_ms_from_i64(ms: i64) -> u64 {
    u64::try_from(ms).unwrap_or(0)
}

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> ServerError {
    ServerError::Internal("database lock poisoned".into())
}

fn is_wan_dialable_endpoint(ep: &PeerEndpoint) -> bool {
    match ep.scheme.as_str() {
        "tcp" | "quic" => is_public_routable_ipv4(&ep.host) && ep.port != 0,
        _ => false,
    }
}

pub(crate) fn is_public_routable_ipv4(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() || host.len() > 15 || host.contains(':') {
        return false;
    }
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && ip.octets()[0] != 0
        && !(ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40)
}

impl From<rusqlite::Error> for ServerError {
    fn from(_e: rusqlite::Error) -> Self {
        ServerError::Internal("database error".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wan_dialable_accepts_public_tcp() {
        let peer = PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.50".into(),
            port: 41234,
        };
        assert!(is_wan_dialable_endpoint(&peer));
    }

    fn test_secp_pk_hex(seed: u8) -> String {
        let sk = secp256k1::SecretKey::from_byte_array([seed; 32]).expect("test key");
        let secp = secp256k1::Secp256k1::new();
        hex::encode(sk.public_key(&secp).serialize())
    }

    #[test]
    fn merge_register_stores_public_tcp() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(11);
        let client_tcp = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.50".into(),
            port: 41234,
        }];
        let rec = store
            .merge_client_register(pk.clone(), client_tcp, vec!["tcp".into()], None, None)
            .expect("merge");
        assert_eq!(rec.endpoints.len(), 1);
        assert_eq!(rec.endpoints[0].host, "203.0.113.50");
    }

    #[test]
    fn upsert_truncates_endpoint_flood() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(12);
        let flood: Vec<PeerEndpoint> = (0..32)
            .map(|i| PeerEndpoint {
                scheme: "tcp".into(),
                host: format!("203.0.113.{}", 50 + (i % 50)),
                port: 40000 + i as u16,
            })
            .collect();
        let rec = store
            .merge_client_register(pk, flood, vec!["tcp".into(); 64], None, None)
            .expect("merge");
        assert!(rec.endpoints.len() <= 8);
        assert!(rec.transport_capabilities.len() <= 16);
    }

    #[test]
    fn stale_upsert_does_not_rewind_heartbeat() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(13);
        let older = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.10".into(),
            port: 1,
        }];
        let newer = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.11".into(),
            port: 2,
        }];
        store
            .upsert_at(pk.clone(), older, vec!["tcp".into()], None, None, 50_000)
            .unwrap();
        let rec = store
            .upsert_at(pk.clone(), newer, vec!["tcp".into()], None, None, 1_000)
            .unwrap();
        assert_eq!(rec.endpoints[0].host, "203.0.113.11");
        assert_eq!(rec.endpoints[0].port, 2);
        assert_eq!(rec.last_heartbeat_unix_ms, 50_000);
    }

    #[test]
    fn heartbeat_does_not_resurrect_expired_or_undialable_rows() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(14);
        let ep = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.20".into(),
            port: 9,
        }];
        store
            .upsert_at(pk.clone(), ep, vec!["tcp".into()], None, None, 1_000)
            .unwrap();
        let ttl = Duration::from_millis(90_000);
        let err = store.heartbeat_at(&pk, ttl, 1_000 + 90_001).unwrap_err();
        assert!(matches!(err, ServerError::NotFound(_)));
        assert_eq!(store.get_stored(&pk).unwrap().last_heartbeat_unix_ms, 1_000);

        let live = store.heartbeat_at(&pk, ttl, 20_000).unwrap();
        assert_eq!(live.last_heartbeat_unix_ms, 20_000);

        let hidden = test_secp_pk_hex(15);
        store
            .upsert(
                hidden.clone(),
                vec![PeerEndpoint {
                    scheme: "tcp".into(),
                    host: "10.0.0.8".into(),
                    port: 9,
                }],
                vec!["tcp".into()],
                None,
                None,
            )
            .unwrap();
        let before = store.get_stored(&hidden).unwrap().last_heartbeat_unix_ms;
        assert!(store.get_stored(&hidden).unwrap().endpoints.is_empty());
        assert!(store.heartbeat(&hidden, Duration::from_secs(90)).is_err());
        assert_eq!(
            store.get_stored(&hidden).unwrap().last_heartbeat_unix_ms,
            before
        );
    }

    #[test]
    fn purge_keeps_row_exactly_at_cutoff() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(16);
        store
            .upsert_at(
                pk.clone(),
                vec![PeerEndpoint {
                    scheme: "tcp".into(),
                    host: "203.0.113.21".into(),
                    port: 9,
                }],
                vec!["tcp".into()],
                None,
                None,
                10_000,
            )
            .unwrap();
        let ttl = Duration::from_millis(5_000);
        assert_eq!(store.purge_expired_at(ttl, 15_000).unwrap(), 0);
        assert!(store.get_stored(&pk).is_ok());
        assert_eq!(store.purge_expired_at(ttl, 15_001).unwrap(), 1);
        assert!(store.get_stored(&pk).is_err());
    }

    #[test]
    fn negative_heartbeat_is_not_fresh_and_is_purged() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(17);
        store.insert_heartbeat_ms(&pk, -5).unwrap();
        assert!(store.get_stored(&pk).is_err());
        assert_eq!(store.peer_count().unwrap(), 1);
        assert_eq!(store.purge_expired(Duration::from_secs(90)).unwrap(), 1);
        assert_eq!(store.peer_count().unwrap(), 0);
    }

    #[test]
    fn corrupt_stored_json_surfaces_as_not_found() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(19);
        store.insert_corrupt_endpoints_json(&pk, 50_000).unwrap();
        let err = store
            .get(&pk, Duration::from_secs(90))
            .expect_err("malformed endpoints_json");
        assert!(matches!(err, ServerError::NotFound(_)));
    }

    #[test]
    fn stored_peer_cap_rejects_new_identities() {
        let store = PresenceStore::open_in_memory().expect("db");
        let ep = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.60".into(),
            port: 1,
        }];
        for seed in 0u8..4 {
            let pk = test_secp_pk_hex(seed + 40);
            store
                .upsert(pk, ep.clone(), vec!["tcp".into()], None, None)
                .expect("under cap");
        }
        let extra = test_secp_pk_hex(99);
        let err = store
            .upsert(extra, ep, vec!["tcp".into()], None, None)
            .unwrap_err();
        assert!(matches!(err, ServerError::RateLimited(_)));
    }

    #[test]
    fn legacy_bloated_json_truncated_on_lookup() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(21);
        store
            .insert_legacy_bloated_endpoints_json(&pk, 50_000)
            .unwrap();
        let rec = store
            .get_at(&pk, Duration::from_secs(90), 50_001)
            .expect("lookup");
        assert!(rec.endpoints.len() <= MAX_STORED_ENDPOINTS);
        assert!(rec.transport_capabilities.len() <= MAX_STORED_CAPS);
    }

    #[test]
    fn expired_peer_reregisters_with_fresh_presence() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(22);
        let ep = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.55".into(),
            port: 9,
        }];
        store
            .upsert_at(pk.clone(), ep.clone(), vec!["tcp".into()], None, None, 1_000)
            .unwrap();
        let ttl = Duration::from_millis(10_000);
        assert!(store.get_at(&pk, ttl, 11_001).is_err());
        let revived = store
            .merge_client_register(pk.clone(), ep, vec!["tcp".into()], None, None)
            .expect("re-register");
        assert_eq!(revived.endpoints[0].host, "203.0.113.55");
        assert!(revived.last_heartbeat_unix_ms > 1_000);
        assert!(store.get_at(&pk, ttl, revived.last_heartbeat_unix_ms).is_ok());
    }

    #[test]
    fn concurrent_upserts_do_not_rewind_heartbeat() {
        use std::sync::Barrier;
        use std::thread;

        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(23);
        let ep = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.70".into(),
            port: 1,
        }];
        store
            .upsert_at(pk.clone(), ep.clone(), vec!["tcp".into()], None, None, 50_000)
            .unwrap();
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let pk = pk.clone();
            let ep = ep.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .merge_client_register(pk, ep, vec!["tcp".into()], None, None)
                    .expect("concurrent register");
            }));
        }
        barrier.wait();
        for h in handles {
            h.join().expect("join");
        }
        assert!(
            store.get_stored(&pk).unwrap().last_heartbeat_unix_ms >= 50_000,
            "heartbeat must not rewind under concurrent register"
        );
    }

    #[test]
    fn oversized_ip_hints_are_trimmed_on_store() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(24);
        let ep = vec![PeerEndpoint {
            scheme: "tcp".into(),
            host: "203.0.113.80".into(),
            port: 1,
        }];
        let padded_v4 = format!("203.0.113.1{}", "x".repeat(80));
        let rec = store
            .upsert(pk, ep, vec!["tcp".into()], None, Some(padded_v4.clone()))
            .unwrap();
        let stored_v4 = rec.ipv4.expect("ipv4");
        assert!(stored_v4.len() <= MAX_IP_HINT_LEN);
        assert_eq!(&stored_v4, padded_v4.trim().get(..MAX_IP_HINT_LEN).unwrap());
    }

    #[test]
    fn public_quic_is_stored_and_non_global_ipv4_is_not() {
        let store = PresenceStore::open_in_memory().expect("db");
        let pk = test_secp_pk_hex(18);
        let rec = store
            .merge_client_register(
                pk,
                vec![PeerEndpoint {
                    scheme: "quic".into(),
                    host: "203.0.113.40".into(),
                    port: 443,
                }],
                vec!["quic".into()],
                None,
                None,
            )
            .unwrap();
        assert_eq!(rec.endpoints[0].scheme, "quic");
        assert!(!is_public_routable_ipv4("224.0.0.1"));
        assert!(!is_public_routable_ipv4("255.255.255.255"));
        assert!(!is_public_routable_ipv4("100.64.1.1"));
        assert!(!is_public_routable_ipv4("192.168.1.1"));
    }
}
