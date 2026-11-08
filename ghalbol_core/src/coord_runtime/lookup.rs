//! Coord peer lookup (dial addrs / multiaddrs / JSON).

use crate::coord::CoordEndpoint;
use crate::dm_transport::{DmDialAddr, coord_endpoints_to_dial_addrs};
use crate::multiaddr_local::Multiaddr;
use super::config::{
    coord_base_urls, coord_lookup_err_means_http_reachable, note_coord_transport_ok,
};
use super::register::filter_coord_record_tcp_for_dial;
use super::state::*;

const MAX_COORD_LOOKUP_RELAY_ENDPOINTS: usize = 8;

pub(super) fn coord_endpoints_to_dial_multiaddrs(endpoints: &[CoordEndpoint]) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    // Relay circuits first (WAN/NAT); then direct TCP (LAN or UPnP).
    let mut relay_n = 0usize;
    for ep in endpoints {
        if ep.scheme != "libp2p" {
            continue;
        }
        if ep.host.len() > 512 || ep.scheme.len() > 16 {
            continue;
        }
        if let Ok(ma) = ep.host.trim().parse::<Multiaddr>() {
            if crate::p2p::network_transport::is_coord_relay_tcp_circuit_multiaddr(&ma) {
                out.push(ma);
                relay_n += 1;
                if relay_n >= MAX_COORD_LOOKUP_RELAY_ENDPOINTS {
                    break;
                }
            }
        }
    }
    for ep in filter_coord_record_tcp_for_dial(endpoints) {
        #[cfg(target_os = "android")]
        if ep.scheme == "quic" {
            continue;
        }
        let dm = DmDialAddr::new(ep.host.clone(), ep.port);
        if let Ok(ma) = dm.to_multiaddr_string().parse::<Multiaddr>() {
            if crate::p2p::network_transport::is_dm_dial_multiaddr(&ma) {
                out.push(ma);
            }
        }
    }
    let out = crate::p2p::network_transport::filter_coord_dial_addrs(out);
    crate::p2p::network_transport::filter_coord_relay_dial_platform(out)
}
pub fn lookup_bootstrap_multiaddrs(public_key_hex: &str) -> Result<Vec<String>, String> {
    let urls = coord_base_urls();
    if urls.is_empty() {
        return Err("coord base url not set".into());
    }
    let mut last_err = "coord lookup failed".to_string();
    for base in &urls {
        let Ok(client) = client_for(base) else {
            continue;
        };
        match client.lookup(public_key_hex) {
            Ok(record) => {
                let addrs: Vec<String> = coord_endpoints_to_dial_multiaddrs(&record.endpoints)
                    .into_iter()
                    .map(|ma| ma.to_string())
                    .collect();
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
                last_err = format!(
                    "coord lookup ok but peer has no dialable endpoints ({} on record)",
                    record.endpoints.len()
                );
            }
            Err(e) => {
                if coord_lookup_err_means_http_reachable(&e) {
                    note_coord_transport_ok();
                }
                last_err = e.to_string();
            }
        }
    }
    Err(last_err)
}

pub fn coord_lookup_peer_json(public_key_hex: &str) -> serde_json::Value {
    let pk = match crate::public_key_util::normalize_contact_identity_wire(public_key_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return serde_json::json!({ "ok": false, "error": e });
        }
    };
    let now = unix_ms_now();
    if let Ok(m) = lookup_backoff_map().lock() {
        if let Some(b) = m.get(&pk) {
            if now < b.next_allowed_ms {
                return serde_json::json!({
                    "ok": false,
                    "error": format!("lookup backoff (retry in {}ms)", b.next_allowed_ms.saturating_sub(now)),
                    "backoff_ms": b.next_allowed_ms.saturating_sub(now),
                });
            }
        }
    }
    match lookup_bootstrap_multiaddrs(&pk) {
        Ok(addrs) => {
            if let Ok(mut m) = lookup_backoff_map().lock() {
                m.remove(&pk);
            }
            serde_json::json!({
                "ok": true,
                "bootstrap_peers": addrs,
            })
        }
        Err(e) => {
            // Exponential backoff on 404/not-found; shorter backoff on transient reachability errors.
            let es = e.to_string();
            let not_found = es.contains("404") || es.contains("peer_not_on_server");
            let base = if not_found { 800u64 } else { 5_000u64 };
            let mut step = base;
            let mut next = now.saturating_add(step);
            if let Ok(mut m) = lookup_backoff_map().lock() {
                if let Some(prev) = m.get(&pk).copied() {
                    let prev_not_found = prev.step_ms < 5_000;
                    if not_found == prev_not_found {
                        step = (prev.step_ms.saturating_mul(2)).min(5_000);
                    } else {
                        step = base;
                    }
                    next = now.saturating_add(step);
                }
                insert_lookup_backoff(
                    &mut m,
                    pk,
                    CoordLookupBackoff {
                        next_allowed_ms: next,
                        step_ms: step,
                    },
                );
            }
            serde_json::json!({ "ok": false, "error": e })
        }
    }
}
pub fn lookup_dial_addrs_for_public_key(public_key_hex: &str) -> Result<Vec<DmDialAddr>, String> {
    let urls = coord_base_urls();
    if urls.is_empty() {
        return Err("coord base url not set".into());
    }
    let mut last_err = "coord lookup failed".to_string();
    for base in &urls {
        let Ok(client) = client_for(base) else {
            continue;
        };
        match client.lookup(public_key_hex) {
            Ok(record) => {
                let filtered = filter_coord_record_tcp_for_dial(&record.endpoints);
                let addrs = coord_endpoints_to_dial_addrs(&filtered);
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
                last_err = format!(
                    "coord lookup ok but peer has no dialable endpoints ({} on record)",
                    record.endpoints.len()
                );
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

/// Coord lookup → ranked/filtered libp2p multiaddrs (relay + public TCP before RFC1918).
/// Tries configured servers in order; stops on first success (TRANSPORT.md).
pub fn lookup_dial_multiaddrs_for_public_key(
    public_key_hex: &str,
) -> Result<Vec<Multiaddr>, String> {
    let urls = coord_base_urls();
    if urls.is_empty() {
        return Err("coord base url not set".into());
    }
    let mut last_err = "coord lookup failed".to_string();
    for base in &urls {
        let Ok(client) = client_for(base) else {
            continue;
        };
        match client.lookup(public_key_hex) {
            Ok(record) => {
                note_coord_transport_ok();
                let addrs = coord_endpoints_to_dial_multiaddrs(&record.endpoints);
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
                last_err = format!(
                    "coord lookup ok but peer has no dialable endpoints ({} on record)",
                    record.endpoints.len()
                );
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

/// [`lookup_dial_multiaddrs_for_public_key`] on the blocking thread pool (safe from tokio tasks).
pub async fn lookup_dial_multiaddrs_for_public_key_async(
    public_key_hex: &str,
) -> Result<Vec<Multiaddr>, String> {
    let pk = public_key_hex.trim().to_string();
    tokio::task::spawn_blocking(move || lookup_dial_multiaddrs_for_public_key(&pk))
        .await
        .map_err(|e| format!("coord lookup join: {e}"))?
}

/// [`lookup_dial_addrs_for_public_key`] on the blocking thread pool (safe from tokio tasks).
pub async fn lookup_dial_addrs_for_public_key_async(
    public_key_hex: &str,
) -> Result<Vec<DmDialAddr>, String> {
    let pk = public_key_hex.trim().to_string();
    tokio::task::spawn_blocking(move || lookup_dial_addrs_for_public_key(&pk))
        .await
        .map_err(|e| format!("coord lookup join: {e}"))?
}
