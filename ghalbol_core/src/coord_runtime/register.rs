//! Coord endpoint snapshot and presence registration.

use crate::coord::CoordEndpoint;
use crate::dm_transport::DmDialAddr;
use crate::multiaddr_local::Multiaddr;
use super::config::{
    coord_base_urls, coord_is_configured, coord_link_recently_ok, note_coord_transport_failure,
};
use super::presence::{
    ensure_coord_presence_polling, schedule_check_relay_presence_once, start_heartbeat_loop,
    suspend_coord_presence_waiting_endpoints,
};
use super::recovery::{coord_recovery_throttled, note_coord_recovery_attempt};
use super::state::*;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

pub(crate) fn has_coord_endpoints() -> bool {
    has_public_coord_register_endpoints()
}

pub(crate) fn has_public_coord_register_endpoints() -> bool {
    coord_globals()
        .endpoints
        .lock()
        .ok()
        .is_some_and(|v| endpoints_are_registerable(&v))
}

pub(super) fn endpoints_are_registerable(eps: &[CoordEndpoint]) -> bool {
    !endpoints_for_coord_register(eps.to_vec()).is_empty()
}
pub(super) fn is_coord_publishable_host(host: &str) -> bool {
    #[cfg(test)]
    if host.starts_with("127.") {
        return true;
    }
    if host.starts_with("127.") || host == "0.0.0.0" || host == "::" {
        return false;
    }
    if host.starts_with("169.254.") || host.starts_with("fe80:") {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return crate::p2p::network_transport::is_public_bootstrap_ipv4(ip);
    }
    false
}

pub(super) fn endpoint_key(ep: &CoordEndpoint) -> String {
    format!("{}:{}:{}", ep.scheme, ep.host, ep.port)
}

pub(super) fn ipv4_field_rank(host: &str) -> u8 {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if ip.is_private() {
            if ip.octets()[0] == 10 || (ip.octets()[0] == 192 && ip.octets()[1] == 168) {
                return 3;
            }
            return 2;
        }
        return 0;
    }
    if host.starts_with("192.168.") || host.starts_with("10.") {
        3
    } else {
        1
    }
}

/// Any non-loopback DM TCP listen — legacy no-coord path only; coord mode uses public TCP + relay.
pub(super) fn is_coord_presence_tcp_fallback(ma: &Multiaddr) -> bool {
    if crate::p2p::network_transport::is_relay_circuit_multiaddr(ma) {
        return false;
    }
    let Some(ip) = crate::p2p::network_transport::ipv4_from_ma_str(&ma.to_string()) else {
        return false;
    };
    !ip.is_loopback() && crate::p2p::network_transport::is_dm_dial_multiaddr(ma)
}

pub(super) fn listen_addrs_to_coord_endpoints(addrs: &[Multiaddr]) -> Vec<CoordEndpoint> {
    let has_relay = addrs
        .iter()
        .any(crate::p2p::network_transport::is_coord_relay_tcp_circuit_multiaddr);
    let mut eps = Vec::new();
    for ma in addrs {
        eps.extend(multiaddr_to_coord_endpoints(ma));
    }
    // With coord, only relay (or public TCP) is WAN-dialable — never CGNAT/LAN via POST.
    if eps.is_empty() && !has_relay {
        for ma in addrs {
            if coord_is_configured() {
                continue;
            }
            if !is_coord_presence_tcp_fallback(ma) {
                continue;
            } else if let Some(ip) =
                crate::p2p::network_transport::ipv4_from_ma_str(&ma.to_string())
            {
                // RFC1918 is LAN-only — mDNS, not coord (misleading for WAN peers).
                if ip.is_private() && !crate::p2p::network_transport::is_cgnat_ipv4(ip) {
                    continue;
                }
            }
            if let Some(dm) = DmDialAddr::parse(&ma.to_string()) {
                eps.push(CoordEndpoint {
                    scheme: "tcp".into(),
                    host: dm.host,
                    port: dm.port,
                });
            }
        }
    }
    if has_relay {
        let bootstraps = coord_relay_bootstrap_tcp_keys();
        eps.retain(|e| {
            e.scheme == "libp2p"
                || (e.scheme == "tcp"
                    && is_coord_publishable_host(&e.host)
                    && !crate::p2p::network_transport::is_relay_bootstrap_tcp(
                        &e.host,
                        e.port,
                        &bootstraps,
                    ))
        });
    }
    eps.sort_by_key(|e| {
        if e.scheme == "libp2p" {
            0u8
        } else {
            ipv4_field_rank(&e.host) + 1
        }
    });
    let mut seen = HashSet::new();
    eps.retain(|e| seen.insert(endpoint_key(e)));
    if eps.len() > MAX_COORD_ENDPOINTS {
        eps.truncate(MAX_COORD_ENDPOINTS);
    }
    eps
}

pub(super) fn should_throttle_register() -> bool {
    let now = unix_ms_now();
    let last = COORD_LAST_REG_ATTEMPT_MS.load(Ordering::Relaxed);
    let min_gap = if COORD_REGISTERED.load(Ordering::Relaxed) {
        MIN_REGISTER_INTERVAL_MS
    } else {
        MIN_REGISTER_RETRY_MS
    };
    now.saturating_sub(last) < min_gap
}

pub(super) fn spawn_register_presence() {
    spawn_register_presence_inner(false);
}

/// `force` bypasses throttle (endpoint set changed while already registered).
pub(super) fn spawn_register_presence_inner(force: bool) {
    #[cfg(test)]
    if coord_base_urls().iter().any(|b| b.contains("example.test")) {
        return;
    }
    if !force && should_throttle_register() {
        if !COORD_REGISTERED.load(Ordering::Relaxed) {
            COORD_REG_PENDING.store(true, Ordering::Release);
        }
        return;
    }
    if COORD_REG_WORKER_BUSY.load(Ordering::Acquire) {
        COORD_REG_PENDING.store(true, Ordering::Release);
        return;
    }
    if COORD_REG_WORKER_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        COORD_REG_PENDING.store(true, Ordering::Release);
        return;
    }
    COORD_LAST_REG_ATTEMPT_MS.store(unix_ms_now(), Ordering::Relaxed);
    if std::thread::Builder::new()
        .name("ghalbol-coord-reg".into())
        // Blocking HTTP + TLS on the default 2 MiB thread stack overflowed on CI runners.
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            struct BusyGuard;
            impl Drop for BusyGuard {
                fn drop(&mut self) {
                    COORD_REG_WORKER_BUSY.store(false, Ordering::Release);
                    // `COORD_REG_PENDING` is drained on the next `coord_register_tick` (libp2p
                    // 1s loop). Do not call `spawn_register_presence_inner` from `Drop` — that
                    // chained synchronous spawns on a shallow exiting stack and caused SIGABRT on
                    // GitHub Actions integration tests.
                }
            }
            let _busy = BusyGuard;
            if let Err(e) = try_register_presence() {
                let es = e.to_string();
                if es.contains("relay-only") || es.contains("no listen endpoints") {
                    crate::flow_log::debug("coord", format!("register: {e}"));
                } else {
                    note_coord_transport_failure();
                    crate::flow_log::warn("coord", format!("register: {e}"));
                }
            }
        })
        .is_err()
    {
        COORD_REG_WORKER_BUSY.store(false, Ordering::Release);
    }
}

/// Safe from the tokio P2P task (blocking HTTP on a std thread).
pub fn schedule_register_presence() {
    spawn_register_presence();
}

pub(super) fn multiaddr_to_coord_endpoints(ma: &Multiaddr) -> Vec<CoordEndpoint> {
    if crate::p2p::network_transport::is_coord_relay_tcp_circuit_multiaddr(ma) {
        return vec![CoordEndpoint {
            scheme: "libp2p".into(),
            host: ma.to_string(),
            port: 0,
        }];
    }
    let preferred_relay = coord_globals()
        .preferred_relay_peer_id
        .lock()
        .ok()
        .and_then(|g| g.clone());
    let local = match coord_local_peer_id() {
        Some(p) => p,
        None => return Vec::new(),
    };
    if !crate::p2p::network_transport::is_peer_own_coord_register_tcp(
        ma,
        &local,
        &coord_relay_bootstrap_tcp_keys(),
        preferred_relay.as_deref(),
    ) {
        return Vec::new();
    }
    if let Some(dm) = DmDialAddr::parse(&ma.to_string()) {
        return vec![CoordEndpoint {
            scheme: "tcp".into(),
            host: dm.host,
            port: dm.port,
        }];
    }
    Vec::new()
}

pub fn rebuild_coord_endpoints_from_listen(addrs: &[Multiaddr]) {
    if !coord_is_configured() {
        return;
    }
    if addrs.is_empty() {
        if has_coord_endpoints() && !COORD_REGISTERED.load(Ordering::Relaxed) {
            spawn_register_presence_inner(false);
        }
        return;
    }
    let has_relay = addrs
        .iter()
        .any(crate::p2p::network_transport::is_coord_ipv4_relay_listen);
    let publishable: Vec<Multiaddr> = addrs
        .iter()
        .filter(|ma| {
            crate::p2p::network_transport::is_coord_ipv4_relay_listen(ma) || {
                let local = coord_local_peer_id();
                let preferred = coord_globals()
                    .preferred_relay_peer_id
                    .lock()
                    .ok()
                    .and_then(|g| g.clone());
                local.is_some_and(|local| {
                    crate::p2p::network_transport::is_peer_own_coord_register_tcp(
                        ma,
                        &local,
                        &coord_relay_bootstrap_tcp_keys(),
                        preferred.as_deref(),
                    )
                })
            }
        })
        .cloned()
        .collect();
    let eps = listen_addrs_to_coord_endpoints(if publishable.is_empty() {
        addrs
    } else {
        &publishable
    });
    if eps.is_empty() {
        let cgnat_only = !has_relay
            && addrs.iter().any(|ma| {
                crate::p2p::network_transport::ipv4_from_ma_str(&ma.to_string())
                    .is_some_and(crate::p2p::network_transport::is_cgnat_ipv4)
            });
        let was_registered = COORD_REGISTERED.load(Ordering::Relaxed);
        if was_registered {
            // CGNAT-only local listen snapshot — server still owns relay circuit on coord.
            schedule_check_relay_presence_once();
            return;
        }
        let g = coord_globals();
        if let Ok(mut v) = g.endpoints.lock() {
            if !v.is_empty() {
                v.clear();
            }
        }
        if !was_registered {
            suspend_coord_presence_waiting_endpoints();
            if cgnat_only {
                crate::flow_log::debug(
                    "coord",
                    "CGNAT — no public TCP for coord register; WAN text uses delivery, LAN uses mDNS",
                );
            } else if !crate::wan_coord::local_relay_circuit_listening() {
                crate::flow_log::debug(
                    "coord",
                    "no public TCP endpoint yet — WAN text uses delivery; LAN uses mDNS",
                );
            } else {
                crate::flow_log::warn(
                    "coord",
                    "waiting for relay/public listen endpoint before coord register",
                );
            }
        }
        return;
    }
    let g = coord_globals();
    let Ok(mut v) = g.endpoints.lock() else {
        return;
    };
    let mut old_keys: Vec<String> = v.iter().map(endpoint_key).collect();
    let mut new_keys: Vec<String> = eps.iter().map(endpoint_key).collect();
    old_keys.sort();
    new_keys.sort();
    if old_keys == new_keys {
        if !COORD_REGISTERED.load(Ordering::Relaxed) {
            schedule_check_relay_presence_once();
        }
        return;
    }
    *v = eps;
    if endpoints_are_registerable(&v) {
        spawn_register_presence_inner(true);
    } else {
        schedule_check_relay_presence_once();
    }
}
pub fn coord_register_tick(listen_snapshot: &[Multiaddr]) {
    if !coord_is_configured() {
        return;
    }
    rebuild_coord_endpoints_from_listen(listen_snapshot);
    if !COORD_REGISTERED.load(Ordering::Relaxed) {
        if has_coord_endpoints() {
            spawn_register_presence_inner(false);
        }
        if crate::wan_coord::local_relay_circuit_listening() {
            ensure_coord_presence_polling();
            schedule_check_relay_presence_once();
        }
    } else if COORD_REG_PENDING.swap(false, Ordering::AcqRel) {
        spawn_register_presence_inner(false);
    } else if !coord_link_recently_ok() && COORD_CONSEC_FAILS.load(Ordering::Relaxed) >= 1 {
        let now = unix_ms_now();
        if !coord_recovery_throttled(now) {
            note_coord_recovery_attempt(now);
            schedule_check_relay_presence_once();
        }
    }
}

/// Push libp2p listen addresses into coord registration (full snapshot preferred).
pub fn sync_published_listen_addrs(addrs: &[Multiaddr]) {
    rebuild_coord_endpoints_from_listen(addrs);
}

pub(super) fn dial_addr_to_endpoints(addr: &DmDialAddr) -> Vec<CoordEndpoint> {
    if !is_coord_publishable_host(addr.host.trim()) {
        return Vec::new();
    }
    vec![CoordEndpoint {
        scheme: "tcp".into(),
        host: addr.host.clone(),
        port: addr.port,
    }]
}

/// Legacy DM poll listen hook — merges one addr then rebuilds if the set changed.
pub fn on_listen_dm_addr(addr: &DmDialAddr) {
    let eps = dial_addr_to_endpoints(addr);
    if eps.is_empty() {
        return;
    }
    let g = coord_globals();
    let Ok(mut v) = g.endpoints.lock() else {
        return;
    };
    let before = v.len();
    for ep in eps {
        let key = endpoint_key(&ep);
        if v.iter().any(|e| endpoint_key(e) == key) {
            continue;
        }
        v.push(ep);
    }
    if v.len() > before {
        // Endpoint set changed — bypass register throttle (TRANSPORT.md).
        spawn_register_presence_inner(true);
    }
}
pub(super) fn endpoints_for_coord_register(eps: Vec<CoordEndpoint>) -> Vec<CoordEndpoint> {
    let tcp: Vec<CoordEndpoint> = eps.into_iter().filter(|e| e.scheme == "tcp").collect();
    if !coord_is_configured() {
        return tcp;
    }
    let bootstraps = coord_relay_bootstrap_tcp_keys();
    tcp.into_iter()
        .filter(|e| is_coord_publishable_host(&e.host))
        .filter(|e| {
            !crate::p2p::network_transport::is_relay_bootstrap_tcp(&e.host, e.port, &bootstraps)
        })
        .collect()
}

pub(super) fn try_register_on_server(
    base: &str,
    ident: &crate::DecryptedIdentity,
    endpoints: &[CoordEndpoint],
) -> Result<(), String> {
    let wire = ident.identity_wire();
    let ipv4 = endpoints
        .iter()
        .filter(|e| e.scheme == "tcp" && !e.host.contains(':'))
        .min_by_key(|e| ipv4_field_rank(&e.host))
        .map(|e| e.host.as_str())
        .map(str::to_string);
    let ipv6 = endpoints
        .iter()
        .filter(|e| e.scheme == "tcp" && e.host.contains(':'))
        .min_by_key(|e| ipv4_field_rank(&e.host))
        .map(|e| e.host.as_str())
        .map(str::to_string);
    let client = client_for(base)?;
    client.register(ident, endpoints, ipv4.as_deref(), ipv6.as_deref())?;
    client
        .lookup(&wire)
        .map_err(|e| format!("register HTTP ok but GET /v1/peers failed: {e}"))?;
    Ok(())
}

pub(super) fn try_register_presence() -> Result<(), String> {
    let _http = coord_reg_http_lock()
        .lock()
        .map_err(|_| "coord register http mutex poisoned")?;
    let ident = match crate::session_runtime::unlocked_identity_clone() {
        Ok(i) => i,
        Err(_) => return Err("identity not unlocked".into()),
    };
    let wire = ident.identity_wire();
    let endpoints = endpoints_for_coord_register(
        coord_globals()
            .endpoints
            .lock()
            .map_err(|_| "coord mutex poisoned")?
            .clone(),
    );
    if endpoints.is_empty() {
        schedule_check_relay_presence_once();
        return Err("relay-only — coord register skipped".into());
    }
    let urls = coord_base_urls();
    if urls.is_empty() {
        return Err("coord base url not set".into());
    }
    let ep_summary: String = endpoints
        .iter()
        .map(|e| {
            if e.scheme == "libp2p" {
                format!("libp2p:{}", &e.host[..e.host.len().min(48)])
            } else {
                format!("{}://{}:{}", e.scheme, e.host, e.port)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut any_ok = false;
    let mut registered = HashSet::new();
    let mut last_err = String::new();
    for base in &urls {
        match try_register_on_server(base, &ident, &endpoints) {
            Ok(()) => {
                any_ok = true;
                registered.insert(base.clone());
                crate::flow_log::info(
                    "coord",
                    format!(
                        "registered on {base} — {} endpoint(s) for {} [{}]",
                        endpoints.len(),
                        &wire[..wire.len().min(16)],
                        ep_summary
                    ),
                );
            }
            Err(e) => {
                last_err = e.clone();
                let has_relay = endpoints.iter().any(|ep| ep.scheme == "libp2p");
                let (reason, action) =
                    crate::p2p::connectivity_diag::explain_coord_register_failure(&e, has_relay);
                crate::flow_log::warn(
                    "coord",
                    format!(
                        "register on {base} — reason={reason} | next={action} | http={last_err}"
                    ),
                );
            }
        }
    }
    if !any_ok {
        return Err(if last_err.is_empty() {
            "coord register failed on all servers".into()
        } else {
            last_err
        });
    }
    if let Ok(mut r) = coord_globals().registered_on.lock() {
        *r = registered;
    }
    COORD_REGISTERED.store(true, Ordering::Relaxed);
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(unix_ms_now(), Ordering::Relaxed);
    start_heartbeat_loop(wire);
    // We are visible on coord — known peers should lookup/dial us; we lookup them on next upkeep.
    crate::p2p::notify_dm_presence_wake();
    Ok(())
}
pub fn coord_register_now_json() -> serde_json::Value {
    if !coord_is_configured() {
        return serde_json::json!({ "ok": false, "error": "coord base url not set" });
    }
    if crate::session_runtime::unlocked_identity_clone().is_err() {
        return serde_json::json!({ "ok": false, "error": "identity not unlocked" });
    }
    let endpoints = match coord_globals().endpoints.lock() {
        Ok(v) => v.clone(),
        Err(_) => {
            return serde_json::json!({ "ok": false, "error": "coord mutex poisoned" });
        }
    };
    if endpoints.is_empty() {
        return serde_json::json!({
            "ok": false,
            "error": "no listen endpoints for coord register yet",
        });
    }
    if COORD_REGISTERED.load(Ordering::Relaxed) {
        return serde_json::json!({ "ok": true, "already_registered": true });
    }
    schedule_register_presence();
    serde_json::json!({ "ok": true, "scheduled": true })
}
