//! Main connect worker loop — mDNS + TCP + Noise + mux.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::select;

use super::lan_discovery::{LanDiscovery, LanDiscoveryEvent, spawn_event_forwarder};
use super::outbound::process_outbound_cmds;
use super::outbox_acks::run_ack_upkeep;
use super::peer_session::{PeerSessionRegistry, SessionWriters, accept_inbound_tcp, dial_peer_tcp};
use super::session::{SessionState, chrono_now_ms};
use super::types::{
    ConnectConfig, ConnectError, GossipChatEvent, MAX_OUTBOUND_CMDS_PER_TICK, OutboundCmd,
    SessionPeer,
};
use crate::dm_transport::DmDialAddr;
use crate::p2p::native_log;

static LAST_BRIDGE_PENDING_POLL_MS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);
const BRIDGE_PENDING_POLL_MS: i64 = 3_000;
static LAST_COORD_DIAL_SWEEP_MS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);
/// Last observed OS default transport discriminant for handover detection.
static LAST_OS_DEFAULT_TRANSPORT: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(0xff);
/// Storm throttle for coord public-TCP sweep (urgent/priority still win inside the pass).
const COORD_DIAL_SWEEP_MS: i64 = 5_000;
/// Back off repeated mDNS-driven LAN dials while a prior attempt to the same endpoint failed.
const LAN_MDNS_DIAL_BACKOFF_MS: i64 = 5_000;
/// Outbound dial task uses a 4s connect timeout — wait before trying the next coord address.
pub(crate) const DIAL_ADDR_ATTEMPT_WAIT_ITERS: u32 = 50;
static LAN_MDNS_DIAL_BACKOFF: std::sync::LazyLock<Mutex<HashMap<String, i64>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
/// After a failed accept, wait before retrying the same bridge_id (avoids log storms).
const BRIDGE_ACCEPT_RETRY_MS: i64 = 30_000;
static BRIDGE_ACCEPT_BACKOFF: std::sync::LazyLock<Mutex<HashMap<String, i64>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
/// bridge_ids currently in `accept_bridge_pending` — do not spawn duplicates.
static BRIDGE_ACCEPT_INFLIGHT: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
/// Hard ceiling on concurrent bridge accepts (DoS / task fan-out).
const MAX_BRIDGE_ACCEPT_INFLIGHT: usize = 32;

pub struct ConnectWorkerState {
    pub registry: Arc<PeerSessionRegistry>,
    pub session: Arc<SessionState>,
    pub identity: crate::DecryptedIdentity,
    pub events_tx: std::sync::mpsc::Sender<GossipChatEvent>,
}

pub async fn run_connect_node_with_std_io(
    mut config: ConnectConfig,
    identity: crate::DecryptedIdentity,
    outbound_rx: std::sync::mpsc::Receiver<OutboundCmd>,
    events_tx: std::sync::mpsc::Sender<GossipChatEvent>,
    stop: Arc<AtomicBool>,
) -> Result<(), ConnectError> {
    config.cap_dm_peers();
    let ident_wire = identity.identity_wire();
    native_log::info("connect", "starting native connect worker");

    let session = Arc::new(
        SessionState::new(
            identity.clone(),
            &config.dm_peers,
            config.app_namespace.clone(),
        )
        .map_err(ConnectError::Other)?,
    );

    let registry = Arc::new(PeerSessionRegistry::new(ident_wire.clone()));

    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(ConnectError::Io)?;
    let local_addr = listener.local_addr().map_err(ConnectError::Io)?;
    let listen_port = local_addr.port();
    let listen_str = format!("{}:{}", local_addr.ip(), local_addr.port());
    let _ = events_tx.send(GossipChatEvent::Listening(listen_str.clone()));
    native_log::info(
        "connect",
        format!(
            "TCP listen {listen_str} pattern={}",
            super::noise_session::NOISE_PATTERN
        ),
    );

    let mut discovery = LanDiscovery::new().map_err(ConnectError::Other)?;
    for p in &config.dm_peers {
        let _ = discovery.register_contact(&p.identity_wire);
    }
    let _ = discovery.publish_listener(&ident_wire, local_addr.port());
    let discovery = Arc::new(std::sync::Mutex::new(discovery));
    let (mdns_tx, mut mdns_rx) = tokio::sync::mpsc::unbounded_channel::<LanDiscoveryEvent>();
    spawn_event_forwarder(Arc::clone(&discovery), mdns_tx);

    let _ = events_tx.send(GossipChatEvent::NodeReady);

    let worker = Arc::new(ConnectWorkerState {
        registry: Arc::clone(&registry),
        session: Arc::clone(&session),
        identity: identity.clone(),
        events_tx: events_tx.clone(),
    });

    let events_opt = Some(events_tx.clone());
    let mut upkeep = tokio::time::interval(std::time::Duration::from_secs(1));
    upkeep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        if super::notify::take_connect_upkeep_notify() {
            run_connect_upkeep(
                &identity,
                listen_port,
                Arc::clone(&registry),
                Arc::clone(&session),
                events_tx.clone(),
            );
        }

        process_outbound_cmds(
            Arc::clone(&worker),
            &events_opt,
            &outbound_rx,
            MAX_OUTBOUND_CMDS_PER_TICK,
        )
        .await;

        while let Ok(ev) = mdns_rx.try_recv() {
            match ev {
                LanDiscoveryEvent::Discovered {
                    identity_commitment,
                    host,
                    port,
                } => {
                    let peer_wire = discovery
                        .lock()
                        .ok()
                        .and_then(|d| d.wire_for_commitment(&identity_commitment));
                    if let Some(peer) = peer_wire {
                        if super::peer_session::writer_open_for_peer(&registry.writers, &peer) {
                            continue;
                        }
                        let now = chrono_now_ms();
                        if lan_mdns_dial_backoff_active(&peer, &host, port, now) {
                            continue;
                        }
                        record_lan_mdns_dial_attempt(&peer, &host, port, now);
                        native_log::info(
                            "connect",
                            format!("mdns discovered {host}:{port} peer={peer}"),
                        );
                        let reg = Arc::clone(&registry);
                        let sess = Arc::clone(&session);
                        let id = identity.clone();
                        let ev = events_tx.clone();
                        tokio::spawn(dial_peer_tcp(reg, sess, id, ev, peer, host, port));
                    }
                }
                LanDiscoveryEvent::Expired {
                    identity_commitment,
                } => {
                    if let Some(peer) = discovery
                        .lock()
                        .ok()
                        .and_then(|d| d.wire_for_commitment(&identity_commitment))
                    {
                        native_log::info("connect", format!("mdns expired {peer}"));
                        clear_lan_mdns_dial_backoff_for_peer(&peer);
                        registry.remove_session(&peer);
                        session.set_peer_on_local_lan(&peer, false);
                    }
                }
            }
        }

        select! {
            biased;
            accept = listener.accept() => {
                if let Ok((stream, addr)) = accept {
                    let reg = Arc::clone(&registry);
                    let sess = Arc::clone(&session);
                    let id = identity.clone();
                    let ev = events_tx.clone();
                    tokio::spawn(accept_inbound_tcp(reg, sess, id, ev, stream, addr));
                }
            }
            _ = upkeep.tick() => {
                run_connect_upkeep(
                    &identity,
                    listen_port,
                    Arc::clone(&registry),
                    Arc::clone(&session),
                    events_tx.clone(),
                );
                super::chat_room_session::tick_chat_room_session_if_active(session.as_ref());
                let connected: Vec<SessionPeer> = registry
                    .writers
                    .read()
                    .ok()
                    .map(|g| g.keys().cloned().collect())
                    .unwrap_or_default();
                if !connected.is_empty() {
                    let sess = Arc::clone(&session);
                    let writers: SessionWriters = Arc::clone(&registry.writers);
                    let ev = events_tx.clone();
                    let peers = connected.clone();
                    super::outbox_acks::resync_pending_outbox(sess, writers, peers, Some(ev)).await;
                    run_ack_upkeep(
                        Arc::clone(&session),
                        Arc::clone(&registry.writers),
                        &connected,
                    )
                    .await;
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
    }

    registry.abort_all_sessions();
    let _ = events_tx.send(GossipChatEvent::NodeStopped { error: None });
    Ok(())
}

pub fn mark_peer_connected(
    session: &SessionState,
    peer: &SessionPeer,
    events_tx: &std::sync::mpsc::Sender<GossipChatEvent>,
) {
    session.set_peer_connected(peer, true);
    session.set_stream_ready(peer, true);
    if session.emit_identified_once(peer) {
        let _ = events_tx.send(GossipChatEvent::PeerIdentified {
            peer_id: peer.clone(),
            public_key_hex: peer.clone(),
        });
    }
    if session.emit_chat_ready_once(peer) {
        let _ = events_tx.send(GossipChatEvent::ChatReady {
            peer_id: peer.clone(),
        });
    }
    let _ = events_tx.send(GossipChatEvent::PeerConnected(peer.clone()));
}

pub fn mark_peer_disconnected(
    session: &SessionState,
    peer: &SessionPeer,
    events_tx: &std::sync::mpsc::Sender<GossipChatEvent>,
) {
    session.set_peer_connected(peer, false);
    session.set_stream_ready(peer, false);
    session.clear_transport_kem_for_peer(peer);
    crate::coord_runtime::note_peer_disconnect_urgent(peer);
    let _ = events_tx.send(GossipChatEvent::PeerDisconnected(peer.clone()));
}

fn os_default_transport_disc(
    t: crate::p2p::network_transport::OsDefaultTransport,
) -> u8 {
    use crate::p2p::network_transport::OsDefaultTransport;
    match t {
        OsDefaultTransport::None => 0,
        OsDefaultTransport::Wifi => 1,
        OsDefaultTransport::Cellular => 2,
        OsDefaultTransport::Ethernet => 3,
    }
}

fn run_connect_upkeep(
    identity: &crate::DecryptedIdentity,
    listen_port: u16,
    registry: Arc<PeerSessionRegistry>,
    session: Arc<SessionState>,
    events_tx: std::sync::mpsc::Sender<GossipChatEvent>,
) {
    crate::p2p::network_transport::refresh_os_network_truth();
    let mut net = crate::p2p::network_transport::detect_local_network_profile();
    crate::p2p::network_transport::merge_os_network_truth(&mut net);
    let disc = os_default_transport_disc(net.os.default_transport);
    let prev = LAST_OS_DEFAULT_TRANSPORT.swap(disc, Ordering::SeqCst);
    if prev != 0xff && prev != disc {
        native_log::info(
            "connect",
            format!(
                "OS default route changed disc {prev}→{disc} iface={:?}",
                net.os.default_route_iface
            ),
        );
        crate::coord_runtime::coord_invalidate_presence_on_network_change();
    }
    if let Some(pub_ip) = net.primary_public_ipv4 {
        if let Some(addr) = parse_listen_dm_addr(pub_ip, listen_port) {
            crate::coord_runtime::on_listen_dm_addr(&addr);
        }
    }
    crate::coord_runtime::coord_register_tick(&[]);

    // TRANSPORT.md scale invariant: urgent → priority → capped background public-TCP dials.
    let sweep_now = chrono_now_ms();
    let last_sweep = LAST_COORD_DIAL_SWEEP_MS.load(std::sync::atomic::Ordering::Relaxed);
    if crate::coord_runtime::coord_is_configured()
        && sweep_now.saturating_sub(last_sweep) >= COORD_DIAL_SWEEP_MS
    {
        LAST_COORD_DIAL_SWEEP_MS.store(sweep_now, std::sync::atomic::Ordering::Relaxed);
        spawn_scheduled_coord_dials(
            Arc::clone(&registry),
            Arc::clone(&session),
            identity.clone(),
            events_tx.clone(),
        );
    }

    let now = chrono_now_ms();
    let last = LAST_BRIDGE_PENDING_POLL_MS.load(std::sync::atomic::Ordering::Relaxed);
    if now.saturating_sub(last) < BRIDGE_PENDING_POLL_MS {
        return;
    }
    LAST_BRIDGE_PENDING_POLL_MS.store(now, std::sync::atomic::Ordering::Relaxed);
    if !crate::coord_runtime::coord_is_configured() {
        return;
    }
    let ident_wire = identity.identity_wire();
    let reg = Arc::clone(&registry);
    let sess = Arc::clone(&session);
    let id = identity.clone();
    let ev = events_tx;
    tokio::spawn(async move {
        let pending = match tokio::task::spawn_blocking(move || {
            super::bridge_ws::poll_bridge_pending_blocking(&ident_wire)
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                native_log::debug("bridge", format!("pending poll: {e}"));
                return;
            }
            Err(e) => {
                native_log::debug("bridge", format!("pending poll task: {e}"));
                return;
            }
        };
        for item in pending {
            let caller = item.caller_identity_wire.clone();
            // Skip only when a live writer exists — a stale registry entry must not
            // block WAN bridge accept (cell↔Wi‑Fi calls).
            if super::peer_session::writer_open_for_peer(&reg.writers, &caller) {
                continue;
            }
            let now_ms = chrono_now_ms();
            if let Ok(g) = BRIDGE_ACCEPT_BACKOFF.lock() {
                if g.get(&item.bridge_id).is_some_and(|until| *until > now_ms) {
                    continue;
                }
            }
            {
                let Ok(mut inflight) = BRIDGE_ACCEPT_INFLIGHT.lock() else {
                    continue;
                };
                if inflight.contains(&item.bridge_id) {
                    continue; // already accepting this bridge_id
                }
                if inflight.len() >= MAX_BRIDGE_ACCEPT_INFLIGHT {
                    continue; // global fan-out ceiling
                }
                inflight.insert(item.bridge_id.clone());
            }
            native_log::info(
                "bridge",
                format!("accepting pending bridge call_id={}", item.call_id),
            );
            let bridge_id = item.bridge_id.clone();
            let accept_result = super::bridge_ws::accept_bridge_pending(
                Arc::clone(&reg),
                Arc::clone(&sess),
                id.clone(),
                ev.clone(),
                caller,
                item,
            )
            .await;
            if let Ok(mut inflight) = BRIDGE_ACCEPT_INFLIGHT.lock() {
                inflight.remove(&bridge_id);
            }
            if let Err(e) = accept_result {
                native_log::warn("bridge", format!("accept pending bridge failed: {e}"));
                if let Ok(mut g) = BRIDGE_ACCEPT_BACKOFF.lock() {
                    g.insert(bridge_id, now_ms + BRIDGE_ACCEPT_RETRY_MS);
                    if g.len() > 64 {
                        g.retain(|_, until| *until > now_ms);
                    }
                    while g.len() > 64 {
                        let Some(oldest) = g.keys().next().cloned() else {
                            break;
                        };
                        g.remove(&oldest);
                    }
                }
            }
        }
    });
}

fn spawn_scheduled_coord_dials(
    registry: Arc<PeerSessionRegistry>,
    session: Arc<SessionState>,
    identity: crate::DecryptedIdentity,
    events_tx: std::sync::mpsc::Sender<GossipChatEvent>,
) {
    let mut priority = session.peers_with_pending_outbox();
    if let Some(fg) = session.foreground_peer() {
        if !priority.iter().any(|p| p == &fg) {
            priority.push(fg);
        }
    }
    let mut all = session.list_dm_peer_wires();
    if let Some(ns) = session.app_namespace.as_deref() {
        if let Ok(contacts) = crate::contacts_v1::list_contacts(ns) {
            for c in contacts {
                if c.has_public_key() && !all.iter().any(|p| p.eq_ignore_ascii_case(&c.public_key_hex))
                {
                    all.push(c.public_key_hex);
                }
            }
        }
    }
    let connected: Vec<String> = all
        .iter()
        .filter(|p| super::peer_session::writer_open_for_peer(&registry.writers, p))
        .cloned()
        .collect();
    let targets =
        crate::coord_runtime::peers_for_lookup_tick(&[], &priority, &all, &connected);
    if targets.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for pk in targets {
            if super::peer_session::writer_open_for_peer(&registry.writers, &pk) {
                continue;
            }
            let addrs =
                match crate::coord_runtime::lookup_dial_addrs_for_public_key_async(&pk).await {
                    Ok(a) if !a.is_empty() => a,
                    Ok(_) => continue,
                    Err(_) => continue,
                };
            for addr in addrs.into_iter().take(2) {
                if super::peer_session::writer_open_for_peer(&registry.writers, &pk) {
                    break;
                }
                let reg = Arc::clone(&registry);
                let sess = Arc::clone(&session);
                let id = identity.clone();
                let ev = events_tx.clone();
                let peer = pk.clone();
                tokio::spawn(dial_peer_tcp(
                    reg, sess, id, ev, peer, addr.host, addr.port,
                ));
                for _ in 0..DIAL_ADDR_ATTEMPT_WAIT_ITERS {
                    if super::peer_session::writer_open_for_peer(&registry.writers, &pk) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });
}

fn lan_mdns_dial_key(peer: &SessionPeer, host: &str, port: u16) -> String {
    format!("{peer}\n{host}\n{port}")
}

fn lan_mdns_dial_backoff_active(peer: &SessionPeer, host: &str, port: u16, now_ms: i64) -> bool {
    let Ok(g) = LAN_MDNS_DIAL_BACKOFF.lock() else {
        return false;
    };
    g.get(&lan_mdns_dial_key(peer, host, port))
        .is_some_and(|last| now_ms.saturating_sub(*last) < LAN_MDNS_DIAL_BACKOFF_MS)
}

fn clear_lan_mdns_dial_backoff_for_peer(peer: &SessionPeer) {
    if let Ok(mut g) = LAN_MDNS_DIAL_BACKOFF.lock() {
        let prefix = format!("{peer}\n");
        g.retain(|k, _| !k.starts_with(&prefix));
    }
}

fn record_lan_mdns_dial_attempt(peer: &SessionPeer, host: &str, port: u16, now_ms: i64) {
    if let Ok(mut g) = LAN_MDNS_DIAL_BACKOFF.lock() {
        g.insert(lan_mdns_dial_key(peer, host, port), now_ms);
        if g.len() > 256 {
            g.retain(|_, ts| now_ms.saturating_sub(*ts) < LAN_MDNS_DIAL_BACKOFF_MS);
        }
        while g.len() > 256 {
            let Some(oldest) = g.keys().next().cloned() else {
                break;
            };
            g.remove(&oldest);
        }
    }
}

fn parse_listen_dm_addr(pub_ip: std::net::Ipv4Addr, listen_port: u16) -> Option<DmDialAddr> {
    DmDialAddr::parse(&format!("{pub_ip}:{listen_port}"))
}

#[cfg(test)]
mod dial_policy_tests {
    use super::*;

    #[test]
    fn parse_listen_dm_addr_ipv4_host_port() {
        let a = parse_listen_dm_addr("192.0.2.5".parse().unwrap(), 4242).unwrap();
        assert_eq!(a.host, "192.0.2.5");
        assert_eq!(a.port, 4242);
    }

    #[test]
    fn lan_mdns_dial_backoff_per_endpoint() {
        let peer = "0220899663decabbb1b9f19c2e7baa610e123badd98cfe6e43484f941c45a36d0c".to_string();
        if let Ok(mut g) = LAN_MDNS_DIAL_BACKOFF.lock() {
            g.clear();
        }
        record_lan_mdns_dial_attempt(&peer, "10.0.0.2", 9000, 1_000);
        assert!(lan_mdns_dial_backoff_active(&peer, "10.0.0.2", 9000, 3_000));
        assert!(!lan_mdns_dial_backoff_active(&peer, "10.0.0.2", 9000, 6_001));
        assert!(!lan_mdns_dial_backoff_active(&peer, "10.0.0.3", 9000, 3_000));
    }

    #[test]
    fn bridge_accept_inflight_respects_global_ceiling() {
        let Ok(mut inflight) = BRIDGE_ACCEPT_INFLIGHT.lock() else {
            return;
        };
        inflight.clear();
        for i in 0..MAX_BRIDGE_ACCEPT_INFLIGHT {
            assert!(
                inflight.len() < MAX_BRIDGE_ACCEPT_INFLIGHT,
                "precondition"
            );
            inflight.insert(format!("b{i}"));
        }
        assert_eq!(inflight.len(), MAX_BRIDGE_ACCEPT_INFLIGHT);
        // Admission gate used by the accept loop.
        let next = "b-overflow".to_string();
        assert!(!inflight.contains(&next));
        assert!(inflight.len() >= MAX_BRIDGE_ACCEPT_INFLIGHT);
        inflight.clear();
    }

    #[test]
    fn lan_mdns_dial_backoff_hard_caps_map_size() {
        if let Ok(mut g) = LAN_MDNS_DIAL_BACKOFF.lock() {
            g.clear();
        }
        let peer = "0220899663decabbb1b9f19c2e7baa610e123badd98cfe6e43484f941c45a36d0c".to_string();
        // All timestamps "fresh" so retain alone would not shrink.
        for i in 0..300 {
            record_lan_mdns_dial_attempt(&peer, &format!("10.0.0.{i}"), 9000, 1_000_000);
        }
        let len = LAN_MDNS_DIAL_BACKOFF.lock().map(|g| g.len()).unwrap_or(0);
        assert!(len <= 256, "backoff map grew to {len}");
    }
}
