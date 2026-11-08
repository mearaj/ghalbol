//! P2P node holder, start/stop, and DM peer registration.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use serde_json::Value;

use crate::call_state;
use crate::contacts_v1::is_valid_public_key_hex;
use crate::dm_event_handler::{clear_p2p_handler_context, set_p2p_handler_context};
use crate::p2p::{
    DEFAULT_GOSSIP_TOPIC, GossipChatConfig, GossipChatEvent, OutboundCmd, native_log,
    set_drop_pending_call_invite_hook,
};
use crate::session_runtime::unlocked_identity_clone;

use super::helpers::{apply_coord_from_config, apply_delivery_from_p2p_config, json_err, json_ok, now_ms, parse_dm_peers};
use super::poll::drop_pending_call_invite;
use super::ui_session::clear_ui_session_snapshot;

pub(crate) struct P2pHolder {
    pub(crate) out_tx: std::sync::mpsc::Sender<OutboundCmd>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) join: std::thread::JoinHandle<()>,
    pub(crate) events_rx: std::sync::mpsc::Receiver<GossipChatEvent>,
}

pub(crate) fn p2p_mx() -> &'static Mutex<Option<P2pHolder>> {
    static P: OnceLock<Mutex<Option<P2pHolder>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

/// Soft ceiling — UI poll must not let an idle app accumulate unbounded gossip.
pub(crate) const MAX_PENDING_P2P_EVENTS: usize = 2_048;

pub(crate) fn pending_p2p_events_mx() -> &'static Mutex<VecDeque<GossipChatEvent>> {
    static P: OnceLock<Mutex<VecDeque<GossipChatEvent>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(VecDeque::new()))
}

pub(crate) fn push_pending_p2p_event(q: &mut VecDeque<GossipChatEvent>, ev: GossipChatEvent) {
    while q.len() >= MAX_PENDING_P2P_EVENTS {
        q.pop_front();
    }
    q.push_back(ev);
}

/// Bound register-dm-peer throttle keys (one per contact is enough).
const MAX_REGISTER_DM_PEER_THROTTLE: usize = 4_096;

pub(crate) fn register_dm_peer_throttle_mx() -> &'static RwLock<std::collections::HashMap<String, i64>> {
    static S: OnceLock<RwLock<std::collections::HashMap<String, i64>>> = OnceLock::new();
    S.get_or_init(|| RwLock::new(std::collections::HashMap::new()))
}

pub(crate) fn clear_pending_p2p_events() {
    if let Ok(mut q) = pending_p2p_events_mx().lock() {
        q.clear();
    }
}

pub(crate) fn drain_holder_events_into_pending(h: &P2pHolder) {
    let Ok(mut q) = pending_p2p_events_mx().lock() else {
        return;
    };
    while let Ok(ev) = h.events_rx.try_recv() {
        push_pending_p2p_event(&mut q, ev);
    }
}

pub(crate) fn poll_next_p2p_event() -> Option<GossipChatEvent> {
    if let Ok(g) = p2p_mx().lock() {
        if let Some(h) = g.as_ref() {
            if let Ok(ev) = h.events_rx.try_recv() {
                return Some(ev);
            }
        }
    }
    pending_p2p_events_mx()
        .lock()
        .ok()
        .and_then(|mut q| q.pop_front())
}

pub(crate) fn clear_p2p_holder() {
    if let Ok(mut g) = p2p_mx().lock() {
        if let Some(h) = g.take() {
            drain_holder_events_into_pending(&h);
        }
    }
}

fn reconcile_stale_p2p_holder(g: &mut Option<P2pHolder>) -> bool {
    let Some(h) = g.as_ref() else {
        return false;
    };
    if !h.join.is_finished() {
        return true;
    }
    let finished = g.take().expect("holder");
    drain_holder_events_into_pending(&finished);
    false
}

pub fn p2p_holder_alive() -> bool {
    let Ok(mut g) = p2p_mx().lock() else {
        return false;
    };
    reconcile_stale_p2p_holder(&mut g)
}

fn dm_peers_roster_fingerprint(dm_peers: &[crate::p2p::DmPeer], app_namespace: Option<&str>) -> String {
    let mut keys: Vec<&str> = dm_peers
        .iter()
        .map(|p| p.identity_wire.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    format!("{}|{}", app_namespace.unwrap_or(""), keys.join(","))
}

fn register_dm_peers_throttled(dm_peers: &[crate::p2p::DmPeer], app_namespace: Option<&str>) {
    static LAST: OnceLock<Mutex<(String, i64)>> = OnceLock::new();
    let fingerprint = dm_peers_roster_fingerprint(dm_peers, app_namespace);
    let now = now_ms();
    let skip = LAST
        .get_or_init(|| Mutex::new((String::new(), 0)))
        .lock()
        .ok()
        .is_some_and(|mut g| {
            if g.0 == fingerprint && now.saturating_sub(g.1) < 30_000 {
                true
            } else {
                g.0 = fingerprint;
                g.1 = now;
                false
            }
        });
    if skip {
        native_log::debug(
            "session",
            format!(
                "p2p_start roster sync unchanged ({} peers) — skip register burst",
                dm_peers.len()
            ),
        );
        return;
    }
    for dm in dm_peers {
        let pk = dm.identity_wire.trim();
        if !crate::contacts_v1::is_valid_public_key_hex(pk) {
            continue;
        }
        let _ = p2p_register_dm_peer(pk);
    }
}

pub(crate) fn stop_p2p_node(wait: Duration) {
    let join = {
        let Ok(mut g) = p2p_mx().lock() else {
            return;
        };
        let Some(h) = g.take() else {
            return;
        };
        h.stop.store(true, Ordering::SeqCst);
        drop(h.out_tx);
        h.join
    };
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = join.join();
        let _ = done_tx.send(());
    });
    let _ = done_rx.recv_timeout(wait);
}

/// DM + libp2p connectivity — forward to Makepad App log (`Native/…` tags in export).
fn native_log_should_forward_to_ui(line: &native_log::NativeLogLine) -> bool {
    if line.level == "warn" || line.level == "error" {
        return true;
    }
    let tag = line.tag.as_str();
    let connectivity = matches!(
        tag,
        "flow"
            | "net"
            | "p2p"
            | "swarm"
            | "kad"
            | "listen"
            | "relay"
            | "coord"
            | "mdns"
            | "dial"
            | "autonat"
            | "dcutr"
            | "upnp"
            | "stream"
            | "connect"
            | "bridge"
            | "call"
            | "call_media"
            | "call_video"
    );
    if connectivity {
        return line.level == "info" || (line.level == "debug" && native_log::verbose_enabled());
    }
    let dm_flow = matches!(
        tag,
        "DM/store"
            | "Contacts"
            | "Transcript"
            | "outbound"
            | "outbox"
            | "delivery_ack"
            | "delivery"
            | "read_ack"
            | "session"
            | "Storage"
    );
    if dm_flow && (line.level == "info" || line.level == "debug") {
        return true;
    }
    false
}

pub fn p2p_start(config: &Value) -> Value {
    crate::rustls_init::ensure_rustls_crypto_provider();
    set_drop_pending_call_invite_hook(drop_pending_call_invite);
    // Stale notification-tap marker must not fire presentWindow on next UI login.
    crate::desktop_wake::clear_incoming_call_wake();
    apply_coord_from_config(config);
    let topic = config
        .get("topic")
        .and_then(|t| t.as_str())
        .unwrap_or(DEFAULT_GOSSIP_TOPIC)
        .to_string();
    let dm_peers = parse_dm_peers(config);

    let ident = match unlocked_identity_clone() {
        Ok(i) => i,
        Err(e) => return json_err(e),
    };
    if !ident.p2p_ready() {
        return json_err("identity cannot start p2p on this build");
    }

    let mut gossip_cfg = match GossipChatConfig::from_unlocked_identity(topic, &ident) {
        Ok(c) => c,
        Err(e) => return json_err(e),
    };
    gossip_cfg.dm_peers = dm_peers;
    gossip_cfg.cap_dm_peers();
    gossip_cfg.app_namespace = config
        .get("app_namespace")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if p2p_holder_alive() {
        native_log::info(
            "p2p",
            format!(
                "p2p_start already_running — refresh handler + dm_peers={} ns={}",
                gossip_cfg.dm_peers.len(),
                gossip_cfg.app_namespace.as_deref().unwrap_or("(none)")
            ),
        );
        if let Some(ns) = gossip_cfg.app_namespace.as_deref() {
            set_p2p_handler_context(ns);
            crate::incoming_call_notify::set_desktop_app_id(ns);
        }
        register_dm_peers_throttled(
            &gossip_cfg.dm_peers,
            gossip_cfg.app_namespace.as_deref(),
        );
        if crate::coord_runtime::coord_is_configured() {
            crate::p2p::notify_relay_refresh();
        }
        apply_delivery_from_p2p_config(config);
        return json_ok(serde_json::json!({ "ok": true, "already_running": true }));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let (out_tx, out_rx) = std::sync::mpsc::channel::<OutboundCmd>();
    let (ev_tx, ev_rx) = std::sync::mpsc::channel::<GossipChatEvent>();
    let ev_tx_log = ev_tx.clone();
    native_log::set_sink(Some(Box::new(move |line| {
        if !native_log_should_forward_to_ui(&line) {
            return;
        }
        let _ = ev_tx_log.send(GossipChatEvent::NativeLog {
            level: line.level.to_string(),
            tag: line.tag,
            message: line.message,
        });
    })));
    native_log::info(
        "p2p",
        format!(
            "node starting identity={} dm_peers={}",
            ident.identity_wire(),
            gossip_cfg.dm_peers.len(),
        ),
    );

    if let Some(ns) = gossip_cfg.app_namespace.as_deref() {
        set_p2p_handler_context(ns);
        crate::incoming_call_notify::set_desktop_app_id(ns);
    }

    clear_pending_p2p_events();
    apply_delivery_from_p2p_config(config);
    {
        let contacts: Vec<String> = gossip_cfg
            .dm_peers
            .iter()
            .map(|p| p.identity_wire.clone())
            .collect();
        if let Err(e) = crate::connect::connect_start(&ident.identity_wire(), &contacts) {
            native_log::warn("connect", format!("connect_start failed: {e}"));
        }
    }
    let join = std::thread::spawn(move || {
        let default_panic_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            native_log::error("p2p", format!("panic: {info}"));
            default_panic_hook(info);
        }));
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let msg = format!("tokio runtime build failed: {e}");
                native_log::error("p2p", msg.clone());
                let _ = ev_tx.send(GossipChatEvent::NodeStopped { error: Some(msg) });
                native_log::set_sink(None);
                clear_p2p_holder();
                return;
            }
        };
        let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(crate::connect::run_connect_node_with_std_io(
                gossip_cfg,
                ident,
                out_rx,
                ev_tx.clone(),
                stop_t,
            ))
        }));
        native_log::set_sink(None);
        let stop_err = match run_result {
            Ok(Ok(())) => {
                native_log::info("p2p", "node stopped cleanly");
                None
            }
            Ok(Err(e)) => {
                let msg = format!("{e}");
                native_log::error("p2p", format!("node ended: {msg}"));
                Some(msg)
            }
            Err(panic) => {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    format!("panic: {s}")
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    format!("panic: {s}")
                } else {
                    "panic in p2p worker".to_string()
                };
                native_log::error("p2p", msg.clone());
                Some(msg)
            }
        };
        let _ = ev_tx.send(GossipChatEvent::NodeStopped { error: stop_err });
        clear_p2p_holder();
    });

    let holder = P2pHolder {
        out_tx,
        stop,
        join,
        events_rx: ev_rx,
    };

    match p2p_mx().lock() {
        Ok(mut g) => {
            if g.is_some() {
                drop(g);
                stop_p2p_node(Duration::from_secs(3));
                let Ok(mut g2) = p2p_mx().lock() else {
                    return json_err("p2p mutex poisoned");
                };
                if g2.is_some() {
                    return json_err("p2p still stopping (try again)");
                }
                *g2 = Some(holder);
            } else {
                *g = Some(holder);
            }
        }
        Err(_) => return json_err("p2p mutex poisoned"),
    }

    json_ok(serde_json::json!({ "ok": true }))
}


pub fn p2p_stop() {
    native_log::info("p2p", "p2p_stop requested");
    crate::connect::connect_stop();
    crate::delivery_runtime::delivery_stop();
    clear_ui_session_snapshot();
    crate::connect::reset_live_session_ui_after_stop();
    crate::coord_runtime::stop_coord_presence();
    crate::p2p::set_app_ack_read_enabled(false);
    if let Ok(mut m) = register_dm_peer_throttle_mx().write() {
        m.clear();
    }
    stop_p2p_node(Duration::from_secs(3));
    call_state::clear_all_calls();
    crate::incoming_call_notify::dismiss_incoming_call();
    clear_p2p_handler_context();
    native_log::set_sink(None);
}

pub fn p2p_register_dm_peer(public_key_hex: &str) -> Value {
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    let pk_trim = public_key_hex.trim();
    // UI can call this repeatedly while processing lots of inbound events / transcript patches.
    // That burst causes repeated coord lookups + dial churn and can destabilize the DM stream.
    // Keep it idempotent: enqueue at most once per peer per short window.
    let now = now_ms();
    if is_valid_public_key_hex(pk_trim) {
        if let Ok(mut m) = register_dm_peer_throttle_mx().write() {
            if let Some(last) = m.get(pk_trim).copied() {
                if now.saturating_sub(last) < 1_200 {
                    return json_ok(serde_json::json!({ "ok": true, "throttled": true }));
                }
            }
            if !m.contains_key(pk_trim) && m.len() >= MAX_REGISTER_DM_PEER_THROTTLE {
                // Drop stale entries first, then an arbitrary key if still full.
                m.retain(|_, ts| now.saturating_sub(*ts) < 60_000);
                while m.len() >= MAX_REGISTER_DM_PEER_THROTTLE {
                    if let Some(k) = m.keys().next().cloned() {
                        m.remove(&k);
                    } else {
                        break;
                    }
                }
            }
            m.insert(pk_trim.to_string(), now);
        }
    }
    let pk_short = crate::flow_log::short_hex(pk_trim);
    native_log::info("session", format!("register_dm_peer pk={pk_short}"));
    if out_tx
        .send(OutboundCmd::RegisterDmPeer {
            public_key_hex: public_key_hex.to_string(),
        })
        .is_err()
    {
        native_log::warn("session", "register_dm_peer failed: node stopped?");
        return json_err("p2p register failed (node stopped?)");
    }
    json_ok(serde_json::json!({ "ok": true }))
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::p2p::DmPeer;

    #[test]
    fn roster_fingerprint_stable_across_order() {
        let a = DmPeer {
            identity_wire: "bb".repeat(32),
        };
        let b = DmPeer {
            identity_wire: "aa".repeat(32),
        };
        let f1 = dm_peers_roster_fingerprint(&[a.clone(), b.clone()], Some("ns"));
        let f2 = dm_peers_roster_fingerprint(&[b, a], Some("ns"));
        assert_eq!(f1, f2);
        let f3 = dm_peers_roster_fingerprint(
            &[DmPeer {
                identity_wire: "cc".repeat(32),
            }],
            Some("ns"),
        );
        assert_ne!(f1, f3);
    }

    #[test]
    fn pending_p2p_event_queue_drops_oldest_when_full() {
        clear_pending_p2p_events();
        let mut q = VecDeque::new();
        for i in 0..MAX_PENDING_P2P_EVENTS {
            push_pending_p2p_event(
                &mut q,
                GossipChatEvent::Listening(format!("addr-{i}")),
            );
        }
        assert_eq!(q.len(), MAX_PENDING_P2P_EVENTS);
        push_pending_p2p_event(&mut q, GossipChatEvent::Listening("newest".into()));
        assert_eq!(q.len(), MAX_PENDING_P2P_EVENTS);
        assert!(matches!(
            q.front(),
            Some(GossipChatEvent::Listening(s)) if s == "addr-1"
        ));
        assert!(matches!(
            q.back(),
            Some(GossipChatEvent::Listening(s)) if s == "newest"
        ));
        clear_pending_p2p_events();
    }
}

