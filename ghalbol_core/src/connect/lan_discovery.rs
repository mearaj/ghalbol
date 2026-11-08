//! mDNS LAN discovery via `mdns-sd` (`_ghalbol._tcp.local`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flume::Receiver;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;

use super::id_commitment::identity_commitment_hex;
use super::types::CONNECT_MDNS_SERVICE;

#[derive(Clone, Debug)]
pub enum LanDiscoveryEvent {
    Discovered {
        identity_commitment: String,
        host: String,
        port: u16,
    },
    Expired {
        identity_commitment: String,
    },
}

pub struct LanDiscovery {
    daemon: ServiceDaemon,
    event_rx: Receiver<ServiceEvent>,
    /// identity_wire → commitment hex
    contact_commitments: HashMap<String, String>,
    /// commitment → identity_wire
    commitment_to_wire: HashMap<String, String>,
    /// Suppress repeated `ServiceResolved` for the same contact endpoint (mDNS refresh flood).
    last_discovered: Mutex<HashMap<String, (String, u16)>>,
}

impl LanDiscovery {
    pub fn new() -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("mdns daemon: {e}"))?;
        let event_rx = daemon
            .browse(CONNECT_MDNS_SERVICE)
            .map_err(|e| format!("mdns browse: {e}"))?;
        Ok(Self {
            daemon,
            event_rx,
            contact_commitments: HashMap::new(),
            commitment_to_wire: HashMap::new(),
            last_discovered: Mutex::new(HashMap::new()),
        })
    }

    pub fn register_contact(&mut self, identity_wire: &str) -> Result<(), String> {
        let wire = crate::public_key_util::normalize_contact_identity_wire(identity_wire)?;
        let idc = identity_commitment_hex(&wire)?;
        self.commitment_to_wire.insert(idc.clone(), wire.clone());
        self.contact_commitments.insert(wire, idc);
        Ok(())
    }

    pub fn publish_listener(&self, identity_wire: &str, port: u16) -> Result<(), String> {
        let wire = crate::public_key_util::normalize_contact_identity_wire(identity_wire)?;
        let idc = identity_commitment_hex(&wire)?;
        let host = mdns_local_hostname();
        let mut props = HashMap::new();
        props.insert("v".to_string(), "1".to_string());
        props.insert("idc".to_string(), idc.clone());
        let info = ServiceInfo::new(CONNECT_MDNS_SERVICE, &idc, &host, "", port, Some(props))
            .map_err(|e| format!("mdns service info: {e}"))?;
        self.daemon
            .register(info)
            .map_err(|e| format!("mdns register: {e}"))?;
        Ok(())
    }

    /// Drain pending mDNS events into connect-layer discovery events (non-blocking).
    pub fn drain_events(&self) -> Vec<LanDiscoveryEvent> {
        let mut out = Vec::new();
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if let Some(ev) = self.resolved_to_event(info.as_ref()) {
                        out.push(ev);
                    }
                }
                ServiceEvent::ServiceRemoved(_, fullname) => {
                    if let Some(idc) = fullname
                        .split('.')
                        .next()
                        .and_then(normalize_idc_hex)
                    {
                        if let Ok(mut g) = self.last_discovered.lock() {
                            g.remove(&idc);
                        }
                        out.push(LanDiscoveryEvent::Expired {
                            identity_commitment: idc,
                        });
                    }
                }
                _ => {}
            }
        }
        out
    }

    pub fn wire_for_commitment(&self, identity_commitment: &str) -> Option<String> {
        let idc = normalize_idc_hex(identity_commitment)?;
        self.commitment_to_wire.get(&idc).cloned()
    }

    fn resolved_to_event(&self, info: &ResolvedService) -> Option<LanDiscoveryEvent> {
        let idc = info
            .get_property_val_str("idc")
            .and_then(normalize_idc_hex)
            .or_else(|| {
                info.get_fullname()
                    .split('.')
                    .next()
                    .and_then(normalize_idc_hex)
            })?;
        if !self.commitment_to_wire.contains_key(&idc) {
            return None;
        }
        let port = info.get_port();
        let host = pick_lan_ip(info)?;
        // Check + remember under one lock so a refresh between locks cannot double-emit.
        let Ok(mut g) = self.last_discovered.lock() else {
            return None;
        };
        if g.get(&idc).is_some_and(|(h, p)| h == &host && *p == port) {
            return None;
        }
        // Bound cache to known contacts (+1 for this insert); drop stale idcs no longer tracked.
        let allowed = self.commitment_to_wire.len().saturating_add(1).max(1);
        if !g.contains_key(&idc) && g.len() >= allowed {
            g.retain(|k, _| self.commitment_to_wire.contains_key(k));
        }
        while !g.contains_key(&idc) && g.len() >= allowed {
            if let Some(old) = g.keys().next().cloned() {
                g.remove(&old);
            } else {
                break;
            }
        }
        g.insert(idc.clone(), (host.clone(), port));
        drop(g);
        Some(LanDiscoveryEvent::Discovered {
            identity_commitment: idc,
            host,
            port,
        })
    }
}

/// mDNS may surface `idc` with different ASCII casing; commitments are lowercase hex.
fn normalize_idc_hex(idc: &str) -> Option<String> {
    let t = idc.trim();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

/// Soft ceiling — pathological `HOSTNAME` must not become an mDNS label bomb.
const MAX_MDNS_HOSTNAME_CHARS: usize = 63;

/// Hostname for mDNS-SD registration (`mdns-sd` requires a `.local.` suffix).
fn mdns_local_hostname() -> String {
    let raw = std::env::var("HOSTNAME").unwrap_or_else(|_| "ghalbol".to_string());
    let trimmed = raw.trim().trim_end_matches('.');
    let safe = if trimmed.is_empty()
        || trimmed.len() > MAX_MDNS_HOSTNAME_CHARS
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        "ghalbol"
    } else {
        trimmed
    };
    if safe.to_ascii_lowercase().ends_with(".local") {
        format!("{safe}.")
    } else {
        format!("{safe}.local.")
    }
}

fn pick_lan_ip(info: &ResolvedService) -> Option<String> {
    crate::p2p::network_transport::prefer_lan_dial_ipv4(info.get_addresses_v4().into_iter())
        .map(|v4| v4.to_string())
}

/// Async bridge: forward mDNS events to a tokio channel.
pub fn spawn_event_forwarder(
    discovery: Arc<std::sync::Mutex<LanDiscovery>>,
    tx: mpsc::UnboundedSender<LanDiscoveryEvent>,
) {
    std::thread::Builder::new()
        .name("ghalbol_mdns".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(200));
                let events = discovery
                    .lock()
                    .ok()
                    .map(|d| d.drain_events())
                    .unwrap_or_default();
                for ev in events {
                    let _ = tx.send(ev);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_idc_hex_lowercases_and_rejects_junk() {
        let lower = "a".repeat(64);
        let upper: String = lower.chars().map(|c| c.to_ascii_uppercase()).collect();
        assert_eq!(normalize_idc_hex(&upper).as_deref(), Some(lower.as_str()));
        assert!(normalize_idc_hex("short").is_none());
        assert!(normalize_idc_hex(&"g".repeat(64)).is_none());
    }

    #[test]
    fn pick_lan_ip_uses_prefer_lan_dial_ipv4() {
        let lan: std::net::Ipv4Addr = "10.0.0.8".parse().unwrap();
        let picked = crate::p2p::network_transport::prefer_lan_dial_ipv4(
            [
                std::net::Ipv4Addr::LOCALHOST,
                "100.64.0.1".parse().unwrap(),
                lan,
            ]
            .into_iter(),
        );
        assert_eq!(picked, Some(lan));
    }

    #[test]
    fn register_contact_normalizes_wire_before_commitment() {
        // Avoid ServiceDaemon — parallel tests can race the OS mDNS stack.
        let wire = "0220899663decabbb1b9f19c2e7baa610e123badd98cfe6e43484f941c45a36d0c";
        let upper = wire.to_uppercase();
        let norm = crate::public_key_util::normalize_contact_identity_wire(&upper).unwrap();
        assert_eq!(norm, wire);
        let idc = identity_commitment_hex(&upper).unwrap();
        assert_eq!(idc, identity_commitment_hex(wire).unwrap());
        assert_eq!(normalize_idc_hex(&idc.to_uppercase()).as_deref(), Some(idc.as_str()));
    }

    #[test]
    fn mdns_local_hostname_falls_back_on_hostile_env() {
        let prev = std::env::var_os("HOSTNAME");
        // SAFETY: test-only; serialised by this function's restore.
        unsafe {
            std::env::set_var("HOSTNAME", "ok-host");
        }
        assert_eq!(mdns_local_hostname(), "ok-host.local.");
        unsafe {
            std::env::set_var("HOSTNAME", "a".repeat(MAX_MDNS_HOSTNAME_CHARS + 1));
        }
        assert_eq!(mdns_local_hostname(), "ghalbol.local.");
        unsafe {
            std::env::set_var("HOSTNAME", "bad host!");
        }
        assert_eq!(mdns_local_hostname(), "ghalbol.local.");
        unsafe {
            match prev {
                Some(v) => std::env::set_var("HOSTNAME", v),
                None => std::env::remove_var("HOSTNAME"),
            }
        }
    }
}
