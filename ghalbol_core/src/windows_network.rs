//! Windows network truth — adapter carrying the OS default IPv4 route.
//!
//! A connected UDP socket asks the routing table which local address reaches the internet
//! (no packet is sent). That address names the adapter; Windows adapter names ("Wi-Fi",
//! "Ethernet", "Cellular") classify the transport.

use std::net::{IpAddr, UdpSocket};

use crate::p2p::network_transport::{OsDefaultTransport, OsNetworkSnapshot};

/// Any public address works: only the route lookup matters.
const ROUTE_PROBE_ADDR: &str = "1.1.1.1:53";

fn iface_name_is_wifi(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("wi-fi") || n.contains("wifi") || n.contains("wlan") || n.contains("wireless")
}

fn iface_name_is_cellular(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("cellular") || n.contains("mobile broadband") || n.contains("wwan")
}

/// VPN / tunnel / virtual adapters must not be treated as the OS default LAN path.
fn windows_default_route_adapter_disqualified(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("loopback")
        || n.contains("vpn")
        || n.contains("wireguard")
        || n.contains("wintun")
        || n.contains("tap-windows")
        || n.contains("tailscale")
        || n.contains("zerotier")
        || n.contains("nordlynx")
        || n.contains("openvpn")
        || n.contains("isatap")
        || n.contains("teredo")
        || n.contains("6to4")
        || n.contains("pptp")
        || n.contains("ppp")
        || n.contains("ras ")
        || n.contains("vethernet")
        || n.contains("hyper-v")
        || n.contains("bluetooth")
        || n.contains("wi-fi direct")
        || n.contains("wifi direct")
        || n.contains("virtualbox")
        || n.contains("vmware")
        || n.contains("softether")
        || n.contains("anyconnect")
        || n.contains("protonvpn")
        || n.contains("mullvad")
}

fn classify_iface_transport(name: &str) -> OsDefaultTransport {
    let n = name.to_ascii_lowercase();
    if windows_default_route_adapter_disqualified(name) || n == "lo" {
        return OsDefaultTransport::None;
    }
    if iface_name_is_wifi(name) {
        OsDefaultTransport::Wifi
    } else if iface_name_is_cellular(name) {
        OsDefaultTransport::Cellular
    } else {
        OsDefaultTransport::Ethernet
    }
}

fn default_route_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(ROUTE_PROBE_ADDR).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// Authoritative Windows connectivity snapshot for `LocalNetworkProfile`.
pub fn probe_connectivity_truth() -> OsNetworkSnapshot {
    let ifaces = if_addrs::get_if_addrs().unwrap_or_default();
    let default_ip = default_route_local_ip();
    let default_iface = default_ip.and_then(|ip| {
        if ip.is_loopback() {
            return None;
        }
        ifaces
            .iter()
            .find(|i| {
                !i.is_loopback()
                    && i.ip() == ip
                    && !windows_default_route_adapter_disqualified(&i.name)
            })
            .map(|i| i.name.clone())
    });
    let default_transport = default_iface
        .as_deref()
        .map(classify_iface_transport)
        .unwrap_or(OsDefaultTransport::None);
    let wifi_up = windows_wifi_link_up(&ifaces, default_ip, default_transport);
    let routed = default_transport != OsDefaultTransport::None;
    OsNetworkSnapshot {
        default_transport,
        internet_validated: routed,
        has_internet: routed,
        wifi_link_up: wifi_up,
        default_route_iface: default_iface,
    }
}

/// Wi‑Fi link without counting stale Wi‑Fi IPv4 after default route moved to cellular.
fn windows_wifi_link_up(
    ifaces: &[if_addrs::Interface],
    default_ip: Option<IpAddr>,
    default_transport: OsDefaultTransport,
) -> bool {
    if default_transport == OsDefaultTransport::Wifi {
        return true;
    }
    if matches!(
        default_transport,
        OsDefaultTransport::Cellular | OsDefaultTransport::Ethernet
    ) {
        return false;
    }
    let Some(dip) = default_ip else {
        // No UDP route — do not treat stale Wi‑Fi from if_addrs as linked.
        return false;
    };
    ifaces.iter().any(|i| {
        !i.is_loopback()
            && i.ip().is_ipv4()
            && iface_name_is_wifi(&i.name)
            && !windows_default_route_adapter_disqualified(&i.name)
            && i.ip() == dip
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_names_classify() {
        assert_eq!(classify_iface_transport("Wi-Fi"), OsDefaultTransport::Wifi);
        assert_eq!(
            classify_iface_transport("Wi-Fi 2"),
            OsDefaultTransport::Wifi
        );
        assert_eq!(
            classify_iface_transport("Cellular"),
            OsDefaultTransport::Cellular
        );
        assert_eq!(
            classify_iface_transport("Ethernet"),
            OsDefaultTransport::Ethernet
        );
        assert_eq!(
            classify_iface_transport("Loopback Pseudo-Interface 1"),
            OsDefaultTransport::None
        );
    }

    #[test]
    fn probe_reports_a_route_iface_only_with_a_transport() {
        let snap = probe_connectivity_truth();
        assert_eq!(
            snap.default_route_iface.is_some(),
            snap.default_transport != OsDefaultTransport::None
        );
    }

    #[test]
    fn loopback_adapter_classified_none() {
        assert_eq!(
            classify_iface_transport("Loopback Pseudo-Interface 1"),
            OsDefaultTransport::None
        );
    }

    #[test]
    fn vpn_adapters_not_default_transport() {
        assert_eq!(
            classify_iface_transport("NordLynx Tunnel"),
            OsDefaultTransport::None
        );
        assert_eq!(
            classify_iface_transport("WireGuard Tunnel"),
            OsDefaultTransport::None
        );
        assert!(windows_default_route_adapter_disqualified(
            "TAP-Windows Adapter V9 for OpenVPN Connect"
        ));
        assert!(!windows_default_route_adapter_disqualified("Ethernet"));
    }

    #[test]
    fn route_probe_ip_loopback_has_no_default_iface() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ip.is_loopback());
    }

    #[test]
    fn wifi_link_suppressed_when_default_is_cellular() {
        assert!(!windows_wifi_link_up(
            &[],
            Some("192.0.2.1".parse().unwrap()),
            OsDefaultTransport::Cellular,
        ));
        assert!(!windows_wifi_link_up(
            &[],
            None,
            OsDefaultTransport::Ethernet,
        ));
        assert!(windows_wifi_link_up(
            &[],
            None,
            OsDefaultTransport::Wifi,
        ));
    }

    #[test]
    fn wifi_link_not_inferred_without_udp_default_route() {
        use if_addrs::IfAddr;
        let stale_wifi = if_addrs::Interface {
            name: "Wi-Fi".into(),
            addr: IfAddr::V4(if_addrs::Ifv4Addr {
                ip: "192.168.1.5".parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
                prefixlen: 24,
                broadcast: None,
            }),
            index: None,
            oper_status: if_addrs::IfOperStatus::Up,
        };
        assert!(!windows_wifi_link_up(
            &[stale_wifi],
            None,
            OsDefaultTransport::None,
        ));
    }

    #[test]
    fn virtual_and_hyper_v_adapters_disqualified() {
        assert!(windows_default_route_adapter_disqualified(
            "vEthernet (Default Switch)"
        ));
        assert!(windows_default_route_adapter_disqualified(
            "Microsoft Wi-Fi Direct Virtual Adapter"
        ));
        assert!(windows_default_route_adapter_disqualified(
            "OpenVPN Data Channel Offload"
        ));
        assert!(!windows_default_route_adapter_disqualified("Wi-Fi"));
    }

    #[test]
    fn classify_oversized_adapter_name_does_not_panic() {
        let huge = format!("Wi-Fi{}", "x".repeat(16_384));
        let _ = classify_iface_transport(&huge);
        assert!(!windows_default_route_adapter_disqualified(&huge));
    }
}
