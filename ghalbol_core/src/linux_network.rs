//! Linux network truth — Wi‑Fi operstate + default IPv4 route iface.

use crate::p2p::network_transport::{OsDefaultTransport, OsNetworkSnapshot};

fn operstate_is_up(state: &str) -> bool {
    matches!(state.trim(), "up" | "unknown" | "dormant")
}

fn sysfs_has_wifi_iface() -> bool {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("wl"))
}

fn read_any_wifi_oper_up() -> bool {
    if !sysfs_has_wifi_iface() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return false;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("wl") {
            continue;
        }
        let Ok(state) = std::fs::read_to_string(entry.path().join("operstate")) else {
            continue;
        };
        if operstate_is_up(&state) {
            return true;
        }
    }
    false
}

/// Reject path-climbing / oversized iface tokens from `/proc/net/route`.
fn iface_name_safe(name: &str) -> bool {
    let t = name.trim();
    !t.is_empty()
        && t.len() <= 64
        && !t.contains("..")
        && !t.contains('/')
        && !t.contains('\\')
        && !t.contains('\0')
        && t
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'@'))
}

fn iface_oper_up(name: &str) -> bool {
    if !iface_name_safe(name) {
        return false;
    }
    let path = format!("/sys/class/net/{name}/operstate");
    let Ok(state) = std::fs::read_to_string(path) else {
        return true;
    };
    operstate_is_up(&state)
}

fn iface_name_is_wifi(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("wl") || n.contains("wlan") || n.contains("wifi")
}

fn iface_name_is_cellular(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("wwan") || n.contains("rmnet") || n.contains("pdp")
}

/// Virtual / bridge ifaces must not win default-route truth when a physical path exists.
fn linux_default_route_iface_disqualified(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo"
        || n.starts_with("docker")
        || n.starts_with("veth")
        || n.starts_with("br-")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("wg")
        || n.starts_with("virbr")
        || n.starts_with("zt")
        || n.starts_with("tailscale")
        || n == "vethernet"
        || n.starts_with("ppp")
        || n.starts_with("cni")
        || n.starts_with("flannel")
        || n.contains("nordlynx")
        || n.contains("vpn")
}

/// Lower rank wins when two default routes share the same metric (Wi‑Fi before Ethernet before cellular).
fn default_route_candidate_rank(name: &str) -> u8 {
    if iface_name_is_wifi(name) {
        0
    } else if iface_name_is_cellular(name) {
        2
    } else {
        1
    }
}

fn default_route_candidate_better(
    metric: u32,
    iface: &str,
    best_metric: u32,
    best_iface: &str,
) -> bool {
    if metric != best_metric {
        return metric < best_metric;
    }
    default_route_candidate_rank(iface) < default_route_candidate_rank(best_iface)
}

/// Extract iface + metric from one `/proc/net/route` row (never panics on short/malformed rows).
fn linux_proc_route_v4_default_fields<'a>(cols: &'a [&str]) -> Option<(&'a str, u32)> {
    if cols.len() < 8 {
        return None;
    }
    let dest = cols.get(1)?;
    if *dest != "00000000" {
        return None;
    }
    let iface = cols.get(0)?.trim();
    if iface.is_empty() {
        return None;
    }
    let metric = cols.get(6)?.parse::<u32>().unwrap_or(u32::MAX);
    Some((iface, metric))
}

/// Parse `/proc/net/route` for the default IPv4 route (destination `00000000`).
pub(crate) fn parse_linux_default_ipv4_route_iface(route_table: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in route_table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let Some((iface, metric)) = linux_proc_route_v4_default_fields(&cols) else {
            continue;
        };
        if !iface_name_safe(iface) || linux_default_route_iface_disqualified(iface) {
            continue;
        }
        let take = match &best {
            None => true,
            Some((m, prev)) => default_route_candidate_better(metric, iface, *m, prev),
        };
        if take {
            best = Some((metric, iface.to_string()));
        }
    }
    best.map(|(_, iface)| iface)
}

fn linux_default_ipv4_route_iface() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_linux_default_ipv4_route_iface(&raw)
}

fn linux_snapshot_from(wifi_up: bool, default_iface: Option<String>) -> OsNetworkSnapshot {
    let default_transport = default_iface
        .as_deref()
        .map(classify_iface_transport)
        .unwrap_or(OsDefaultTransport::None);
    let has_default_route = default_transport != OsDefaultTransport::None;
    let route_oper_up = default_iface
        .as_deref()
        .map(iface_oper_up)
        .unwrap_or(false);
    let routed_live = has_default_route && route_oper_up;
    OsNetworkSnapshot {
        default_transport,
        internet_validated: routed_live,
        has_internet: routed_live,
        wifi_link_up: wifi_up,
        default_route_iface: default_iface,
    }
}

/// Authoritative Linux connectivity snapshot for `LocalNetworkProfile`.
pub fn probe_connectivity_truth() -> OsNetworkSnapshot {
    let wifi_up = read_any_wifi_oper_up();
    let default_iface = linux_default_ipv4_route_iface();
    linux_snapshot_from(wifi_up, default_iface)
}

fn classify_iface_transport(name: &str) -> OsDefaultTransport {
    if linux_default_route_iface_disqualified(name) || name == "lo" {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operstate_up_values() {
        assert!(operstate_is_up("up"));
        assert!(operstate_is_up(" unknown \n"));
        assert!(operstate_is_up("dormant"));
        assert!(!operstate_is_up("down"));
        assert!(!operstate_is_up(""));
    }

    #[test]
    fn iface_names_classify() {
        assert_eq!(
            classify_iface_transport("wlan0"),
            OsDefaultTransport::Wifi
        );
        assert_eq!(
            classify_iface_transport("wwan0"),
            OsDefaultTransport::Cellular
        );
        assert_eq!(
            classify_iface_transport("eth0"),
            OsDefaultTransport::Ethernet
        );
        assert_eq!(classify_iface_transport("lo"), OsDefaultTransport::None);
        assert!(iface_name_is_wifi("wlan0"));
        assert!(iface_name_is_wifi("wlp2s0"));
        assert!(iface_name_is_wifi("WiFi"));
        assert!(!iface_name_is_wifi("eth0"));
        assert!(iface_name_is_cellular("wwan0"));
        assert!(iface_name_is_cellular("rmnet_data0"));
        assert!(!iface_name_is_cellular("wlan0"));
        assert_eq!(classify_iface_transport("wlan0"), OsDefaultTransport::Wifi);
        assert_eq!(
            classify_iface_transport("rmnet0"),
            OsDefaultTransport::Cellular
        );
        assert_eq!(classify_iface_transport("eth0"), OsDefaultTransport::Ethernet);
        assert_eq!(classify_iface_transport("lo"), OsDefaultTransport::None);
        assert_eq!(
            classify_iface_transport("docker0"),
            OsDefaultTransport::None
        );
    }

    #[test]
    fn default_route_skips_loopback_and_docker() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
docker0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("eth0".into())
        );
    }

    #[test]
    fn default_route_skips_path_climb_iface_names() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
../etc\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0
evil/name\t00000000\t0101A8C0\t0003\t0\t0\t60\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert!(!iface_name_safe("../etc"));
        assert!(!iface_name_safe("evil/name"));
        assert!(iface_name_safe("wlan0"));
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0".into())
        );
    }

    #[test]
    fn default_route_picks_lowest_metric_physical() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
tun0\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0".into())
        );
    }

    #[test]
    fn disqualified_ifaces() {
        assert!(linux_default_route_iface_disqualified("lo"));
        assert!(linux_default_route_iface_disqualified("docker0"));
        assert!(linux_default_route_iface_disqualified("br-1234"));
        assert!(linux_default_route_iface_disqualified("tun0"));
        assert!(linux_default_route_iface_disqualified("ppp0"));
        assert!(linux_default_route_iface_disqualified("nordvpn0"));
        assert!(!linux_default_route_iface_disqualified("eth0"));
        assert!(!linux_default_route_iface_disqualified("wlan0"));
    }

    #[test]
    fn no_default_route_not_has_internet() {
        let snap = linux_snapshot_from(false, None);
        assert_eq!(snap.default_transport, OsDefaultTransport::None);
        assert!(!snap.has_internet);
        assert!(!snap.internet_validated);
        assert!(!snap.wifi_link_up);
    }

    #[test]
    fn vpn_default_route_skipped_for_physical() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
nordvpn0\t00000000\t0100000A\t0003\t0\t0\t10\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0".into())
        );
    }

    #[test]
    fn default_route_only_vpn_yields_no_iface() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wg0-client\t00000000\t0100000A\t0003\t0\t0\t10\t00000000\t0\t0\t0
";
        assert_eq!(parse_linux_default_ipv4_route_iface(SAMPLE), None);
        let snap = linux_snapshot_from(false, None);
        assert!(!snap.has_internet);
    }

    #[test]
    fn default_route_bad_metric_treated_as_max() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\tnot-a-number\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0".into())
        );
    }

    #[test]
    fn iface_name_safe_rejects_oversized_and_empty() {
        assert!(!iface_name_safe(""));
        assert!(!iface_name_safe("   "));
        assert!(iface_name_safe("wlan0"));
        assert!(iface_name_safe("wlan0@wlp2s0"));
        assert!(!iface_name_safe(&"a".repeat(65)));
    }

    #[test]
    fn default_route_equal_metric_prefers_wifi_over_cellular() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
rmnet_data0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0".into())
        );
    }

    #[test]
    fn default_route_skips_nordlynx_tunnel() {
        assert!(linux_default_route_iface_disqualified("nordlynx0"));
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
nordlynx0\t00000000\t0100000A\t0003\t0\t0\t5\t00000000\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("eth0".into())
        );
    }

    #[test]
    fn default_route_parse_survives_malformed_rows() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
garbage
eth0\t00000000
\t00000000\t0\t0\t0\t0\t0\t0
eth0\t00000000\t0101A8C0\t0003\t0\t0\t10\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("eth0".into())
        );
        assert_eq!(linux_proc_route_v4_default_fields(&["x"]), None);
        assert_eq!(
            linux_proc_route_v4_default_fields(&[
                "wlan0", "00000000", "0", "0", "0", "0", "xy", "0"
            ]),
            Some(("wlan0", u32::MAX))
        );
    }

    #[test]
    fn default_route_netdev_at_suffix() {
        const SAMPLE: &str = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0@wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_default_ipv4_route_iface(SAMPLE),
            Some("wlan0@wlp2s0".into())
        );
    }

    #[test]
    fn default_route_tailscale_variant_disqualified() {
        assert!(linux_default_route_iface_disqualified("tailscale99"));
    }
}
