//! TCP dial order for coord HTTPS / bridge WSS.
//!
//! Optional `GHALBOL_COORD_DIAL`, then DNS (AAAA before A). No loopback inventing —
//! a blackholed public IPv4 must not block IPv6 that already works.

use std::net::{SocketAddr, ToSocketAddrs};

/// `(host, port)` from `https://host:port` / `http://host:port`.
const MAX_COORD_AUTHORITY_CHARS: usize = 512;
/// Bound DNS / override expansion — a pathological resolver must not create a dial storm.
const MAX_COORD_DIAL_TARGETS: usize = 16;

pub fn parse_coord_authority(base_url: &str) -> Result<(String, u16), String> {
    let t = base_url.trim().trim_end_matches('/');
    if t.len() > 2_048 {
        return Err("coord url too long".into());
    }
    let rest = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .ok_or_else(|| format!("coord url must be http(s):// (got {t})"))?;
    let authority = rest.split('/').next().unwrap_or("").trim();
    if authority.is_empty() {
        return Err("coord url missing host".into());
    }
    if authority.contains('@') {
        return Err("coord url must not include userinfo".into());
    }
    if authority.len() > MAX_COORD_AUTHORITY_CHARS {
        return Err("coord authority too long".into());
    }
    let tls = t.starts_with("https://");
    let (host, port) = if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| format!("invalid IPv6 authority in {authority}"))?;
        let host = authority[1..end].trim();
        if host.is_empty() {
            return Err("coord url missing host".into());
        }
        let port = if let Some(p) = authority[end + 1..].strip_prefix(':') {
            p.parse()
                .map_err(|_| format!("invalid coord port in {authority}"))?
        } else if tls {
            443
        } else {
            80
        };
        (host.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let host = h.trim();
        let port: u16 = p
            .parse()
            .map_err(|_| format!("invalid coord port in {authority}"))?;
        (host.to_string(), port)
    } else {
        (
            authority.to_string(),
            if tls { 443 } else { 80 },
        )
    };
    Ok((host, port))
}

fn push_unique(out: &mut Vec<SocketAddr>, addr: SocketAddr) {
    if out.len() >= MAX_COORD_DIAL_TARGETS {
        return;
    }
    if !out.contains(&addr) {
        out.push(addr);
    }
}

/// Dial targets to try **before** plain system DNS for `host:port`.
///
/// Order: `GHALBOL_COORD_DIAL` (if set), then DNS addresses with IPv6 first.
pub fn coord_dial_overrides(host: &str, port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Ok(raw) = std::env::var("GHALBOL_COORD_DIAL") {
        let d = raw.trim();
        if !d.is_empty() {
            let candidate = if d.contains(':') {
                d.to_string()
            } else {
                format!("{d}:{port}")
            };
            if let Ok(iter) = candidate.to_socket_addrs() {
                for addr in iter {
                    push_unique(&mut out, addr);
                }
            }
        }
    }
    if let Ok(iter) = (host, port).to_socket_addrs() {
        let mut dns: Vec<SocketAddr> = iter.collect();
        dns.sort_by_key(|a| u8::from(a.is_ipv4()));
        for addr in dns {
            push_unique(&mut out, addr);
        }
    }
    out
}

/// All TCP dial strings for bridge WSS: overrides first, then `host:port`.
pub fn coord_dial_tcp_targets(host: &str, port: u16) -> Vec<String> {
    let mut out: Vec<String> = coord_dial_overrides(host, port)
        .into_iter()
        .map(|a| a.to_string())
        .collect();
    let named = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    if out.len() < MAX_COORD_DIAL_TARGETS && !out.iter().any(|c| c == &named) {
        out.push(named);
    }
    out.truncate(MAX_COORD_DIAL_TARGETS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_port() {
        let (h, p) = parse_coord_authority("https://coord1.ghalbol.com:8443").unwrap();
        assert_eq!(h, "coord1.ghalbol.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn dial_targets_include_named_host() {
        let t = coord_dial_tcp_targets("coord1.ghalbol.com", 8443);
        assert!(t.iter().any(|c| c == "coord1.ghalbol.com:8443"));
    }

    #[test]
    fn parse_rejects_userinfo_in_authority() {
        assert!(parse_coord_authority("https://user:pass@coord.example.com:8443").is_err());
    }

    #[test]
    fn parse_ipv6_bracket_authority() {
        let (h, p) = parse_coord_authority("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 8443);
        let (h2, p2) = parse_coord_authority("http://[::1]").unwrap();
        assert_eq!(h2, "::1");
        assert_eq!(p2, 80);
    }

    #[test]
    fn parse_rejects_oversized_authority() {
        let huge = format!("https://{}.example", "a".repeat(MAX_COORD_AUTHORITY_CHARS));
        assert!(parse_coord_authority(&huge).is_err());
        assert!(parse_coord_authority(&format!("https://x/{}", "p".repeat(3000))).is_err());
    }

    #[test]
    fn dial_target_list_is_hard_capped() {
        let mut out = Vec::new();
        for i in 0..(MAX_COORD_DIAL_TARGETS + 20) {
            let addr: SocketAddr = format!("198.51.100.{i}:443")
                .parse()
                .unwrap_or_else(|_| "198.51.100.1:443".parse().unwrap());
            push_unique(&mut out, addr);
        }
        assert_eq!(out.len(), MAX_COORD_DIAL_TARGETS);
        let targets = coord_dial_tcp_targets("example.test", 443);
        assert!(targets.len() <= MAX_COORD_DIAL_TARGETS);
    }
}
