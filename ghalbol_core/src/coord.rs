//! HTTP client for [`ghalbol_coord`](../../ghalbol_coord) coordination API (Tier 1).

use std::net::SocketAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::coord_dial::{coord_dial_overrides, parse_coord_authority};
use crate::coord_register_auth::sign_coord_registration;
use crate::keystore_v1::DecryptedIdentity;
use crate::public_key_util::normalize_contact_identity_wire;

/// Hard cap on coord HTTP response bodies (register/lookup/bridge/pending).
const MAX_COORD_HTTP_BODY_BYTES: usize = 1024 * 1024;
/// Endpoint rows accepted from coord HTTP responses and sent on register (matches runtime snapshot).
const MAX_COORD_PEER_ENDPOINTS: usize = 16;
const MAX_COORD_IP_HINT_CHARS: usize = 64;

/// HTTPS coord bases always verify TLS — mirrors `coord_runtime::resolve_coord_insecure_tls`.
fn coord_effective_insecure_tls(base_url: &str, requested: bool) -> bool {
    let t = base_url.trim();
    if t.is_empty() {
        return false;
    }
    if t.to_ascii_lowercase().starts_with("https://") {
        return false;
    }
    requested
}

fn validate_register_endpoints(endpoints: &[CoordEndpoint]) -> Result<(), String> {
    if endpoints.is_empty() {
        return Err("register endpoints empty".into());
    }
    if endpoints.len() > MAX_COORD_PEER_ENDPOINTS {
        return Err(format!(
            "register endpoints {} exceeds {MAX_COORD_PEER_ENDPOINTS}",
            endpoints.len()
        ));
    }
    Ok(())
}

fn validate_ip_hint(opt: Option<&str>, label: &str) -> Result<(), String> {
    if let Some(s) = opt {
        let t = s.trim();
        if !t.is_empty() && t.len() > MAX_COORD_IP_HINT_CHARS {
            return Err(format!("{label} hint too long"));
        }
    }
    Ok(())
}

fn bound_coord_peer_record(mut record: CoordPeerRecord) -> CoordPeerRecord {
    if record.endpoints.len() > MAX_COORD_PEER_ENDPOINTS {
        record.endpoints.truncate(MAX_COORD_PEER_ENDPOINTS);
    }
    record
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoordPeerRecord {
    pub public_key_hex: String,
    pub endpoints: Vec<CoordEndpoint>,
    #[serde(default)]
    pub transport_capabilities: Vec<String>,
    pub ipv6: Option<String>,
    pub ipv4: Option<String>,
    pub last_heartbeat_unix_ms: i64,
}

/// Remember which TCP dial worked so we do not burn 12s on a dead public hairpin every poll.
#[derive(Clone, Copy, Debug)]
enum DialChoice {
    Override(SocketAddr),
    SystemDns,
}

pub struct CoordHttpClient {
    base: String,
    host: String,
    port: u16,
    insecure_tls: bool,
    preferred: Mutex<Option<DialChoice>>,
}

/// rustls client config trusting the bundled `webpki-roots` store (no OS verifier).
fn webpki_client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn build_http_client(
    host: &str,
    insecure_tls: bool,
    override_addr: Option<SocketAddr>,
) -> Result<reqwest::blocking::Client, String> {
    crate::rustls_init::ensure_rustls_crypto_provider();
    let mut b = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(4))
        .timeout(std::time::Duration::from_secs(25));
    if let Some(addr) = override_addr {
        b = b.resolve(host, addr);
    }
    if insecure_tls {
        b = b.danger_accept_invalid_certs(true);
    } else {
        // Bundled Mozilla roots, same as the delivery WSS client. reqwest's default
        // (`rustls-platform-verifier`) needs a Kotlin class in the APK that the
        // cargo-makepad build does not ship, so every coord HTTPS call failed on
        // Android with ClassNotFoundException.
        b = b.use_preconfigured_tls(webpki_client_config());
    }
    b.build().map_err(|e| e.to_string())
}

impl CoordHttpClient {
    pub fn new(base_url: &str, insecure_tls: bool) -> Result<Self, String> {
        retain_wan_relay_listen_setter_for_linker();
        let base = base_url.trim().trim_end_matches('/').to_string();
        if base.is_empty() {
            return Err("coord base url empty".into());
        }
        let (host, port) = parse_coord_authority(&base)?;
        let insecure_tls = coord_effective_insecure_tls(&base, insecure_tls);
        Ok(Self {
            base,
            host,
            port,
            insecure_tls,
            preferred: Mutex::new(None),
        })
    }

    fn dial_plan(&self) -> Vec<DialChoice> {
        let mut plan = Vec::new();
        if let Ok(g) = self.preferred.lock() {
            if let Some(pref) = *g {
                plan.push(pref);
            }
        }
        for addr in coord_dial_overrides(&self.host, self.port) {
            let choice = DialChoice::Override(addr);
            if !plan.iter().any(|c| matches!(c, DialChoice::Override(a) if *a == addr)) {
                plan.push(choice);
            }
        }
        if !plan.iter().any(|c| matches!(c, DialChoice::SystemDns)) {
            plan.push(DialChoice::SystemDns);
        }
        plan
    }

    fn client_for(&self, choice: DialChoice) -> Result<reqwest::blocking::Client, String> {
        match choice {
            DialChoice::Override(addr) => {
                build_http_client(&self.host, self.insecure_tls, Some(addr))
            }
            DialChoice::SystemDns => build_http_client(&self.host, self.insecure_tls, None),
        }
    }

    fn remember(&self, choice: DialChoice) {
        if let Ok(mut g) = self.preferred.lock() {
            *g = Some(choice);
        }
    }

    /// Try pinned / IPv6-first dials before plain system DNS so a blackholed
    /// public IPv4 cannot stall every bridge pending poll.
    fn send_with_transport_retry(
        &self,
        build: impl Fn(&reqwest::blocking::Client) -> reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::Response, String> {
        let mut last = "coord: no dial candidates".to_string();
        for choice in self.dial_plan() {
            let http = match self.client_for(choice) {
                Ok(c) => c,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match build(&http).send() {
                Ok(resp) => {
                    self.remember(choice);
                    return Ok(resp);
                }
                Err(e) if e.is_connect() || e.is_timeout() || e.is_request() => {
                    std::thread::sleep(std::time::Duration::from_millis(80));
                    match build(&http).send() {
                        Ok(resp) => {
                            self.remember(choice);
                            return Ok(resp);
                        }
                        Err(e2) => last = e2.to_string(),
                    }
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        Err(last)
    }

    fn with_headers(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        builder.header("Accept", "application/json")
    }

    pub fn health(&self) -> Result<bool, String> {
        let url = format!("{}/health", self.base);
        let resp = self.send_with_transport_retry(|http| self.with_headers(http.get(&url)))?;
        if !resp.status().is_success() {
            return Err(format!("health HTTP {}", resp.status()));
        }
        let body = read_coord_http_body(resp)?;
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        Ok(v.get("database") == Some(&serde_json::Value::Bool(true)))
    }

    pub fn register(
        &self,
        ident: &DecryptedIdentity,
        endpoints: &[CoordEndpoint],
        ipv4: Option<&str>,
        ipv6: Option<&str>,
    ) -> Result<CoordPeerRecord, String> {
        validate_register_endpoints(endpoints)?;
        validate_ip_hint(ipv4, "ipv4")?;
        validate_ip_hint(ipv6, "ipv6")?;
        let wire = normalize_contact_identity_wire(&ident.identity_wire())?;
        let ch_url = format!("{}/v1/register/challenge", self.base);
        let ch_resp = self.send_with_transport_retry(|http| {
            self.with_headers(http.post(&ch_url))
                .json(&serde_json::json!({ "public_key_hex": wire }))
        })?;
        let ch_status = ch_resp.status();
        let ch_body = read_coord_http_body(ch_resp)?;
        if !ch_status.is_success() {
            return Err(format!(
                "register challenge HTTP {}: {}",
                ch_status,
                truncate_body(&ch_body)
            ));
        }
        let ch: serde_json::Value = serde_json::from_str(&ch_body).map_err(|e| e.to_string())?;
        let nonce_hex = ch["nonce_hex"].as_str().ok_or("missing nonce_hex")?;
        let nonce = parse_coord_nonce32(nonce_hex)?;

        let sig = sign_coord_registration(ident, &nonce, &wire)?;
        let sig_hex = hex::encode(sig);

        let reg_url = format!("{}/v1/register", self.base);
        let resp = self.send_with_transport_retry(|http| {
            self.with_headers(http.post(&reg_url))
                .json(&serde_json::json!({
                    "public_key_hex": wire,
                    "nonce_hex": nonce_hex,
                    "signature_hex": sig_hex,
                    "endpoints": endpoints,
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "transport_capabilities": ["tcp", "sync-v1"]
                }))
        })?;
        let status = resp.status();
        let body = read_coord_http_body(resp)?;
        if !status.is_success() {
            return Err(format!(
                "register HTTP {}: {}",
                status,
                truncate_body(&body)
            ));
        }
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let peer = v.get("peer").ok_or("register response missing peer")?;
        let record: CoordPeerRecord =
            serde_json::from_value(peer.clone()).map_err(|e| e.to_string())?;
        Ok(bound_coord_peer_record(record))
    }

    pub fn heartbeat(&self, identity_wire: &str) -> Result<CoordPeerRecord, String> {
        let wire = normalize_contact_identity_wire(identity_wire)?;
        let url = format!("{}/v1/heartbeat", self.base);
        let resp = self.send_with_transport_retry(|http| {
            self.with_headers(http.post(&url))
                .json(&serde_json::json!({ "public_key_hex": wire }))
        })?;
        let status = resp.status();
        let body = read_coord_http_body(resp)?;
        if !status.is_success() {
            return Err(format!("heartbeat HTTP {}", status));
        }
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let peer = v.get("peer").ok_or("heartbeat response missing peer")?;
        let record: CoordPeerRecord =
            serde_json::from_value(peer.clone()).map_err(|e| e.to_string())?;
        Ok(bound_coord_peer_record(record))
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let resp =
            self.send_with_transport_retry(|http| self.with_headers(http.post(url)).json(body))?;
        let status = resp.status();
        let body = read_coord_http_body(resp)?;
        if !status.is_success() {
            return Err(format!(
                "POST {} HTTP {}: {}",
                url,
                status,
                truncate_body(&body)
            ));
        }
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }

    pub fn get_json(&self, url: &str) -> Result<serde_json::Value, String> {
        let resp = self.send_with_transport_retry(|http| self.with_headers(http.get(url)))?;
        let status = resp.status();
        let body = read_coord_http_body(resp)?;
        if !status.is_success() {
            return Err(format!(
                "GET {} HTTP {}: {}",
                url,
                status,
                truncate_body(&body)
            ));
        }
        serde_json::from_str(&body).map_err(|e| e.to_string())
    }

    pub fn lookup(&self, identity_wire: &str) -> Result<CoordPeerRecord, String> {
        let pk = normalize_contact_identity_wire(identity_wire)?;
        let encoded = crate::identity::percent_encode_uri_component(&pk);
        let url = format!("{}/v1/peers/{}", self.base, encoded);
        let resp = self.send_with_transport_retry(|http| self.with_headers(http.get(&url)))?;
        let status = resp.status();
        let body = read_coord_http_body(resp)?;
        if !status.is_success() {
            return Err(format!("lookup HTTP {}: {}", status, truncate_body(&body)));
        }
        let record: CoordPeerRecord =
            serde_json::from_str(&body).map_err(|e| {
                format!("lookup JSON parse: {e} (body: {})", truncate_body(&body))
            })?;
        Ok(bound_coord_peer_record(record))
    }
}

fn read_coord_http_body(resp: reqwest::blocking::Response) -> Result<String, String> {
    if let Some(len) = resp.content_length() {
        if len > MAX_COORD_HTTP_BODY_BYTES as u64 {
            return Err(format!(
                "coord HTTP body Content-Length {len} exceeds {MAX_COORD_HTTP_BODY_BYTES}"
            ));
        }
    }
    let bytes = resp.bytes().map_err(|e| e.to_string())?;
    if bytes.len() > MAX_COORD_HTTP_BODY_BYTES {
        return Err(format!(
            "coord HTTP body {} bytes exceeds {MAX_COORD_HTTP_BODY_BYTES}",
            bytes.len()
        ));
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("coord HTTP body utf8: {e}"))
}

fn parse_coord_nonce32(hex_s: &str) -> Result<[u8; 32], String> {
    let t = hex_s.trim();
    if t.len() != 64 {
        return Err("nonce must be 32 bytes hex".into());
    }
    let bytes = hex::decode(t).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "nonce must be 32 bytes hex".to_string())
}

/// Swarm / relay worker should call [`crate::wan_coord::set_local_relay_circuit_listening`].
fn retain_wan_relay_listen_setter_for_linker() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _api: fn(bool) = crate::wan_coord::set_local_relay_circuit_listening;
    });
}

fn truncate_body(body: &str) -> String {
    let t = body.trim();
    if t.chars().count() <= 120 {
        t.to_string()
    } else {
        format!("{}…", t.chars().take(120).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bound_coord_peer_record, coord_effective_insecure_tls, parse_coord_nonce32,
        truncate_body, validate_ip_hint, validate_register_endpoints, CoordEndpoint,
        CoordPeerRecord, MAX_COORD_HTTP_BODY_BYTES, MAX_COORD_PEER_ENDPOINTS,
    };

    #[test]
    fn parse_coord_nonce32_rejects_wrong_length() {
        assert!(parse_coord_nonce32("ab").is_err());
        assert!(parse_coord_nonce32(&"a".repeat(128)).is_err());
        assert!(parse_coord_nonce32(&"g".repeat(64)).is_err());
        assert_eq!(parse_coord_nonce32(&"ab".repeat(32)).unwrap().len(), 32);
    }

    #[test]
    fn coord_http_body_cap_is_one_mib() {
        assert_eq!(MAX_COORD_HTTP_BODY_BYTES, 1024 * 1024);
    }

    #[test]
    fn https_coord_base_disables_insecure_tls_flag() {
        assert!(!coord_effective_insecure_tls("https://coord.ghalbol.com", true));
        assert!(!coord_effective_insecure_tls("HTTPS://10.0.0.1:8443", true));
        assert!(coord_effective_insecure_tls("http://127.0.0.1:8765", true));
        assert!(!coord_effective_insecure_tls("http://127.0.0.1:8765", false));
    }

    #[test]
    fn register_endpoints_rejects_empty_and_oversized() {
        assert!(validate_register_endpoints(&[]).is_err());
        let many: Vec<CoordEndpoint> = (0..=MAX_COORD_PEER_ENDPOINTS)
            .map(|i| CoordEndpoint {
                scheme: "tcp".into(),
                host: format!("203.0.113.{i}"),
                port: 4001,
            })
            .collect();
        assert!(validate_register_endpoints(&many).is_err());
        assert!(validate_register_endpoints(&many[..MAX_COORD_PEER_ENDPOINTS]).is_ok());
    }

    #[test]
    fn ip_hint_length_bounded() {
        assert!(validate_ip_hint(Some(&"203.0.113.1"), "ipv4").is_ok());
        let long = "x".repeat(65);
        assert!(validate_ip_hint(Some(&long), "ipv4").is_err());
    }

    #[test]
    fn lookup_peer_record_endpoints_are_capped() {
        let endpoints: Vec<CoordEndpoint> = (0..32)
            .map(|i| CoordEndpoint {
                scheme: "tcp".into(),
                host: format!("203.0.113.{i}"),
                port: 4001,
            })
            .collect();
        let record = bound_coord_peer_record(CoordPeerRecord {
            public_key_hex: "ab".repeat(32),
            endpoints,
            transport_capabilities: Vec::new(),
            ipv6: None,
            ipv4: None,
            last_heartbeat_unix_ms: 0,
        });
        assert_eq!(record.endpoints.len(), MAX_COORD_PEER_ENDPOINTS);
    }

    #[test]
    fn truncate_body_never_panics_on_utf8() {
        let s = "é".repeat(200);
        let out = truncate_body(&s);
        assert!(out.chars().count() <= 121);
    }
}
