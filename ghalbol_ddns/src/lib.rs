//! GoDaddy dynamic DNS for Ghal Bol home servers (coord, delivery, …).
//!
//! Uses GoDaddy REST **v3** with a Personal Access Token (PAT).
//! Runs in-process so DNS stays in sync with the server — no separate systemd timer.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use fs4::fs_std::FileExt;
use tokio::sync::Notify;
use tracing::{info, warn};

const GODADDY_V3_BASE: &str = "https://api.godaddy.com/v3";

const MAX_CREDENTIALS_FILE_BYTES: usize = 16 * 1024;
const MAX_CREDENTIALS_LINES: usize = 128;
const MAX_PAT_LEN: usize = 4096;
const MAX_POLL_SECS: u64 = 86_400;
const MAX_TTL: u32 = 604_800;
const MAX_ERROR_RESPONSE_BYTES: usize = 8 * 1024;

/// Parsed GoDaddy DDNS settings (credentials file + optional env overrides).
#[derive(Clone, Debug)]
pub struct DdnsConfig {
    pub pat: String,
    pub domain: String,
    pub host: String,
    pub ttl: u32,
    pub poll_interval: Duration,
    pub state_path: PathBuf,
}

impl DdnsConfig {
    /// Load from `GHALBOL_DDNS_CREDENTIALS` (path to key=value file). Disabled when unset or missing.
    pub fn from_env() -> Option<Self> {
        let creds_path = std::env::var("GHALBOL_DDNS_CREDENTIALS")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        Self::from_credentials_file(&creds_path)
    }

    /// Parse a GoDaddy credentials file (`GODADDY_*` key=value lines).
    pub fn from_credentials_file(path: &str) -> Option<Self> {
        let path = PathBuf::from(path);
        if !path.is_file() {
            warn!(
                path = %path.display(),
                "GHALBOL_DDNS_CREDENTIALS set but file missing — DDNS disabled"
            );
            return None;
        }
        let meta = std::fs::metadata(&path).ok()?;
        if meta.len() > MAX_CREDENTIALS_FILE_BYTES as u64 {
            warn!(
                path = %path.display(),
                bytes = meta.len(),
                "GoDaddy DDNS: credentials file exceeds size limit — DDNS disabled"
            );
            return None;
        }
        let raw = std::fs::read_to_string(&path).ok()?;
        if raw.len() > MAX_CREDENTIALS_FILE_BYTES {
            warn!(
                path = %path.display(),
                "GoDaddy DDNS: credentials file exceeds size limit — DDNS disabled"
            );
            return None;
        }
        let mut vars = std::collections::HashMap::<String, String>::new();
        let mut line_count = 0usize;
        for line in raw.lines() {
            line_count += 1;
            if line_count > MAX_CREDENTIALS_LINES {
                warn!(
                    path = %path.display(),
                    "GoDaddy DDNS: credentials file exceeds line limit — DDNS disabled"
                );
                return None;
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            vars.insert(k.trim().to_string(), v.trim().to_string());
        }
        let get = |key: &str| {
            vars.get(key)
                .cloned()
                .filter(|v| !v.is_empty() && !v.contains("paste_"))
        };
        if get("GODADDY_API_KEY").is_some() || get("GODADDY_API_SECRET").is_some() {
            warn!(
                path = %path.display(),
                "GoDaddy DDNS: v1 API keys (GODADDY_API_KEY/SECRET) are no longer supported — use GODADDY_PAT (v3 Personal Access Token)"
            );
            return None;
        }
        let pat = get("GODADDY_PAT")?;
        if !is_safe_pat(&pat) {
            warn!(
                path = %path.display(),
                "GoDaddy DDNS: PAT has unsafe characters — DDNS disabled"
            );
            return None;
        }
        let domain = get("GODADDY_DOMAIN")?;
        let host = get("GODADDY_HOST")?;
        if !is_dns_name(&domain) || !is_ddns_host(&host) {
            warn!(
                domain,
                host, "GoDaddy DDNS: domain or host is not a DNS name — DDNS disabled"
            );
            return None;
        }
        let ttl = vars
            .get("GODADDY_TTL")
            .and_then(|s| s.parse().ok())
            .unwrap_or(600)
            .clamp(600, MAX_TTL);
        let poll_secs = std::env::var("GHALBOL_DDNS_POLL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300)
            .clamp(60, MAX_POLL_SECS);
        let state_path = std::env::var("GHALBOL_DDNS_STATE_FILE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| default_state_path(&path, &host));
        Some(Self {
            pat,
            domain,
            host,
            ttl,
            poll_interval: Duration::from_secs(poll_secs),
            state_path,
        })
    }

    pub fn fqdn(&self) -> String {
        if self.host == "@" {
            self.domain.clone()
        } else {
            format!("{}.{}", self.host, self.domain)
        }
    }

    fn list_a_records_url(&self) -> String {
        format!(
            "{GODADDY_V3_BASE}/domains/zones/{}/dns-records?type=A&name={}",
            self.domain, self.host
        )
    }

    fn create_record_url(&self) -> String {
        format!(
            "{GODADDY_V3_BASE}/domains/zones/{}/dns-records",
            self.domain
        )
    }

    fn replace_record_url(&self, record_id: &str) -> String {
        format!(
            "{GODADDY_V3_BASE}/domains/zones/{}/dns-records/{record_id}",
            self.domain
        )
    }
}

fn default_state_path(creds_path: &Path, host: &str) -> PathBuf {
    creds_path
        .parent()
        .map(|p| p.join(format!(".godaddy-ddns-{host}.last_ip")))
        .unwrap_or_else(|| PathBuf::from(format!(".godaddy-ddns-{host}.last_ip")))
}

/// One-shot DDNS update (manual / emergency). Returns Ok when A record matches public IPv4.
pub async fn run_ddns_pass(config: &DdnsConfig) -> Result<(), String> {
    let client = http_client()?;
    run_pass(&client, config).await
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        // A redirect must not carry the PAT to another host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}

/// Background task: poll public IPv4 vs GoDaddy A record; update when stale.
pub fn spawn_ddns_task(
    config: DdnsConfig,
    shutdown: std::sync::Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    let fqdn = config.fqdn();
    info!(
        fqdn = %fqdn,
        poll_secs = config.poll_interval.as_secs(),
        "GoDaddy DDNS enabled (in-process, API v3)"
    );
    tokio::spawn(async move {
        let client = match http_client() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "GoDaddy DDNS: failed to build HTTP client");
                return;
            }
        };
        let mut tick = tokio::time::interval(config.poll_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // One waiter for the whole task. Recreating `notified()` each tick misses
        // `notify_waiters` between polls, and a pass must cancel when shutdown fires.
        let shutdown_fut = shutdown.notified();
        tokio::pin!(shutdown_fut);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_fut => {
                    tracing::debug!("GoDaddy DDNS task stopped");
                    break;
                }
                _ = tick.tick() => {
                    let pass = run_pass(&client, &config);
                    tokio::pin!(pass);
                    tokio::select! {
                        biased;
                        _ = &mut shutdown_fut => break,
                        result = &mut pass => {
                            if let Err(e) = result {
                                warn!(error = %e, fqdn = %fqdn, "GoDaddy DDNS pass failed");
                            }
                        }
                    }
                }
            }
        }
    })
}

async fn run_pass(client: &reqwest::Client, config: &DdnsConfig) -> Result<(), String> {
    let current = fetch_public_ipv4(client).await?;
    if !is_publishable_ipv4(&current) {
        return Err("refusing to publish a non-global IPv4 address".into());
    }
    // A failed list is an error. Treating it as "no record" creates a second A.
    let records = list_godaddy_a_records(client, config).await?;
    match plan_a_record_sync(&records, &current) {
        ARecordSync::InSync => {
            write_state(&config.state_path, &current)?;
            Ok(())
        }
        ARecordSync::Create => {
            create_godaddy_a_record(client, config, &current).await?;
            write_state(&config.state_path, &current)?;
            info!(fqdn = %config.fqdn(), new = %current, "GoDaddy DDNS created A record");
            Ok(())
        }
        ARecordSync::Update(ids) => {
            let old = records
                .iter()
                .map(|row| row.data.as_str())
                .collect::<Vec<_>>()
                .join(",");
            for id in &ids {
                if !is_safe_godaddy_record_id(id) {
                    return Err("refusing GoDaddy record id with unsafe characters".into());
                }
                replace_godaddy_a_record(client, config, id, &current).await?;
            }
            write_state(&config.state_path, &current)?;
            info!(
                fqdn = %config.fqdn(),
                old = %old,
                new = %current,
                updated = ids.len(),
                "GoDaddy DDNS updated A record"
            );
            Ok(())
        }
    }
}

/// IPv4 text probes must stay tiny; a hostile endpoint must not force a multi‑MiB buffer.
const MAX_PUBLIC_IP_BODY_BYTES: usize = 64;

const PUBLIC_IP_PROBE_URLS: &[&str] = &["https://api.ipify.org", "https://ifconfig.me/ip"];

fn is_allowed_public_ip_probe_url(url: &str) -> bool {
    PUBLIC_IP_PROBE_URLS.contains(&url)
}

/// Parse a public-IP probe HTTP body (trimmed); rejects oversize and non-global IPv4.
fn parse_public_ip_probe_body(bytes: &[u8]) -> Option<String> {
    if bytes.len() > MAX_PUBLIC_IP_BODY_BYTES {
        return None;
    }
    let ip = String::from_utf8_lossy(bytes).trim().to_string();
    if is_publishable_ipv4(&ip) {
        Some(ip)
    } else {
        None
    }
}

async fn fetch_public_ipv4(client: &reqwest::Client) -> Result<String, String> {
    for url in PUBLIC_IP_PROBE_URLS {
        if !is_allowed_public_ip_probe_url(url) {
            continue;
        }
        match client.get(*url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if resp
                    .content_length()
                    .is_some_and(|n| n > MAX_PUBLIC_IP_BODY_BYTES as u64)
                {
                    warn!(url, "public IP probe Content-Length exceeds size limit");
                    continue;
                }
                let bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(url, error = %e, "public IP probe body error");
                        continue;
                    }
                };
                if let Some(ip) = parse_public_ip_probe_body(&bytes) {
                    return Ok(ip);
                }
                if !bytes.is_empty() {
                    let preview = truncate_err(&String::from_utf8_lossy(&bytes));
                    warn!(
                        url,
                        ip = %preview,
                        "public IP probe returned a non-publishable or malformed address"
                    );
                }
            }
            Ok(resp) => {
                warn!(url, status = %resp.status(), "public IP probe failed");
            }
            Err(e) => {
                warn!(url, error = %e, "public IP probe error");
            }
        }
    }
    Err("could not detect public IPv4".into())
}

#[derive(Debug)]
struct GodaddyARecord {
    record_id: String,
    data: String,
}

async fn list_godaddy_a_records(
    client: &reqwest::Client,
    config: &DdnsConfig,
) -> Result<Vec<GodaddyARecord>, String> {
    let url = config.list_a_records_url();
    let resp = client
        .get(&url)
        .header("Authorization", auth_header(config))
        .header("Cache-Control", "no-cache")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("GoDaddy GET {url} {}", resp.status()));
    }
    const MAX_LIST_BODY_BYTES: usize = 256 * 1024;
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_LIST_BODY_BYTES as u64)
    {
        return Err("GoDaddy list Content-Length exceeds size limit".into());
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > MAX_LIST_BODY_BYTES {
        return Err(format!(
            "GoDaddy list body too large ({} bytes)",
            bytes.len()
        ));
    }
    godaddy_a_records_from_list_bytes(&bytes)
}

fn godaddy_a_records_from_list_bytes(bytes: &[u8]) -> Result<Vec<GodaddyARecord>, String> {
    const MAX_LIST_BODY_BYTES: usize = 256 * 1024;
    if bytes.len() > MAX_LIST_BODY_BYTES {
        return Err(format!(
            "GoDaddy list body too large ({} bytes)",
            bytes.len()
        ));
    }
    let body: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let items = godaddy_list_items(&body)
        .cloned()
        .unwrap_or_default();
    let raw_count = items.len();
    let mut out = Vec::new();
    for item in items.into_iter().take(64) {
        let Some(record_id) = item.get("recordId").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(data) = item.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_safe_godaddy_record_id(record_id) || data.len() > 64 {
            continue;
        }
        out.push(GodaddyARecord {
            record_id: record_id.to_string(),
            data: data.to_string(),
        });
    }
    if raw_count > 0 && out.is_empty() {
        return Err("GoDaddy list contained records but none were usable".into());
    }
    Ok(out)
}

fn godaddy_list_items(body: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    if let Some(arr) = body.as_array() {
        return Some(arr);
    }
    body.get("items").and_then(|v| v.as_array())
}

fn is_safe_godaddy_record_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_safe_pat(pat: &str) -> bool {
    !pat.is_empty()
        && pat.len() <= MAX_PAT_LEN
        && pat
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_control() && !b.is_ascii_whitespace())
}

#[derive(Debug, PartialEq, Eq)]
enum ARecordSync {
    InSync,
    Create,
    Update(Vec<String>),
}

fn plan_a_record_sync(records: &[GodaddyARecord], ip: &str) -> ARecordSync {
    if records.is_empty() {
        return ARecordSync::Create;
    }
    let stale: Vec<String> = records
        .iter()
        .filter(|row| row.data != ip)
        .map(|row| row.record_id.clone())
        .collect();
    if stale.is_empty() {
        ARecordSync::InSync
    } else {
        ARecordSync::Update(stale)
    }
}

fn record_body(config: &DdnsConfig, ip: &str) -> serde_json::Value {
    serde_json::json!({
        "name": config.host,
        "type": "A",
        "data": ip,
        "ttl": config.ttl,
    })
}

async fn replace_godaddy_a_record(
    client: &reqwest::Client,
    config: &DdnsConfig,
    record_id: &str,
    ip: &str,
) -> Result<(), String> {
    let url = config.replace_record_url(record_id);
    let resp = client
        .put(&url)
        .header("Authorization", auth_header(config))
        .header("Content-Type", "application/json")
        .json(&record_body(config, ip))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let text = read_limited_error_body(resp).await;
        Err(format!(
            "GoDaddy PUT {url} failed {status}: {}",
            truncate_err(&text)
        ))
    }
}

async fn create_godaddy_a_record(
    client: &reqwest::Client,
    config: &DdnsConfig,
    ip: &str,
) -> Result<(), String> {
    let url = config.create_record_url();
    let resp = client
        .post(&url)
        .header("Authorization", auth_header(config))
        .header("Content-Type", "application/json")
        .json(&record_body(config, ip))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let text = read_limited_error_body(resp).await;
        Err(format!(
            "GoDaddy POST {url} failed {status}: {}",
            truncate_err(&text)
        ))
    }
}

async fn read_limited_error_body(resp: reqwest::Response) -> String {
    match resp.bytes().await {
        Ok(bytes) => {
            let n = bytes.len().min(MAX_ERROR_RESPONSE_BYTES);
            String::from_utf8_lossy(&bytes[..n]).into_owned()
        }
        Err(_) => String::new(),
    }
}

fn truncate_err(text: &str) -> String {
    let t = text.trim();
    let t = if t.len() <= 180 { t } else { &t[..180] };
    t.to_string()
}

fn is_publishable_ipv4(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4
        || parts
            .iter()
            .any(|p| p.is_empty() || (p.len() > 1 && p.starts_with('0')))
    {
        return false;
    }
    !addr.is_private()
        && !addr.is_loopback()
        && !addr.is_unspecified()
        && !addr.is_link_local()
        && !addr.is_multicast()
        && !addr.is_broadcast()
        && addr.octets()[0] != 0
        && !(addr.octets()[0] == 100 && (addr.octets()[1] & 0xc0) == 0x40)
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return false;
    }
    bytes
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

fn is_dns_name(name: &str) -> bool {
    if name.len() > 253 || !name.contains('.') {
        return false;
    }
    name.split('.').all(is_dns_label)
}

fn is_ddns_host(host: &str) -> bool {
    host == "@" || is_dns_label(host)
}

fn auth_header(config: &DdnsConfig) -> String {
    format!("Bearer {}", config.pat)
}

static STATE_IO_CHAIN: OnceLock<Mutex<()>> = OnceLock::new();

struct StateWriteGuard {
    _process: MutexGuard<'static, ()>,
    _lock_file: File,
}

impl StateWriteGuard {
    fn acquire(path: &Path) -> Result<Self, String> {
        let process = STATE_IO_CHAIN
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let lock_path = path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| e.to_string())?;
        lock_file
            .lock_exclusive()
            .map_err(|e| format!("DDNS state flock {lock_path:?}: {e}"))?;
        Ok(Self {
            _process: process,
            _lock_file: lock_file,
        })
    }
}

fn write_state(path: &Path, ip: &str) -> Result<(), String> {
    if !is_publishable_ipv4(ip) {
        return Err("refusing to write non-publishable IPv4 to DDNS state".into());
    }
    let _guard = StateWriteGuard::acquire(path)?;
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        f.write_all(format!("{ip}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "GODADDY_PAT=pat789\nGODADDY_DOMAIN=ghalbol.com\nGODADDY_HOST=delivery\n"
        )
        .unwrap();
        let cfg = DdnsConfig::from_credentials_file(path.to_str().unwrap()).expect("parse");
        assert_eq!(cfg.pat, "pat789");
        assert_eq!(cfg.domain, "ghalbol.com");
        assert_eq!(cfg.host, "delivery");
        assert_eq!(cfg.fqdn(), "delivery.ghalbol.com");
        assert!(
            cfg.state_path
                .to_string_lossy()
                .contains(".godaddy-ddns-delivery.last_ip")
        );
    }

    #[test]
    fn rejects_legacy_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "GODADDY_API_KEY=key123\nGODADDY_API_SECRET=sec456\nGODADDY_DOMAIN=ghalbol.com\nGODADDY_HOST=coord1\n"
        )
        .unwrap();
        assert!(DdnsConfig::from_credentials_file(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn publishable_ipv4_rejects_non_global() {
        assert!(is_publishable_ipv4("1.2.3.4"));
        assert!(is_publishable_ipv4("8.8.8.8"));
        assert!(!is_publishable_ipv4("10.1.2.3"));
        assert!(!is_publishable_ipv4("127.0.0.1"));
        assert!(!is_publishable_ipv4("100.64.0.1"));
        assert!(!is_publishable_ipv4("169.254.1.1"));
        assert!(!is_publishable_ipv4("224.0.0.1"));
        assert!(!is_publishable_ipv4("0.0.0.0"));
        assert!(!is_publishable_ipv4("255.255.255.255"));
        assert!(!is_publishable_ipv4("not-an-ip"));
        assert!(!is_publishable_ipv4("1.02.3.4"));
    }

    #[test]
    fn a_record_plan_updates_only_stale_rows() {
        let records = vec![
            GodaddyARecord {
                record_id: "a".into(),
                data: "1.1.1.1".into(),
            },
            GodaddyARecord {
                record_id: "b".into(),
                data: "8.8.8.8".into(),
            },
        ];
        assert_eq!(
            plan_a_record_sync(&records, "1.1.1.1"),
            ARecordSync::Update(vec!["b".into()])
        );
        assert_eq!(
            plan_a_record_sync(&records[..1], "1.1.1.1"),
            ARecordSync::InSync
        );
        assert_eq!(plan_a_record_sync(&[], "1.1.1.1"), ARecordSync::Create);
    }

    #[test]
    fn public_ip_body_size_gate() {
        assert!(MAX_PUBLIC_IP_BODY_BYTES >= "255.255.255.255".len());
        assert!(MAX_PUBLIC_IP_BODY_BYTES < 1024);
    }

    #[test]
    fn parse_public_ip_probe_body_accepts_trimmed_global_ipv4() {
        assert_eq!(
            parse_public_ip_probe_body(b"  93.184.216.34\n"),
            Some("93.184.216.34".into())
        );
    }

    #[test]
    fn parse_public_ip_probe_body_rejects_malformed_and_non_global() {
        assert_eq!(parse_public_ip_probe_body(b""), None);
        assert_eq!(parse_public_ip_probe_body(b"<html>1.2.3.4</html>"), None);
        assert_eq!(parse_public_ip_probe_body(b"1.2.3.4.5"), None);
        assert_eq!(parse_public_ip_probe_body(b"10.0.0.1"), None);
        assert_eq!(
            parse_public_ip_probe_body(&vec![b'x'; MAX_PUBLIC_IP_BODY_BYTES + 1]),
            None
        );
    }

    #[test]
    fn public_ip_probe_url_allowlist_is_fixed() {
        assert!(is_allowed_public_ip_probe_url("https://api.ipify.org"));
        assert!(!is_allowed_public_ip_probe_url("https://evil.test/ip"));
    }

    #[test]
    fn rejects_pat_with_whitespace_or_control_chars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "GODADDY_PAT=pat with space\nGODADDY_DOMAIN=ghalbol.com\nGODADDY_HOST=delivery\n"
        )
        .unwrap();
        assert!(DdnsConfig::from_credentials_file(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn rejects_oversized_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        let pad = "x".repeat(MAX_CREDENTIALS_FILE_BYTES + 1);
        writeln!(f, "{pad}").unwrap();
        assert!(DdnsConfig::from_credentials_file(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn rejects_credentials_too_many_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        for _ in 0..=MAX_CREDENTIALS_LINES {
            writeln!(f, "# comment").unwrap();
        }
        writeln!(
            f,
            "GODADDY_PAT=pat789\nGODADDY_DOMAIN=ghalbol.com\nGODADDY_HOST=delivery\n"
        )
        .unwrap();
        assert!(DdnsConfig::from_credentials_file(path.to_str().unwrap()).is_none());
    }

    #[test]
    fn godaddy_list_rejects_when_every_row_is_unusable() {
        assert!(godaddy_a_records_from_list_bytes(
            br#"{"items":[{"recordId":"../evil","data":"1.2.3.4"}]}"#
        )
        .is_err());
    }

    #[test]
    fn godaddy_list_parses_root_array_response() {
        let rows = godaddy_a_records_from_list_bytes(
            br#"[{"recordId":"root-array","data":"8.8.8.8"}]"#,
        )
        .expect("parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_id, "root-array");
    }

    #[test]
    fn write_state_rejects_non_publishable_ip() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        assert!(write_state(&state, "10.0.0.1").is_err());
        assert!(!state.is_file());
    }

    #[test]
    fn safe_pat_rejects_header_injection_chars() {
        assert!(is_safe_pat("valid-token_9"));
        assert!(!is_safe_pat(""));
        assert!(!is_safe_pat("tok en"));
        assert!(!is_safe_pat("tok\nen"));
    }

    #[test]
    fn godaddy_list_json_rejects_malformed_and_unsafe_record_ids() {
        assert!(godaddy_a_records_from_list_bytes(b"not-json").is_err());
        assert!(godaddy_a_records_from_list_bytes(b"{\"items\":[]}").unwrap().is_empty());
        let rows = godaddy_a_records_from_list_bytes(
            br#"{"items":[{"recordId":"ok-id_1","data":"8.8.8.8"}]}"#,
        )
        .expect("parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_id, "ok-id_1");
        let skipped = godaddy_a_records_from_list_bytes(
            br#"{"items":[{"recordId":"../evil","data":"1.2.3.4"},{"recordId":"good","data":"1.2.3.4"}]}"#,
        )
        .expect("parse");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].record_id, "good");
    }

    #[test]
    fn safe_godaddy_record_id_rejects_path_chars() {
        assert!(is_safe_godaddy_record_id("abc-123_9"));
        assert!(!is_safe_godaddy_record_id("../zone"));
        assert!(!is_safe_godaddy_record_id(""));
    }

    #[test]
    fn rejects_domain_that_rewrites_the_api_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "GODADDY_PAT=pat789\nGODADDY_DOMAIN=ghalbol.com/other\nGODADDY_HOST=coord\n"
        )
        .unwrap();
        assert!(DdnsConfig::from_credentials_file(path.to_str().unwrap()).is_none());
    }

    #[tokio::test]
    async fn ddns_task_stops_when_shutdown_is_signaled() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DdnsConfig {
            pat: "pat".into(),
            domain: "example.com".into(),
            host: "coord".into(),
            ttl: 600,
            poll_interval: Duration::from_secs(3600),
            state_path: dir.path().join("state"),
        };
        let shutdown = std::sync::Arc::new(Notify::new());
        let handle = spawn_ddns_task(cfg, std::sync::Arc::clone(&shutdown));
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.notify_waiters();
        let joined = tokio::time::timeout(Duration::from_secs(3), handle).await;
        assert!(joined.is_ok(), "DDNS task did not stop on shutdown");
        assert!(joined.unwrap().is_ok());
    }
}
