//! Coord URL configuration, status queries, and prefs persistence.

use super::presence::schedule_check_relay_presence_once;
use super::register::schedule_register_presence;
use super::state::*;
use std::sync::atomic::Ordering;

pub(super) fn normalize_coord_url(url: &str) -> Option<String> {
    let t = url.trim().trim_end_matches('/');
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

pub(super) fn is_coord_url_delimiter(c: char) -> bool {
    c == ',' || c == ';' || c.is_ascii_whitespace()
}

/// Parse one URL, JSON array, or a delimiter-separated list.
///
/// Delimiters may be comma, semicolon, tab, space, newline, or any mix.
pub fn parse_coord_urls(input: &str) -> Vec<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed) {
            return arr
                .into_iter()
                .filter_map(|s| normalize_coord_url(&s))
                .take(MAX_COORD_SERVERS)
                .collect();
        }
    }
    trimmed
        .split(is_coord_url_delimiter)
        .filter_map(|s| normalize_coord_url(s))
        .take(MAX_COORD_SERVERS)
        .collect()
}

/// Parse coord URL(s) from `p2p_start` JSON.
pub fn coord_urls_from_json_value(v: &serde_json::Value) -> Vec<String> {
    for key in ["base_urls", "coord_base_urls"] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            let urls: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str())
                .filter_map(|s| normalize_coord_url(s))
                .take(MAX_COORD_SERVERS)
                .collect();
            if !urls.is_empty() {
                return urls;
            }
        }
    }
    for key in ["base_url", "coord_base_url", "url"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            if let Some(u) = normalize_coord_url(s) {
                return vec![u];
            }
        }
    }
    Vec::new()
}

/// Configured coord/relay server base URLs (register on all; lookup in order).
pub fn coord_base_urls() -> Vec<String> {
    coord_globals()
        .base_urls
        .lock()
        .ok()
        .map(|v| v.clone())
        .unwrap_or_default()
}

/// Legacy no-op — relay reservations removed with libp2p.
pub fn coord_note_relay_reservation(_relay_peer_id: String) {}

/// Coord URL is set — WAN peer discovery requires coord/relay lookup (TRANSPORT.md).
/// mDNS/LAN still works without coord; coord HTTP retries continue in the background.
pub fn wan_discovery_via_coord_only() -> bool {
    coord_is_configured()
}
pub fn fetch_all_ghalbol_relays(_remap: bool) -> Vec<(String, Vec<String>)> {
    Vec::new()
}

/// Delete legacy `ghalbol_relay*.json` files from the identity data dir (`:p2p` start).
pub fn purge_legacy_relay_cache_files(data_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let legacy = name.as_ref() == "ghalbol_relay.json"
            || (name.starts_with("ghalbol_relay_") && name.ends_with(".json"));
        if legacy {
            if std::fs::remove_file(entry.path()).is_ok() {
                crate::flow_log::info("relay", format!("purged legacy relay cache {name}"));
            }
        }
    }
}

/// Relay TCP failed — purge any leftover legacy cache files in `data_dir`.
pub fn invalidate_cached_ghalbol_relay(data_dir: Option<&std::path::Path>) {
    if let Some(dir) = data_dir {
        purge_legacy_relay_cache_files(dir);
    }
}

/// True when at least one coordination server URL was configured.
pub fn coord_is_configured() -> bool {
    !coord_base_urls().is_empty()
}

/// Insecure TLS flag for the configured coord URL list (always false for all-HTTPS).
pub fn coord_insecure_tls() -> bool {
    coord_globals().insecure_tls.load(Ordering::Relaxed)
}

/// True after a successful `POST /v1/peers/register` for this session.
pub fn coord_is_registered() -> bool {
    COORD_REGISTERED.load(Ordering::Relaxed)
}

/// Recent successful coord register, heartbeat, or self-lookup (internet likely up).
pub fn coord_link_recently_ok() -> bool {
    if !coord_is_configured() {
        return true;
    }
    if !COORD_REGISTERED.load(Ordering::Relaxed) {
        return false;
    }
    let last = COORD_LAST_OK_MS.load(Ordering::Relaxed);
    last > 0 && unix_ms_now().saturating_sub(last) < PRESENCE_STALE_MS
}

/// Coord URL is set but coord HTTP transport has not succeeded recently — LAN/mDNS still works.
/// Self not yet on coord (`awaiting_coord_mirror`) is **not** transport degradation when HTTP
/// recently returned 200/404 (TRANSPORT.md § WAN phases — coord HTTP flap recovery).
pub fn coord_http_degraded() -> bool {
    if !coord_is_configured() {
        return false;
    }
    // One transient mobile/coord HTTP flake must not flip WAN to degraded for minutes.
    if COORD_CONSEC_FAILS.load(Ordering::Relaxed) >= 2 {
        return true;
    }
    let last = COORD_LAST_OK_MS.load(Ordering::Relaxed);
    last == 0 || unix_ms_now().saturating_sub(last) >= PRESENCE_STALE_MS
}

pub(super) fn coord_lookup_err_means_http_reachable(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("404")
        || e.contains("peer_not_on")
        || e.contains("not registered")
        || e.contains("no dialable endpoints")
}

/// Record a coord HTTP transport failure (lookup/register/heartbeat) — flips degraded quickly.
pub(crate) fn note_coord_transport_failure() {
    COORD_CONSEC_FAILS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_coord_transport_ok() {
    COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(unix_ms_now(), Ordering::Relaxed);
}
/// Single-server helper (integration tests + legacy callers).
pub fn set_coord_base_url(url: &str, insecure_tls: bool) {
    set_coord_base_urls(&[url.to_string()], insecure_tls);
}

/// HTTPS coord URLs always use verified TLS in Rust — stale `insecure_tls` prefs from self-signed
/// dev must not stick after switching to Let's Encrypt (AGENTS.md: product logic in `ghalbol`).
pub(super) fn resolve_coord_insecure_tls(urls: &[String], requested: bool) -> bool {
    if urls.is_empty() {
        return false;
    }
    if urls
        .iter()
        .all(|u| u.trim().to_ascii_lowercase().starts_with("https://"))
    {
        return false;
    }
    requested
}

pub fn set_coord_base_urls(urls: &[String], insecure_tls: bool) {
    let insecure_tls = resolve_coord_insecure_tls(urls, insecure_tls);
    let urls: Vec<String> = urls
        .iter()
        .filter_map(|u| normalize_coord_url(u))
        .take(MAX_COORD_SERVERS)
        .collect();
    let g = coord_globals();
    let unchanged = g.base_urls.lock().ok().is_some_and(|cur| *cur == urls)
        && g.insecure_tls.load(Ordering::Relaxed) == insecure_tls;
    if unchanged {
        // `p2p_start already_running` and hub resume call this every session — do not wipe
        // coord presence or force a WAN rediscovery gap when URLs are unchanged.
        if !COORD_REGISTERED.load(Ordering::Relaxed) {
            schedule_check_relay_presence_once();
        }
        return;
    }
    if let Ok(mut u) = g.base_urls.lock() {
        *u = urls.clone();
    }
    if let Ok(mut r) = g.registered_on.lock() {
        r.clear();
    }
    g.insecure_tls.store(insecure_tls, Ordering::Relaxed);
    COORD_REGISTERED.store(false, Ordering::Relaxed);
    COORD_LAST_OK_MS.store(0, Ordering::Relaxed);
    crate::flow_log::info(
        "coord",
        format!("base_urls set ({} server(s)): {urls:?}", urls.len()),
    );
    schedule_register_presence();
}
/// Legacy single-URL FFI/daemon response shape.
pub fn coord_set_base_url_json(url: &str, insecure_tls: bool) -> serde_json::Value {
    coord_set_base_urls_json(&[url.to_string()], insecure_tls)
}

/// Where coord URL prefs are persisted — Android path is unchanged (always release namespace).
pub(super) fn coord_prefs_storage_config() -> crate::storage::StorageConfig {
    #[cfg(target_os = "android")]
    {
        crate::app_paths::storage_config_for_namespace(crate::ANDROID_LIBRARY_NAMESPACE)
    }
    #[cfg(not(target_os = "android"))]
    {
        let ns = crate::dm_event_handler::active_app_namespace()
            .unwrap_or_else(|| crate::ANDROID_LIBRARY_NAMESPACE.to_string());
        crate::app_paths::storage_config_for_namespace(&ns)
    }
}

pub fn coord_set_base_urls_json(urls: &[String], insecure_tls: bool) -> serde_json::Value {
    if urls.is_empty() {
        return serde_json::json!({ "ok": false, "error": "url empty" });
    }
    let insecure_tls = resolve_coord_insecure_tls(urls, insecure_tls);
    set_coord_base_urls(urls, insecure_tls);
    let cfg = coord_prefs_storage_config();
    let joined = urls.join(",");
    if let Err(e) = crate::preferences_v1::coord_settings_set(&cfg, &joined, insecure_tls) {
        return serde_json::json!({ "ok": false, "error": format!("{e}") });
    }
    serde_json::json!({
        "ok": true,
        "base_urls": urls,
    })
}
