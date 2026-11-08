//! App-level preferences (non-secret) stored next to the keystore under the same [`StorageConfig`].
//!
//! v1 file: **`{namespace_data_dir}/preferences_v1.json`** (see [`crate::storage::namespace_data_dir`]).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use crate::DecryptedIdentity;
use crate::storage::{KeystoreStorageError, StorageConfig};

const PREFERENCES_FORMAT_VERSION: u64 = 1;
/// Soft ceiling — preferences are tiny; a runaway file must not map into RAM.
const MAX_PREFERENCES_JSON_BYTES: u64 = 1024 * 1024;
const MAX_COORD_BASE_URL_CHARS: usize = 2048;
const MAX_PEER_ALIAS_ENTRIES: usize = 4096;

static IO_CHAIN: OnceLock<Mutex<()>> = OnceLock::new();

fn io_chain() -> &'static Mutex<()> {
    IO_CHAIN.get_or_init(|| Mutex::new(()))
}

fn with_prefs_io<T>(
    f: impl FnOnce() -> Result<T, KeystoreStorageError>,
) -> Result<T, KeystoreStorageError> {
    let _guard = io_chain()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    f()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreferencesV1 {
    pub format_version: u64,
    #[serde(default)]
    pub peer_display_aliases: HashMap<String, String>,
    #[serde(default)]
    pub availability_status: Option<String>,
    #[serde(default)]
    pub coord_base_url: Option<String>,
    #[serde(default)]
    pub coord_insecure_tls: bool,
    #[serde(default)]
    pub ui_locale: Option<String>,
    /// Optional name embedded in invitations (`global_alias`).
    #[serde(default)]
    pub local_display_name: Option<String>,
}

impl Default for PreferencesV1 {
    fn default() -> Self {
        Self {
            format_version: PREFERENCES_FORMAT_VERSION,
            peer_display_aliases: HashMap::new(),
            availability_status: None,
            coord_base_url: None,
            coord_insecure_tls: false,
            ui_locale: None,
            local_display_name: None,
        }
    }
}

pub fn preferences_v1_path(cfg: &StorageConfig) -> Result<PathBuf, KeystoreStorageError> {
    let mut p = crate::storage::namespace_data_dir(cfg)?;
    p.push("preferences_v1.json");
    Ok(p)
}

fn prefs_file_modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn read_preferences_utf8_capped(path: &Path) -> Result<Option<String>, KeystoreStorageError> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > MAX_PREFERENCES_JSON_BYTES {
        return Err(KeystoreStorageError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "preferences_v1.json exceeds size limit",
        )));
    }
    let bytes = fs::read(path)?;
    Ok(String::from_utf8(bytes).ok())
}

fn adopt_preferences_tmp(main: &Path, tmp: &Path) {
    let _ = fs::rename(tmp, main);
}

fn sanitize_loaded_preferences(mut p: PreferencesV1) -> Result<PreferencesV1, KeystoreStorageError> {
    if p.format_version != PREFERENCES_FORMAT_VERSION {
        return Err(KeystoreStorageError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported preferences format_version",
        )));
    }
    let mut aliases = HashMap::new();
    for (k, v) in p.peer_display_aliases.drain() {
        if aliases.len() >= MAX_PEER_ALIAS_ENTRIES {
            break;
        }
        let key = k.trim().to_lowercase();
        // Identity wires are short; refuse pathological map keys from a hand-edited prefs file.
        if key.is_empty() || key.len() > 192 {
            continue;
        }
        if let Some(alias) = sanitize_peer_display_alias(&v) {
            aliases.insert(key, alias);
        }
    }
    p.peer_display_aliases = aliases;
    if let Some(url) = p.coord_base_url.as_mut() {
        let t = url.trim().trim_end_matches('/').to_string();
        if t.is_empty() || t.chars().count() > MAX_COORD_BASE_URL_CHARS {
            p.coord_base_url = None;
        } else {
            *url = t;
        }
    }
    if let Some(status) = p.availability_status.take() {
        p.availability_status = sanitize_peer_display_alias(&status);
    }
    if let Some(name) = p.local_display_name.take() {
        p.local_display_name = sanitize_peer_display_alias(&name);
    }
    if let Some(locale) = p.ui_locale.as_mut() {
        let t = locale.trim().to_string();
        if t.is_empty() || t.len() > 32 {
            p.ui_locale = None;
        } else {
            *locale = t;
        }
    }
    Ok(p)
}

fn parse_preferences_json(s: &str) -> Result<PreferencesV1, KeystoreStorageError> {
    let p: PreferencesV1 = serde_json::from_str(s).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("preferences json: {e}"))
    })?;
    sanitize_loaded_preferences(p)
}

fn load_preferences_v1(cfg: &StorageConfig) -> Result<PreferencesV1, KeystoreStorageError> {
    let path = preferences_v1_path(cfg)?;
    let tmp_path = path.with_extension("json.tmp");
    let main_s = read_preferences_utf8_capped(&path)?;
    let tmp_s = read_preferences_utf8_capped(&tmp_path)?;

    if main_s.is_none() && tmp_s.is_none() {
        return Ok(PreferencesV1::default());
    }

    let main_p = main_s.as_deref().and_then(|s| parse_preferences_json(s).ok());
    let tmp_p = tmp_s.as_deref().and_then(|s| parse_preferences_json(s).ok());

    let prefer_tmp = match (&main_p, &tmp_p) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(_), Some(_)) => matches!(
            (prefs_file_modified(&path), prefs_file_modified(&tmp_path)),
            (Some(m), Some(t)) if t >= m
        ),
        (None, None) => false,
    };

    if prefer_tmp {
        if let Some(p) = tmp_p {
            adopt_preferences_tmp(&path, &tmp_path);
            return Ok(p);
        }
    }

    if let Some(p) = main_p {
        if tmp_path.exists() && (tmp_p.is_none() || !prefer_tmp) {
            let _ = fs::remove_file(&tmp_path);
        }
        return Ok(p);
    }

    if let Some(p) = tmp_p {
        adopt_preferences_tmp(&path, &tmp_path);
        return Ok(p);
    }

    if let Some(s) = main_s {
        return parse_preferences_json(&s);
    }
    if let Some(s) = tmp_s {
        return parse_preferences_json(&s);
    }
    Ok(PreferencesV1::default())
}

fn save_preferences_v1(
    cfg: &StorageConfig,
    prefs: &PreferencesV1,
) -> Result<(), KeystoreStorageError> {
    let path = preferences_v1_path(cfg)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(prefs).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("preferences encode: {e}"),
        )
    })?;
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, &path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
fn session_public_key_hex_lower(ident: &DecryptedIdentity) -> String {
    ident.public_key_hex().to_lowercase()
}

#[cfg(test)]
fn verify_public_key_matches_session(
    ident: &DecryptedIdentity,
    public_key_hex: &str,
) -> Result<(), String> {
    let want = public_key_hex.trim().to_lowercase();
    let cur = session_public_key_hex_lower(ident);
    if want != cur {
        return Err("public_key_hex does not match unlocked identity".to_string());
    }
    Ok(())
}

/// Trim / single-line / max length — display hint only (not cryptographic).
pub fn sanitize_peer_display_alias(raw: &str) -> Option<String> {
    let mut t = raw.trim().to_string();
    if t.is_empty() {
        return None;
    }
    for ch in ['\n', '\r', '\t'] {
        t = t.replace(ch, " ");
    }
    const MAX: usize = 64;
    if t.len() > MAX {
        t.truncate(MAX);
        while !t.is_empty() && t.ends_with(' ') {
            t.pop();
        }
    }
    let t = t.trim().to_string();
    if t.is_empty() { None } else { Some(t) }
}

pub fn availability_status_get(
    cfg: &StorageConfig,
) -> Result<Option<String>, KeystoreStorageError> {
    with_prefs_io(|| {
        let prefs = load_preferences_v1(cfg)?;
        Ok(prefs.availability_status.clone())
    })
}

pub fn availability_status_set(
    cfg: &StorageConfig,
    status_raw_utf8: &str,
) -> Result<Option<String>, KeystoreStorageError> {
    with_prefs_io(|| {
        let mut prefs = load_preferences_v1(cfg)?;
        prefs.availability_status = sanitize_peer_display_alias(status_raw_utf8);
        let out = prefs.availability_status.clone();
        save_preferences_v1(cfg, &prefs)?;
        Ok(out)
    })
}

/// Read stored display alias for the **current unlocked** identity (must match [public_key_hex]).
#[cfg(test)]
pub fn peer_display_alias_get(
    cfg: &StorageConfig,
    session: &DecryptedIdentity,
    public_key_hex: &str,
) -> Result<Option<String>, KeystoreStorageError> {
    verify_public_key_matches_session(session, public_key_hex).map_err(|e| {
        KeystoreStorageError::Io(io::Error::new(io::ErrorKind::PermissionDenied, e))
    })?;
    let key = session_public_key_hex_lower(session);
    with_prefs_io(|| {
        let prefs = load_preferences_v1(cfg)?;
        Ok(prefs.peer_display_aliases.get(&key).cloned())
    })
}

/// Set or clear display alias for the **current unlocked** identity.
#[cfg(test)]
pub fn peer_display_alias_set(
    cfg: &StorageConfig,
    session: &DecryptedIdentity,
    public_key_hex: &str,
    alias_raw_utf8: &str,
) -> Result<Option<String>, KeystoreStorageError> {
    verify_public_key_matches_session(session, public_key_hex).map_err(|e| {
        KeystoreStorageError::Io(io::Error::new(io::ErrorKind::PermissionDenied, e))
    })?;
    let key = session_public_key_hex_lower(session);
    with_prefs_io(|| {
        let mut prefs = load_preferences_v1(cfg)?;
        if let Some(s) = sanitize_peer_display_alias(alias_raw_utf8) {
            prefs.peer_display_aliases.insert(key.clone(), s.clone());
            save_preferences_v1(cfg, &prefs)?;
            Ok(Some(s))
        } else {
            prefs.peer_display_aliases.remove(&key);
            save_preferences_v1(cfg, &prefs)?;
            Ok(None)
        }
    })
}

pub fn coord_settings_get(
    cfg: &StorageConfig,
) -> Result<(Option<String>, bool), KeystoreStorageError> {
    with_prefs_io(|| {
        let prefs = load_preferences_v1(cfg)?;
        Ok((prefs.coord_base_url.clone(), prefs.coord_insecure_tls))
    })
}

pub fn coord_settings_set(
    cfg: &StorageConfig,
    base_url: &str,
    insecure_tls: bool,
) -> Result<(), KeystoreStorageError> {
    let t = base_url.trim().trim_end_matches('/').to_string();
    if t.is_empty() {
        return Err(KeystoreStorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coord base url empty",
        )));
    }
    if t.chars().count() > MAX_COORD_BASE_URL_CHARS {
        return Err(KeystoreStorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "coord base url too long",
        )));
    }
    with_prefs_io(|| {
        let mut prefs = load_preferences_v1(cfg)?;
        prefs.coord_base_url = Some(t);
        prefs.coord_insecure_tls = insecure_tls;
        save_preferences_v1(cfg, &prefs)
    })
}

pub fn ui_locale_get(cfg: &StorageConfig) -> Result<Option<String>, KeystoreStorageError> {
    with_prefs_io(|| Ok(load_preferences_v1(cfg)?.ui_locale))
}

pub fn ui_locale_set(cfg: &StorageConfig, locale: &str) -> Result<(), KeystoreStorageError> {
    let locale = locale.trim().to_string();
    if locale.is_empty() {
        return Err(KeystoreStorageError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "locale empty",
        )));
    }
    with_prefs_io(|| {
        let mut prefs = load_preferences_v1(cfg)?;
        prefs.ui_locale = Some(locale);
        save_preferences_v1(cfg, &prefs)
    })
}

pub fn local_display_name_get(cfg: &StorageConfig) -> Result<Option<String>, KeystoreStorageError> {
    with_prefs_io(|| Ok(load_preferences_v1(cfg)?.local_display_name))
}

pub fn local_display_name_set(
    cfg: &StorageConfig,
    name_raw: &str,
) -> Result<Option<String>, KeystoreStorageError> {
    with_prefs_io(|| {
        let mut prefs = load_preferences_v1(cfg)?;
        prefs.local_display_name = sanitize_peer_display_alias(name_raw);
        let out = prefs.local_display_name.clone();
        save_preferences_v1(cfg, &prefs)?;
        Ok(out)
    })
}

/// Removes `preferences_v1.json` for [cfg] if present.
pub fn delete_preferences_v1_file(cfg: &StorageConfig) -> Result<(), KeystoreStorageError> {
    with_prefs_io(|| {
        let path = preferences_v1_path(cfg)?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let tmp = path.with_extension("json.tmp");
        if tmp.exists() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_or_unlock_identity_v1;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_alias() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs").with_override_data_dir(td.path());
        let id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        assert!(peer_display_alias_get(&cfg, &id, "not_hex").is_err());

        let sig = id.public_key_hex();
        assert_eq!(peer_display_alias_get(&cfg, &id, &sig).unwrap(), None);

        let stored = peer_display_alias_set(&cfg, &id, &sig, "  Alice  ").unwrap();
        assert_eq!(stored.as_deref(), Some("Alice"));

        assert_eq!(
            peer_display_alias_get(&cfg, &id, &sig).unwrap().as_deref(),
            Some("Alice")
        );

        let _ = peer_display_alias_set(&cfg, &id, &sig, "   ").unwrap();
        assert_eq!(peer_display_alias_get(&cfg, &id, &sig).unwrap(), None);
    }

    #[test]
    fn roundtrip_availability_status() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.status").with_override_data_dir(td.path());

        assert_eq!(availability_status_get(&cfg).unwrap(), None);
        let stored = availability_status_set(&cfg, "  Busy\nnow  ").unwrap();
        assert_eq!(stored.as_deref(), Some("Busy now"));
        assert_eq!(
            availability_status_get(&cfg).unwrap().as_deref(),
            Some("Busy now")
        );

        let cleared = availability_status_set(&cfg, "   ").unwrap();
        assert_eq!(cleared, None);
        assert_eq!(availability_status_get(&cfg).unwrap(), None);
    }

    #[test]
    fn rejects_oversized_preferences_file() {
        use std::io::Write;
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.big").with_override_data_dir(td.path());
        let path = preferences_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(&vec![b'x'; (MAX_PREFERENCES_JSON_BYTES as usize) + 1])
            .unwrap();
        drop(f);
        let err = load_preferences_v1(&cfg).unwrap_err();
        assert!(
            format!("{err:?}").contains("size limit"),
            "got {err:?}"
        );
    }

    #[test]
    fn load_sanitizes_corrupt_alias_and_drops_empty_url() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.sanitize").with_override_data_dir(td.path());
        let path = preferences_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &path,
            r#"{
              "format_version": 1,
              "peer_display_aliases": { "AbC": "  Bob\n " },
              "coord_base_url": "   ",
              "availability_status": "  Ok\t ",
              "ui_locale": " en "
            }"#,
        )
        .unwrap();
        let p = load_preferences_v1(&cfg).unwrap();
        assert_eq!(p.peer_display_aliases.get("abc").map(String::as_str), Some("Bob"));
        assert_eq!(p.coord_base_url, None);
        assert_eq!(p.availability_status.as_deref(), Some("Ok"));
        assert_eq!(p.ui_locale.as_deref(), Some("en"));
    }

    #[test]
    fn coord_settings_rejects_oversized_url() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.url").with_override_data_dir(td.path());
        let long = format!("https://x/{}", "a".repeat(MAX_COORD_BASE_URL_CHARS));
        assert!(coord_settings_set(&cfg, &long, false).is_err());
    }

    #[test]
    fn load_recovers_preferences_tmp_after_interrupted_save() {
        use std::io::Write;
        use std::thread;
        use std::time::Duration;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.tmp").with_override_data_dir(td.path());
        let _ = availability_status_set(&cfg, "First").unwrap();
        let path = preferences_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let stale = fs::read_to_string(&path).unwrap();
        let _ = availability_status_set(&cfg, "Second").unwrap();
        let durable = fs::read_to_string(&path).unwrap();
        fs::write(&path, stale).unwrap();
        thread::sleep(Duration::from_millis(20));
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(durable.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let p = load_preferences_v1(&cfg).unwrap();
        assert_eq!(p.availability_status.as_deref(), Some("Second"));
        assert!(!tmp_path.exists());
    }

    #[test]
    fn load_rejects_invalid_utf8_without_recoverable_tmp() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.utf8").with_override_data_dir(td.path());
        let path = preferences_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, &[0xff, 0xfe, 0x00]).unwrap();
        let p = load_preferences_v1(&cfg).unwrap();
        assert_eq!(p.format_version, PREFERENCES_FORMAT_VERSION);
        assert!(p.peer_display_aliases.is_empty());
        assert_eq!(p.availability_status, None);
    }

    #[test]
    fn load_drops_pathological_alias_map_keys() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.prefs.alias.key").with_override_data_dir(td.path());
        let path = preferences_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let huge_key = "a".repeat(300);
        fs::write(
            &path,
            format!(
                r#"{{"format_version":1,"peer_display_aliases":{{"{huge_key}":"Bob","ok":"Ada"}}}}"#
            ),
        )
        .unwrap();
        let p = load_preferences_v1(&cfg).unwrap();
        assert!(!p.peer_display_aliases.contains_key(&huge_key));
        assert_eq!(p.peer_display_aliases.get("ok").map(String::as_str), Some("Ada"));
    }
}
