use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::SystemTime;

use directories::ProjectDirs;
use fs4::fs_std::FileExt;
use thiserror::Error;

/// Serialize keystore load/save so concurrent unlock + change-password cannot
/// interleave tmp write / rename on the same path.
fn keystore_io() -> &'static Mutex<()> {
    static IO: OnceLock<Mutex<()>> = OnceLock::new();
    IO.get_or_init(|| Mutex::new(()))
}

/// In-process mutex + cross-process flock for keystore read/modify/write.
struct KeystoreIoGuard {
    _process: MutexGuard<'static, ()>,
    _lock_file: File,
}

impl KeystoreIoGuard {
    fn acquire(cfg: &StorageConfig) -> Result<Self, KeystoreStorageError> {
        let process = keystore_io()
            .lock()
            .map_err(|_| io::Error::other("keystore io mutex poisoned"))?;
        let path = keystore_v1_path(cfg)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("json.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        let _ = restrict_private_file(&lock_path);
        lock_file.lock_exclusive().map_err(|e| {
            io::Error::other(format!("keystore flock {lock_path:?}: {e}"))
        })?;
        Ok(Self {
            _process: process,
            _lock_file: lock_file,
        })
    }
}

#[cfg(unix)]
fn restrict_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_private_file(path: &Path) -> io::Result<()> {
    let _ = path;
    Ok(())
}

use crate::identity::IdentityAlgorithm;
use crate::keystore_v1::{
    DecryptedIdentity, KeystoreError, KeystoreV1, create_keystore_v1_from_secret_with_algorithm,
    create_keystore_v1_with_algorithm, parse_secret_bytes_for_algorithm,
    secret_key_hex_from_identity, unlock_keystore_v1,
};

/// Product / packaging id for **`ghalbol`** (Rust keystore storage root via `directories`).
///
/// Matches the Makepad **`ghalbol_app`** Android `applicationId` / iOS bundle id **`com.ghalbol`**.
/// Use this symbol from JNI / FFI when aligning native paths.
pub const ANDROID_LIBRARY_NAMESPACE: &str = "com.ghalbol";

/// Configuration for where `ghalbol` stores its encrypted keystore blob.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Logical namespace for isolating installs (dev/prod flavors, multiple apps, etc.).
    ///
    /// This is appended under the per-platform app data directory.
    pub app_namespace: String,

    /// Optional override root directory (useful for Android internal storage path or tests).
    pub override_data_dir: Option<PathBuf>,
}

impl StorageConfig {
    pub fn new(app_namespace: impl Into<String>) -> Self {
        Self {
            app_namespace: app_namespace.into(),
            override_data_dir: None,
        }
    }

    pub fn with_override_data_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.override_data_dir = Some(dir.into());
        self
    }
}

#[derive(Debug, Error)]
pub enum KeystoreStorageError {
    #[error("keystore crypto: {0}")]
    Crypto(#[from] KeystoreError),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("cannot determine platform data directory")]
    NoDataDir,

    #[error("invalid app_namespace")]
    BadNamespace,

    #[error(
        "ANDROID_LIBRARY_NAMESPACE must be qualifier.org.application (three dot-separated segments)"
    )]
    InvalidLibraryNamespace,
}

#[derive(Clone, Debug)]
pub struct StoredKeystore {
    pub path: PathBuf,
    pub keystore: KeystoreV1,
}

pub(crate) fn sanitize_namespace(ns: &str) -> Result<(), KeystoreStorageError> {
    let ns = ns.trim();
    if ns.is_empty() || ns.len() > 200 {
        return Err(KeystoreStorageError::BadNamespace);
    }
    // Keep it path-safe: one logical install id, no traversal or odd path segments.
    if ns.contains("..") || ns.contains('/') || ns.contains('\\') {
        return Err(KeystoreStorageError::BadNamespace);
    }
    if ns == "." {
        return Err(KeystoreStorageError::BadNamespace);
    }
    if !ns
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(KeystoreStorageError::BadNamespace);
    }
    Ok(())
}

/// Resolves [`ProjectDirs`] from [`ANDROID_LIBRARY_NAMESPACE`] (`com.ghalbol`).
pub fn project_dirs_for_library() -> Result<ProjectDirs, KeystoreStorageError> {
    return ProjectDirs::from_path(PathBuf::from(ANDROID_LIBRARY_NAMESPACE))
        .ok_or(KeystoreStorageError::NoDataDir);
}

pub fn base_data_dir(cfg: &StorageConfig) -> Result<PathBuf, KeystoreStorageError> {
    if let Some(d) = &cfg.override_data_dir {
        return Ok(d.clone());
    }

    #[cfg(target_os = "linux")]
    {
        return linux_install_data_root(&cfg.app_namespace);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let dirs = project_dirs_for_library()?;
        Ok(dirs.data_local_dir().to_path_buf())
    }
}

/// Directory for identity + prefs under [base_data_dir].
///
/// When [StorageConfig::app_namespace] matches [ANDROID_LIBRARY_NAMESPACE], the base path
/// is already `…/com.ghalbol/` — do not append the namespace segment again.
pub fn namespace_data_dir(cfg: &StorageConfig) -> Result<PathBuf, KeystoreStorageError> {
    sanitize_namespace(&cfg.app_namespace)?;
    #[cfg(target_os = "linux")]
    if cfg.override_data_dir.is_none() {
        return linux_install_data_root(&cfg.app_namespace);
    }
    let mut p = base_data_dir(cfg)?;
    let ns = cfg.app_namespace.trim();
    if ns != ANDROID_LIBRARY_NAMESPACE {
        p.push(ns);
    }
    Ok(p)
}

/// Linux desktop: one XDG root per install id (`com.ghalbol.debug` / `com.ghalbol`).
#[cfg(target_os = "linux")]
fn linux_install_data_root(ns: &str) -> Result<PathBuf, KeystoreStorageError> {
    sanitize_namespace(ns)?;
    ProjectDirs::from_path(PathBuf::from(ns.trim()))
        .ok_or(KeystoreStorageError::NoDataDir)
        .map(|dirs| dirs.data_local_dir().to_path_buf())
}

pub fn keystore_v1_path(cfg: &StorageConfig) -> Result<PathBuf, KeystoreStorageError> {
    let mut p = namespace_data_dir(cfg)?;
    p.push("keystore_v1.json");
    Ok(p)
}

/// Whether the encrypted keystore file is present (does not verify password or JSON).
pub fn keystore_v1_file_exists(cfg: &StorageConfig) -> Result<bool, KeystoreStorageError> {
    let path = keystore_v1_path(cfg)?;
    Ok(path.exists())
}

/// Slightly above [`MAX_KEYSTORE_JSON_IMPORT_BYTES`] so a pretty-printed on-disk file still loads.
const MAX_KEYSTORE_ON_DISK_BYTES: usize = MAX_KEYSTORE_JSON_IMPORT_BYTES + 4096;

fn file_modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn read_keystore_utf8_capped(path: &Path) -> Result<Option<String>, KeystoreStorageError> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(None);
    }
    let len = meta.len();
    if len as usize > MAX_KEYSTORE_ON_DISK_BYTES {
        return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
            "keystore file exceeds size limit",
        )));
    }
    let bytes = fs::read(path)?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(Some(s)),
        // Treat garbage main as absent so a durable `.json.tmp` can recover.
        Err(_) => Ok(None),
    }
}

fn parse_keystore_json(s: &str) -> Result<KeystoreV1, KeystoreStorageError> {
    KeystoreV1::from_json_str(s).map_err(KeystoreStorageError::Crypto)
}

/// Finish a crash-interrupted `save_keystore_v1` (tmp written + synced, rename not done).
fn adopt_keystore_tmp(main: &Path, tmp: &Path) {
    if fs::rename(tmp, main).is_ok() {
        let _ = restrict_private_file(main);
    }
}

fn load_keystore_v1_unlocked(
    cfg: &StorageConfig,
) -> Result<Option<StoredKeystore>, KeystoreStorageError> {
    let path = keystore_v1_path(cfg)?;
    let tmp_path = path.with_extension("json.tmp");
    let main_s = read_keystore_utf8_capped(&path)?;
    let tmp_s = read_keystore_utf8_capped(&tmp_path)?;

    if main_s.is_none() && tmp_s.is_none() {
        return Ok(None);
    }

    let main_ks = main_s
        .as_deref()
        .and_then(|s| parse_keystore_json(s).ok());
    let tmp_ks = tmp_s
        .as_deref()
        .and_then(|s| parse_keystore_json(s).ok());

    let prefer_tmp = match (&main_ks, &tmp_ks) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(_), Some(_)) => matches!(
            (file_modified(&path), file_modified(&tmp_path)),
            (Some(m), Some(t)) if t >= m
        ),
        (None, None) => false,
    };

    if prefer_tmp {
        if let Some(ks) = tmp_ks {
            adopt_keystore_tmp(&path, &tmp_path);
            return Ok(Some(StoredKeystore { path, keystore: ks }));
        }
    }

    if let Some(ks) = main_ks {
        if tmp_path.exists() {
            if tmp_ks.is_none() {
                let _ = fs::remove_file(&tmp_path);
            } else if !prefer_tmp {
                let _ = fs::remove_file(&tmp_path);
            }
        }
        return Ok(Some(StoredKeystore { path, keystore: ks }));
    }

    if let Some(ks) = tmp_ks {
        adopt_keystore_tmp(&path, &tmp_path);
        return Ok(Some(StoredKeystore { path, keystore: ks }));
    }

    if let Some(s) = main_s {
        return Err(parse_keystore_json(&s).unwrap_err());
    }
    if let Some(s) = tmp_s {
        return Err(parse_keystore_json(&s).unwrap_err());
    }
    Ok(None)
}

fn save_keystore_v1_unlocked(
    cfg: &StorageConfig,
    ks: &KeystoreV1,
) -> Result<PathBuf, KeystoreStorageError> {
    use std::io::Write;
    let path = keystore_v1_path(cfg)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let json = ks.to_json_string()?;
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        restrict_private_file(&tmp_path)?;
    }
    fs::rename(&tmp_path, &path)?;
    restrict_private_file(&path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(path)
}

fn with_keystore_io<T>(
    cfg: &StorageConfig,
    f: impl FnOnce() -> Result<T, KeystoreStorageError>,
) -> Result<T, KeystoreStorageError> {
    let _guard = KeystoreIoGuard::acquire(cfg)?;
    f()
}

pub fn load_keystore_v1(
    cfg: &StorageConfig,
) -> Result<Option<StoredKeystore>, KeystoreStorageError> {
    with_keystore_io(cfg, || load_keystore_v1_unlocked(cfg))
}

pub fn save_keystore_v1(
    cfg: &StorageConfig,
    ks: &KeystoreV1,
) -> Result<PathBuf, KeystoreStorageError> {
    with_keystore_io(cfg, || save_keystore_v1_unlocked(cfg, ks))
}

/// High-level helper for UI:
/// - if no keystore exists: create it with `password`, persist it, and return decrypted identity
/// - if keystore exists: unlock it with `password` and return decrypted identity
pub fn create_or_unlock_identity_v1(
    cfg: &StorageConfig,
    password: &str,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    create_or_unlock_identity_v1_with_algorithm(cfg, password, None)
}

/// Same as [`create_or_unlock_identity_v1`] but selects algorithm on **first-time create** only.
pub fn create_or_unlock_identity_v1_with_algorithm(
    cfg: &StorageConfig,
    password: &str,
    create_algorithm: Option<IdentityAlgorithm>,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    if password.trim().is_empty() {
        return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
            "password must not be empty",
        )));
    }
    with_keystore_io(cfg, || {
        if let Some(stored) = load_keystore_v1_unlocked(cfg)? {
            let id = unlock_keystore_v1(password, &stored.keystore)?;
            return Ok(id);
        }

        let algo = create_algorithm.unwrap_or(IdentityAlgorithm::Secp256k1);
        let (ks, id) = create_keystore_v1_with_algorithm(password, algo, None)?;
        let _ = save_keystore_v1_unlocked(cfg, &ks)?;
        Ok(id)
    })
}

/// First-time setup: encrypt [secret_key_hex] (64 hex chars) with [password] and persist.
/// Fails if a keystore already exists (delete first).
pub fn import_identity_from_secret_hex_v1(
    cfg: &StorageConfig,
    password: &str,
    secret_key_hex: &str,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    import_identity_from_secret_hex_v1_with_algorithm(
        cfg,
        password,
        secret_key_hex,
        IdentityAlgorithm::Secp256k1,
    )
}

/// Import existing secret for a specific identity algorithm.
pub fn import_identity_from_secret_hex_v1_with_algorithm(
    cfg: &StorageConfig,
    password: &str,
    secret_key_hex: &str,
    algorithm: IdentityAlgorithm,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    with_keystore_io(cfg, || {
        if keystore_v1_path(cfg)?.exists() {
            return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
                "keystore already exists; delete identity before import",
            )));
        }
        let secret = parse_secret_bytes_for_algorithm(algorithm, secret_key_hex)?;
        let (ks, id) =
            create_keystore_v1_from_secret_with_algorithm(password, algorithm, &secret, None)?;
        let _ = save_keystore_v1_unlocked(cfg, &ks)?;
        Ok(id)
    })
}

/// Verify [password] and return the secret key hex (sensitive) + algorithm.
pub fn reveal_secret_key_hex_v1(
    cfg: &StorageConfig,
    password: &str,
) -> Result<(String, IdentityAlgorithm), KeystoreStorageError> {
    let stored = load_keystore_v1(cfg)?.ok_or(KeystoreStorageError::Crypto(
        KeystoreError::Invalid("no keystore on disk"),
    ))?;
    let id = unlock_keystore_v1(password, &stored.keystore)?;
    Ok((secret_key_hex_from_identity(&id), id.algorithm()))
}

/// Export encrypted `keystore_v1.json` contents (password still required to decrypt elsewhere).
pub fn export_keystore_json_v1(cfg: &StorageConfig) -> Result<String, KeystoreStorageError> {
    let stored = load_keystore_v1(cfg)?.ok_or(KeystoreStorageError::Crypto(
        KeystoreError::Invalid("no keystore on disk"),
    ))?;
    Ok(stored.keystore.to_json_string()?)
}

/// Restore from exported JSON when no keystore exists; [password] must unlock the blob.
/// Matches picker ceiling (`MAX_PICKED_BACKUP_BYTES`) — real keystores are under 1 KB.
const MAX_KEYSTORE_JSON_IMPORT_BYTES: usize = 1024 * 1024;

pub fn import_keystore_from_json_v1(
    cfg: &StorageConfig,
    password: &str,
    keystore_json: &str,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    if keystore_json.len() > MAX_KEYSTORE_JSON_IMPORT_BYTES {
        return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
            "keystore JSON exceeds size limit",
        )));
    }
    with_keystore_io(cfg, || {
        if keystore_v1_path(cfg)?.exists() {
            return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
                "keystore already exists; delete identity before import",
            )));
        }
        let ks = KeystoreV1::from_json_str(keystore_json)?;
        let id = unlock_keystore_v1(password, &ks)?;
        let _ = save_keystore_v1_unlocked(cfg, &ks)?;
        Ok(id)
    })
}

/// Re-encrypt the on-disk keystore under a new app password.
///
/// Verifies [old_password] unlocks the existing keystore, then rewraps the same
/// secret (same identity, same algorithm) with [new_password] and persists it.
/// The public key / identity wire is unchanged; only the at-rest encryption key
/// differs. Any previously exported backup still needs the **old** password —
/// callers should prompt the user to re-export after a successful change.
pub fn change_password_v1(
    cfg: &StorageConfig,
    old_password: &str,
    new_password: &str,
) -> Result<DecryptedIdentity, KeystoreStorageError> {
    if new_password.trim().is_empty() {
        return Err(KeystoreStorageError::Crypto(KeystoreError::Invalid(
            "new password must not be empty",
        )));
    }
    with_keystore_io(cfg, || {
        let stored = load_keystore_v1_unlocked(cfg)?.ok_or(KeystoreStorageError::Crypto(
            KeystoreError::Invalid("no keystore on disk"),
        ))?;
        let id = unlock_keystore_v1(old_password, &stored.keystore)?;
        let algorithm = id.algorithm();
        let secret_hex = secret_key_hex_from_identity(&id);
        let secret = parse_secret_bytes_for_algorithm(algorithm, &secret_hex)?;
        let (ks, new_id) =
            create_keystore_v1_from_secret_with_algorithm(new_password, algorithm, &secret, None)?;
        let _ = save_keystore_v1_unlocked(cfg, &ks)?;
        Ok(new_id)
    })
}

/// Removes `keystore_v1.json` and `preferences_v1.json` for [cfg] if they exist.
pub fn delete_stored_identity_v1(cfg: &StorageConfig) -> Result<(), KeystoreStorageError> {
    with_keystore_io(cfg, || {
        let kp = keystore_v1_path(cfg)?;
        if kp.exists() {
            fs::remove_file(&kp)?;
        }
        let tmp = kp.with_extension("json.tmp");
        if tmp.exists() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(())
    })?;
    crate::preferences_v1::delete_preferences_v1_file(cfg)?;
    Ok(())
}

/// Drop a partial or failed first-time setup so the user can retry with a new app password.
///
/// Safe to call when create/import did not complete successfully; removes keystore if present.
pub fn reset_first_time_identity_v1(cfg: &StorageConfig) -> Result<(), KeystoreStorageError> {
    delete_stored_identity_v1(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore_v1::{
        create_keystore_v1, create_keystore_v1_from_secret_with_algorithm, unlock_keystore_v1,
    };
    use tempfile::TempDir;

    #[test]
    fn keystore_v1_file_exists_false_until_saved() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.exists").with_override_data_dir(td.path());
        assert!(!keystore_v1_file_exists(&cfg).unwrap());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        assert!(keystore_v1_file_exists(&cfg).unwrap());
    }

    #[test]
    fn create_persists_then_unlocks() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.test").with_override_data_dir(td.path());

        let id1 = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let id2 = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn reset_first_time_removes_keystore() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.reset").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        assert!(keystore_v1_file_exists(&cfg).unwrap());
        reset_first_time_identity_v1(&cfg).unwrap();
        assert!(!keystore_v1_file_exists(&cfg).unwrap());
    }

    #[test]
    fn import_secret_hex_persists() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.import").with_override_data_dir(td.path());
        let sk = {
            let (_ks, id) = create_keystore_v1("old", None).unwrap();
            id.secp256k1_secret().secret_bytes()
        };
        let hex = hex::encode(sk);
        let id = import_identity_from_secret_hex_v1(&cfg, "newpw", &hex).unwrap();
        let id2 = create_or_unlock_identity_v1(&cfg, "newpw").unwrap();
        assert_eq!(id.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn export_import_keystore_json_roundtrip() {
        let td = TempDir::new().unwrap();
        let cfg_a = StorageConfig::new("dev.export").with_override_data_dir(td.path().join("a"));
        let cfg_b = StorageConfig::new("dev.export").with_override_data_dir(td.path().join("b"));
        let id1 = create_or_unlock_identity_v1(&cfg_a, "pw").unwrap();
        let json = export_keystore_json_v1(&cfg_a).unwrap();
        let id2 = import_keystore_from_json_v1(&cfg_b, "pw", &json).unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn create_ed25519_identity_on_first_time() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.ed25519").with_override_data_dir(td.path());
        let id = create_or_unlock_identity_v1_with_algorithm(
            &cfg,
            "pw",
            Some(IdentityAlgorithm::Ed25519),
        )
        .unwrap();
        assert_eq!(id.algorithm(), IdentityAlgorithm::Ed25519);
        assert!(id.identity_wire().starts_with("ed25519:"));
        assert!(id.p2p_ready());
        assert!(!id.identity_wire().is_empty());
    }

    #[test]
    fn change_password_rewraps_same_identity() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.chpw").with_override_data_dir(td.path());
        let id1 = create_or_unlock_identity_v1(&cfg, "oldpw").unwrap();
        let changed = change_password_v1(&cfg, "oldpw", "newpw").unwrap();
        assert_eq!(id1.public_key_hex(), changed.public_key_hex());
        // Old password no longer unlocks; new password does.
        assert!(create_or_unlock_identity_v1(&cfg, "oldpw").is_err());
        let id2 = create_or_unlock_identity_v1(&cfg, "newpw").unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn change_password_wrong_old_fails() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.chpw2").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "oldpw").unwrap();
        assert!(change_password_v1(&cfg, "wrong", "newpw").is_err());
        // Original password still works after a failed change.
        assert!(create_or_unlock_identity_v1(&cfg, "oldpw").is_ok());
    }

    #[test]
    fn change_password_empty_new_rejected() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.chpw3").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "oldpw").unwrap();
        assert!(change_password_v1(&cfg, "oldpw", "").is_err());
        assert!(change_password_v1(&cfg, "oldpw", "   \t").is_err());
    }

    #[test]
    fn import_keystore_json_rejects_oversized_blob() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.huge.ks").with_override_data_dir(td.path());
        let huge = "x".repeat(MAX_KEYSTORE_JSON_IMPORT_BYTES + 1);
        let err = import_keystore_from_json_v1(&cfg, "pw", &huge).unwrap_err();
        assert!(err.to_string().contains("size limit"));
    }

    #[test]
    fn concurrent_first_create_yields_one_identity() {
        use std::sync::Arc;
        use std::thread;
        let td = TempDir::new().unwrap();
        let cfg = Arc::new(StorageConfig::new("dev.race").with_override_data_dir(td.path()));
        let mut handles = Vec::new();
        // Same password so losers unlock the winner's blob instead of failing decrypt.
        for _ in 0..8 {
            let cfg = Arc::clone(&cfg);
            handles.push(thread::spawn(move || create_or_unlock_identity_v1(&cfg, "same-pw")));
        }
        let mut pks = Vec::new();
        for h in handles {
            pks.push(h.join().unwrap().unwrap().public_key_hex().to_string());
        }
        pks.sort();
        pks.dedup();
        assert_eq!(pks.len(), 1, "parallel create must not mint multiple identities");
        assert!(load_keystore_v1(&cfg).unwrap().is_some());
    }

    #[test]
    fn create_rejects_whitespace_only_password() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.empty.pw").with_override_data_dir(td.path());
        assert!(create_or_unlock_identity_v1(&cfg, "").is_err());
        assert!(create_or_unlock_identity_v1(&cfg, "  \n").is_err());
    }

    #[test]
    fn change_password_preserves_algorithm() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.chpw4").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1_with_algorithm(
            &cfg,
            "oldpw",
            Some(IdentityAlgorithm::Ed25519),
        )
        .unwrap();
        let changed = change_password_v1(&cfg, "oldpw", "newpw").unwrap();
        assert_eq!(changed.algorithm(), IdentityAlgorithm::Ed25519);
    }

    #[test]
    fn wrong_password_on_existing_keystore_fails() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.test").with_override_data_dir(td.path());

        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let err = create_or_unlock_identity_v1(&cfg, "nope").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("decrypt failed") || msg.contains("kdf failed"));
    }

    #[test]
    fn android_library_namespace_matches_makepad_application_id() {
        assert_eq!(ANDROID_LIBRARY_NAMESPACE, "com.ghalbol");
        let _dirs = project_dirs_for_library().expect("valid library namespace");
    }

    #[test]
    fn default_namespace_keystore_lives_at_base_not_nested() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new(ANDROID_LIBRARY_NAMESPACE).with_override_data_dir(td.path());
        let path = keystore_v1_path(&cfg).unwrap();
        assert_eq!(path, td.path().join("keystore_v1.json"));
    }

    #[test]
    fn other_namespace_keystore_has_subdir() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.test").with_override_data_dir(td.path());
        let path = keystore_v1_path(&cfg).unwrap();
        assert_eq!(path, td.path().join("dev.test").join("keystore_v1.json"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_debug_namespace_own_xdg_root_not_under_release() {
        let path = linux_install_data_root("com.ghalbol.debug").unwrap();
        assert!(path.ends_with("com.ghalbol.debug"));
        assert!(!path.ends_with("com.ghalbol"));
    }

    #[test]
    fn sanitize_namespace_rejects_traversal_and_control_chars() {
        assert!(sanitize_namespace("com.ghalbol.debug").is_ok());
        assert!(matches!(
            sanitize_namespace("../escape"),
            Err(KeystoreStorageError::BadNamespace)
        ));
        assert!(matches!(
            sanitize_namespace("com/evil"),
            Err(KeystoreStorageError::BadNamespace)
        ));
        assert!(matches!(
            sanitize_namespace("com\nev"),
            Err(KeystoreStorageError::BadNamespace)
        ));
        assert!(matches!(
            sanitize_namespace("."),
            Err(KeystoreStorageError::BadNamespace)
        ));
    }

    #[test]
    fn bad_namespace_rejects_keystore_path() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("bad/../x").with_override_data_dir(td.path());
        assert!(matches!(
            keystore_v1_path(&cfg),
            Err(KeystoreStorageError::BadNamespace)
        ));
    }

    #[test]
    fn load_recovers_newer_tmp_after_interrupted_save() {
        use std::io::Write;
        use std::thread;
        use std::time::Duration;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.tmprec").with_override_data_dir(td.path());
        let id1 = create_or_unlock_identity_v1(&cfg, "oldpw").unwrap();
        let (sk_hex, algo) = reveal_secret_key_hex_v1(&cfg, "oldpw").unwrap();
        let secret = parse_secret_bytes_for_algorithm(algo, &sk_hex).unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");

        // Simulate crash after tmp write: main still `oldpw`, tmp holds `newpw` rewrap.
        let (new_ks, _) =
            create_keystore_v1_from_secret_with_algorithm("newpw", algo, &secret, None).unwrap();
        let new_json = new_ks.to_json_string().unwrap();
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(new_json.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        thread::sleep(Duration::from_millis(20));

        let stored = load_keystore_v1(&cfg).unwrap().expect("keystore present");
        let id2 = unlock_keystore_v1("newpw", &stored.keystore).unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert!(!tmp_path.exists());
        assert!(create_or_unlock_identity_v1(&cfg, "newpw").is_ok());
    }

    #[test]
    fn load_rejects_oversize_on_disk_file() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.bigfile").with_override_data_dir(td.path());
        let path = keystore_v1_path(&cfg).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, vec![b'x'; MAX_KEYSTORE_ON_DISK_BYTES + 1]).unwrap();
        let err = load_keystore_v1(&cfg).unwrap_err();
        assert!(err.to_string().contains("size limit"));
    }

    #[test]
    fn load_corrupt_main_uses_valid_tmp() {
        use std::io::Write;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.corrupt").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let good = fs::read_to_string(&path).unwrap();
        // Hold the IO mutex while planting corrupt main + durable tmp so a parallel
        // save/load cannot observe a half-written recovery pair.
        {
            let _guard = keystore_io().lock().unwrap();
            {
                let mut f = fs::File::create(&path).unwrap();
                f.write_all(b"{not json").unwrap();
                f.sync_all().unwrap();
            }
            {
                let mut f = fs::File::create(&tmp_path).unwrap();
                f.write_all(good.as_bytes()).unwrap();
                f.sync_all().unwrap();
            }
        }
        let stored = load_keystore_v1(&cfg).unwrap().expect("recovered");
        assert!(unlock_keystore_v1("pw", &stored.keystore).is_ok());
        assert!(!tmp_path.exists());
    }

    #[test]
    fn change_password_leaves_no_orphan_tmp() {
        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.notmp").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "oldpw").unwrap();
        change_password_v1(&cfg, "oldpw", "newpw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn save_finishes_rename_after_crash_left_tmp_only() {
        use std::io::Write;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.crashsave").with_override_data_dir(td.path());
        let id1 = create_or_unlock_identity_v1(&cfg, "pw1").unwrap();
        let (sk_hex, algo) = reveal_secret_key_hex_v1(&cfg, "pw1").unwrap();
        let secret = parse_secret_bytes_for_algorithm(algo, &sk_hex).unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let (new_ks, _) =
            create_keystore_v1_from_secret_with_algorithm("pw2", algo, &secret, None).unwrap();
        let json = new_ks.to_json_string().unwrap();
        fs::remove_file(&path).unwrap();
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(json.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        assert!(!path.exists());
        assert!(tmp_path.exists());

        let stored = load_keystore_v1(&cfg).unwrap().expect("adopts tmp-only");
        let id2 = unlock_keystore_v1("pw2", &stored.keystore).unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert!(path.exists());
        assert!(!tmp_path.exists());

        let _ = save_keystore_v1(&cfg, &stored.keystore).unwrap();
        assert!(path.exists());
        assert!(!tmp_path.exists());
        let again = load_keystore_v1(&cfg).unwrap().unwrap();
        assert!(unlock_keystore_v1("pw2", &again.keystore).is_ok());
    }

    #[test]
    fn keystore_lock_file_is_exclusive() {
        use fs4::fs_std::FileExt;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.flock").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let lock_path = path.with_extension("json.lock");
        assert!(lock_path.exists());
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        held.lock_exclusive().unwrap();
        let challenger = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert!(
            !challenger.try_lock_exclusive().unwrap(),
            "second exclusive flock must fail while held"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_keystore_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.mode").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let lock_path = path.with_extension("json.lock");
        let lock_mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(lock_mode, 0o600);
    }

    #[test]
    fn load_recovers_valid_tmp_when_main_is_invalid_utf8() {
        use std::io::Write;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.utf8.ks").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let good = fs::read(&path).unwrap();
        fs::write(&path, &[0xff, 0xfe, 0x00, 0x01]).unwrap();
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(&good).unwrap();
            f.sync_all().unwrap();
        }
        let stored = load_keystore_v1(&cfg).unwrap().expect("tmp recovers");
        assert!(unlock_keystore_v1("pw", &stored.keystore).is_ok());
        assert!(!tmp_path.exists());
    }

    #[test]
    fn adopt_keystore_tmp_keeps_durable_tmp_on_rename_failure() {
        use std::io::Write;

        let td = TempDir::new().unwrap();
        let cfg = StorageConfig::new("dev.adoptfail").with_override_data_dir(td.path());
        let _ = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = keystore_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let good = fs::read_to_string(&path).unwrap();
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(good.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let stored = load_keystore_v1_unlocked(&cfg).unwrap().expect("reads tmp");
        assert!(unlock_keystore_v1("pw", &stored.keystore).is_ok());
        assert!(
            tmp_path.exists(),
            "rename onto directory must fail; durable tmp must not be deleted"
        );

        fs::remove_dir(&path).unwrap();
        let _ = load_keystore_v1(&cfg).unwrap();
        assert!(!tmp_path.exists());
    }
}
