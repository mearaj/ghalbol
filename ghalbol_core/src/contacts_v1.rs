//! Persisted 1:1 contacts (`contacts_v1.json`) — same format as Makepad [ContactStore].

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use fs4::fs_std::FileExt;

use serde_json::Value;
use thiserror::Error;

use crate::app_paths::{contacts_v1_path, storage_config_for_namespace};
use crate::dm_transport::normalize_contact_pk;
use crate::flow_log::{self, short_hex};
use crate::identity::Identity;
use crate::public_key_util::{legacy_public_key_from_peer_id_str, normalize_contact_identity_wire};
use crate::storage::KeystoreStorageError;

static CHANGE_VERSION: AtomicU64 = AtomicU64::new(0);
static IO_CHAIN: OnceLock<Mutex<()>> = OnceLock::new();

fn io_chain() -> &'static Mutex<()> {
    IO_CHAIN.get_or_init(|| Mutex::new(()))
}

/// In-process mutex + cross-process flock for contacts read/modify/write.
struct ContactsIoGuard {
    _process: MutexGuard<'static, ()>,
    _lock_file: File,
}

impl ContactsIoGuard {
    fn acquire(path: &Path) -> Result<Self, ContactsError> {
        let process = io_chain().lock().unwrap_or_else(|e| e.into_inner());
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
        lock_file.lock_exclusive().map_err(|e| {
            ContactsError::Io(std::io::Error::other(format!(
                "contacts flock {lock_path:?}: {e}"
            )))
        })?;
        Ok(Self {
            _process: process,
            _lock_file: lock_file,
        })
    }

    fn for_namespace(app_namespace: &str) -> Result<(Self, PathBuf), ContactsError> {
        let cfg = storage_config_for_namespace(app_namespace);
        let path = contacts_v1_path(&cfg)?;
        Ok((Self::acquire(&path)?, path))
    }
}

fn bump_change() {
    CHANGE_VERSION.fetch_add(1, Ordering::SeqCst);
}

pub fn contacts_change_version() -> u64 {
    CHANGE_VERSION.load(Ordering::SeqCst)
}

#[derive(Clone, Debug)]
pub struct SavedContact {
    pub public_key_hex: String,
    pub display_alias: Option<String>,
    pub availability_status: Option<String>,
    pub last_message_preview: Option<String>,
    pub last_message_at_ms: Option<i64>,
    pub unread_count: u32,
    pub created_at_ms: Option<i64>,
    pub updated_at_ms: Option<i64>,
    /// User accepted this peer on this device (scan, Add, or outbound send).
    pub is_known: bool,
    /// User blocked this peer on this device.
    pub is_blocked: bool,
    /// Last moment user was actively in the chat room with this peer (DESIGN.md). Updated in lockstep
    /// with the live session clock while the room is open; frozen on leave/switch/inactive.
    pub chat_room_exit_at_ms: Option<i64>,
}

impl SavedContact {
    pub fn has_public_key(&self) -> bool {
        is_valid_public_key_hex(&self.public_key_hex)
    }

    pub fn conversation_key(&self) -> String {
        self.public_key_hex.trim().to_string()
    }

    pub fn to_json(&self) -> Value {
        let mut m = serde_json::json!({
            "unread_count": self.unread_count,
            "is_known": self.is_known,
            "is_blocked": self.is_blocked,
        });
        if !self.public_key_hex.is_empty() {
            m["public_key_hex"] = Value::String(self.public_key_hex.clone());
        }
        if let Some(a) = &self.display_alias {
            if !a.is_empty() {
                m["display_alias"] = Value::String(a.clone());
            }
        }
        if let Some(s) = &self.availability_status {
            if !s.is_empty() {
                m["availability_status"] = Value::String(s.clone());
            }
        }
        if let Some(p) = &self.last_message_preview {
            m["last_message_preview"] = Value::String(p.clone());
        }
        if let Some(t) = self.last_message_at_ms {
            m["last_message_at_ms"] = Value::Number(t.into());
        }
        if let Some(t) = self.created_at_ms {
            m["created_at_ms"] = Value::Number(t.into());
        }
        if let Some(t) = self.updated_at_ms {
            m["updated_at_ms"] = Value::Number(t.into());
        }
        if let Some(t) = self.chat_room_exit_at_ms {
            m["chat_room_exit_at_ms"] = Value::Number(t.into());
        }
        m
    }

    pub fn from_json(raw: &Value) -> Option<Self> {
        let obj = raw.as_object()?;
        let mut pk = obj
            .get("public_key_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if !is_valid_public_key_hex(&pk) {
            let legacy_pid = obj
                .get("libp2p_peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            pk = legacy_public_key_from_peer_id_str(legacy_pid).unwrap_or_default();
        }
        if !is_valid_public_key_hex(&pk) {
            return None;
        }
        let _ = normalize_contact_pk(&pk);
        let is_known = obj
            .get("is_known")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let is_blocked = obj
            .get("is_blocked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Some(Self {
            public_key_hex: pk,
            display_alias: obj
                .get("display_alias")
                .and_then(|v| v.as_str())
                .and_then(crate::preferences_v1::sanitize_peer_display_alias),
            availability_status: obj
                .get("availability_status")
                .and_then(|v| v.as_str())
                .and_then(crate::preferences_v1::sanitize_peer_display_alias),
            last_message_preview: obj
                .get("last_message_preview")
                .and_then(|v| v.as_str())
                .map(truncate_preview)
                .filter(|s| !s.is_empty()),
            last_message_at_ms: obj.get("last_message_at_ms").and_then(|v| v.as_i64()),
            unread_count: obj
                .get("unread_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .min(9999) as u32,
            created_at_ms: obj.get("created_at_ms").and_then(|v| v.as_i64()),
            updated_at_ms: obj.get("updated_at_ms").and_then(|v| v.as_i64()),
            is_known,
            is_blocked,
            chat_room_exit_at_ms: obj.get("chat_room_exit_at_ms").and_then(|v| v.as_i64()),
        })
    }
}

pub fn is_valid_public_key_hex(hex_s: &str) -> bool {
    // Same wire rules as invite / dial paths (`normalize_contact_identity_wire`).
    crate::public_key_util::is_valid_contact_identity_wire(hex_s)
}

#[derive(Debug, Error)]
pub enum ContactsError {
    #[error("storage: {0}")]
    Storage(#[from] KeystoreStorageError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

fn decode_root_lenient(raw: &str) -> Option<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(serde_json::json!({}));
    }
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return v.is_object().then_some(v);
    }
    if !trimmed.starts_with('{') {
        return None;
    }
    // Bound decode attempts — a multi‑MiB corruption of `}` chars must not O(n²) hang.
    let mut attempts = 0u32;
    for (idx, b) in trimmed.as_bytes().iter().enumerate().rev() {
        if *b != b'}' {
            continue;
        }
        attempts += 1;
        if attempts > 64 {
            break;
        }
        let end = idx + 1;
        if end < 2 {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&trimmed[..end]) {
            if v.is_object() {
                return Some(v);
            }
        }
    }
    None
}

/// Soft ceiling for contacts JSON (roster is small; a runaway file must not map into RAM).
const MAX_CONTACTS_JSON_BYTES: u64 = 8 * 1024 * 1024;

fn file_modified(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn read_raw_capped(path: &Path) -> Result<Option<String>, ContactsError> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Ok(None);
    }
    if meta.len() > MAX_CONTACTS_JSON_BYTES {
        return Err(ContactsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "contacts_v1.json exceeds size limit",
        )));
    }
    let bytes = fs::read(path)?;
    Ok(String::from_utf8(bytes).ok())
}

fn adopt_contacts_tmp(main: &Path, tmp: &Path) {
    let _ = fs::rename(tmp, main);
}

fn contacts_share_identity(a: &SavedContact, b: &SavedContact) -> bool {
    match (
        Identity::parse(a.public_key_hex.trim()),
        Identity::parse(b.public_key_hex.trim()),
    ) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Merge duplicate roster rows left by a crash mid-save (same identity, two array slots).
fn merge_loaded_contacts(a: &SavedContact, b: &SavedContact) -> SavedContact {
    let (newer, older) = if b.updated_at_ms.unwrap_or(0) >= a.updated_at_ms.unwrap_or(0) {
        (b, a)
    } else {
        (a, b)
    };
    SavedContact {
        public_key_hex: a.public_key_hex.clone(),
        display_alias: newer
            .display_alias
            .clone()
            .or_else(|| older.display_alias.clone()),
        availability_status: newer
            .availability_status
            .clone()
            .or_else(|| older.availability_status.clone()),
        last_message_preview: newer
            .last_message_preview
            .clone()
            .or_else(|| older.last_message_preview.clone()),
        last_message_at_ms: newer.last_message_at_ms.or(older.last_message_at_ms),
        unread_count: newer.unread_count.max(older.unread_count),
        created_at_ms: older.created_at_ms.or(newer.created_at_ms),
        updated_at_ms: newer.updated_at_ms.or(older.updated_at_ms),
        is_known: a.is_known || b.is_known,
        is_blocked: if newer.is_known {
            newer.is_blocked
        } else {
            newer.is_blocked || older.is_blocked
        },
        chat_room_exit_at_ms: newer.chat_room_exit_at_ms.or(older.chat_room_exit_at_ms),
    }
}

fn parse_contacts_map(raw: &str) -> Option<HashMap<String, Vec<SavedContact>>> {
    let root = decode_root_lenient(raw)?;
    let obj = root.as_object()?;
    let mut out = HashMap::new();
    for (ns, val) in obj {
        let Some(arr) = val.as_array() else {
            continue;
        };
        let mut list = Vec::new();
        for item in arr {
            let Some(c) = SavedContact::from_json(item) else {
                continue;
            };
            if let Some(i) = list.iter().position(|x| contacts_share_identity(x, &c)) {
                list[i] = merge_loaded_contacts(&list[i], &c);
            } else {
                list.push(c);
            }
        }
        out.insert(ns.clone(), list);
    }
    Some(out)
}

fn read_all(path: &Path) -> Result<HashMap<String, Vec<SavedContact>>, ContactsError> {
    let tmp_path = path.with_extension("json.tmp");
    let main_raw = read_raw_capped(path)?;
    let tmp_raw = read_raw_capped(&tmp_path)?;
    let main_map = main_raw.as_deref().and_then(parse_contacts_map);
    let tmp_map = tmp_raw.as_deref().and_then(parse_contacts_map);

    let prefer_tmp = match (&main_map, &tmp_map) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(_), Some(_)) => matches!(
            (file_modified(path), file_modified(&tmp_path)),
            (Some(m), Some(t)) if t >= m
        ),
        (None, None) => false,
    };

    if prefer_tmp {
        if let Some(m) = tmp_map {
            adopt_contacts_tmp(path, &tmp_path);
            return Ok(m);
        }
    }

    if let Some(m) = main_map {
        if tmp_path.exists() && (tmp_map.is_none() || !prefer_tmp) {
            let _ = fs::remove_file(&tmp_path);
        }
        return Ok(m);
    }

    if let Some(m) = tmp_map {
        adopt_contacts_tmp(path, &tmp_path);
        return Ok(m);
    }

    Ok(HashMap::new())
}

fn write_all(path: &Path, all: &HashMap<String, Vec<SavedContact>>) -> Result<(), ContactsError> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let encodable: HashMap<String, Vec<Value>> = all
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().map(|c| c.to_json()).collect()))
        .collect();
    let json = serde_json::to_string_pretty(&encodable)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn with_store<T>(
    app_namespace: &str,
    f: impl FnOnce(
        &Path,
        HashMap<String, Vec<SavedContact>>,
    ) -> Result<(T, HashMap<String, Vec<SavedContact>>), ContactsError>,
) -> Result<T, ContactsError> {
    let (_guard, path) = ContactsIoGuard::for_namespace(app_namespace)?;
    let mut all = read_all(&path)?;
    let (out, next) = f(&path, all)?;
    all = next;
    write_all(&path, &all)?;
    bump_change();
    Ok(out)
}

fn index_of(list: &[SavedContact], contact: &SavedContact) -> Option<usize> {
    if !contact.has_public_key() {
        return None;
    }
    let target = Identity::parse(contact.public_key_hex.trim()).ok()?;
    index_of_identity(list, &target)
}

fn index_of_identity(list: &[SavedContact], target: &Identity) -> Option<usize> {
    list.iter().position(|c| {
        Identity::parse(c.public_key_hex.trim())
            .ok()
            .is_some_and(|id| id == *target)
    })
}

fn index_of_public_key_hex(list: &[SavedContact], public_key_hex: &str) -> Option<usize> {
    let target = Identity::parse(public_key_hex.trim()).ok()?;
    index_of_identity(list, &target)
}

pub fn list_contacts(app_namespace: &str) -> Result<Vec<SavedContact>, ContactsError> {
    let (_guard, path) = ContactsIoGuard::for_namespace(app_namespace)?;
    let mut all = read_all(&path)?;
    let mut dirty = false;
    {
        let list = all.entry(app_namespace.to_string()).or_default();
        for c in list.iter_mut() {
            if !c.has_public_key() {
                continue;
            }
            if let Ok(norm) = normalize_contact_identity_wire(c.public_key_hex.trim()) {
                if norm != c.public_key_hex {
                    c.public_key_hex = norm;
                    dirty = true;
                }
            }
        }
    }
    if dirty {
        write_all(&path, &all)?;
        bump_change();
    }
    let mut list = all.get(app_namespace).cloned().unwrap_or_default();
    list.sort_by(|a, b| {
        let ta = a
            .last_message_at_ms
            .or(a.updated_at_ms)
            .or(a.created_at_ms)
            .unwrap_or(0);
        let tb = b
            .last_message_at_ms
            .or(b.updated_at_ms)
            .or(b.created_at_ms)
            .unwrap_or(0);
        tb.cmp(&ta)
    });
    Ok(list)
}

pub fn find_by_public_key(
    app_namespace: &str,
    public_key_hex: &str,
) -> Result<Option<SavedContact>, ContactsError> {
    let target = match Identity::parse(public_key_hex.trim()) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };
    Ok(list_contacts(app_namespace)?.into_iter().find(|c| {
        Identity::parse(c.public_key_hex.trim())
            .ok()
            .is_some_and(|id| id == target)
    }))
}

/// Lookup by public key hex, or legacy libp2p PeerId string on disk (migrated to pk).
pub fn find_by_peer_id(
    app_namespace: &str,
    conversation_key: &str,
) -> Result<Option<SavedContact>, ContactsError> {
    let k = conversation_key.trim();
    if k.is_empty() {
        return Ok(None);
    }
    if is_valid_public_key_hex(k) {
        return find_by_public_key(app_namespace, k);
    }
    if let Some(pk) = legacy_public_key_from_peer_id_str(k) {
        return find_by_public_key(app_namespace, &pk);
    }
    Ok(None)
}

pub fn upsert_contact(
    app_namespace: &str,
    contact: SavedContact,
) -> Result<SavedContact, ContactsError> {
    let now = now_ms();
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let idx = index_of(list, &contact);
        let base = if let Some(i) = idx {
            list[i].clone()
        } else {
            contact.clone()
        };
        let pk_norm = if contact.has_public_key() {
            normalize_contact_identity_wire(contact.public_key_hex.trim()).map_err(|e| {
                ContactsError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
            })?
        } else {
            base.public_key_hex.clone()
        };
        let next = SavedContact {
            public_key_hex: pk_norm,
            // `Some(_)` in the upsert payload updates alias (empty → clear); `None` keeps existing.
            display_alias: match &contact.display_alias {
                Some(s) => crate::preferences_v1::sanitize_peer_display_alias(s.as_str()),
                None => base.display_alias.clone(),
            },
            // `Some(_)` updates status (empty → clear); `None` keeps existing.
            availability_status: match &contact.availability_status {
                Some(s) => crate::preferences_v1::sanitize_peer_display_alias(s.as_str()),
                None => base.availability_status.clone(),
            },
            last_message_preview: contact
                .last_message_preview
                .as_deref()
                .map(truncate_preview)
                .filter(|s| !s.is_empty())
                .or(base.last_message_preview.clone()),
            last_message_at_ms: contact.last_message_at_ms.or(base.last_message_at_ms),
            unread_count: if contact.last_message_preview.is_some()
                || contact.last_message_at_ms.is_some()
            {
                contact.unread_count
            } else {
                base.unread_count
            },
            created_at_ms: base.created_at_ms.or(Some(now)),
            updated_at_ms: Some(now),
            is_known: contact.is_known || base.is_known,
            // Inbound preview upserts keep block sticky; explicit `is_known` upserts honor block.
            is_blocked: if contact.is_known {
                contact.is_blocked
            } else {
                contact.is_blocked || base.is_blocked
            },
            chat_room_exit_at_ms: contact.chat_room_exit_at_ms.or(base.chat_room_exit_at_ms),
        };
        if let Some(i) = idx {
            list[i] = next.clone();
        } else {
            list.push(next.clone());
        }
        flow_log::info(
            "Contacts",
            format!(
                "upsert pk={} roster_size={}",
                short_hex(&next.public_key_hex),
                list.len()
            ),
        );
        Ok((next, all))
    })
}

pub fn remove_contact(app_namespace: &str, contact: &SavedContact) -> Result<(), ContactsError> {
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        if let Some(i) = index_of(list, contact) {
            list.remove(i);
        }
        Ok(((), all))
    })
}

pub fn merge_discovered_peer_id(
    app_namespace: &str,
    public_key_hex: &str,
    _legacy_conversation_key: &str,
) -> Result<(), ContactsError> {
    let pk = public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Ok(());
    }
    if find_by_public_key(app_namespace, &pk)?.is_some() {
        return Ok(());
    }
    let _ = upsert_contact(
        app_namespace,
        SavedContact {
            public_key_hex: pk,
            display_alias: None,
            availability_status: None,
            last_message_preview: None,
            last_message_at_ms: None,
            unread_count: 0,
            created_at_ms: Some(now_ms()),
            updated_at_ms: Some(now_ms()),
            is_known: false,
            is_blocked: false,
            chat_room_exit_at_ms: None,
        },
    )?;
    Ok(())
}

pub fn set_contact_availability_status(
    app_namespace: &str,
    public_key_hex: &str,
    status: Option<&str>,
) -> Result<SavedContact, ContactsError> {
    let pk = public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Err(ContactsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid public_key_hex",
        )));
    }
    let now = now_ms();
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let Some(i) = index_of_public_key_hex(list, &pk) else {
            return Err(ContactsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "contact not found",
            )));
        };
        let mut c = list[i].clone();
        c.availability_status = status.and_then(crate::preferences_v1::sanitize_peer_display_alias);
        c.updated_at_ms = Some(now);
        list[i] = c.clone();
        flow_log::info(
            "Contacts",
            format!(
                "availability_status pk={} set={}",
                short_hex(&pk),
                c.availability_status.is_some()
            ),
        );
        Ok((c, all))
    })
}

/// Update trust flags for an existing contact (Add / Block / unblock).
pub fn set_contact_trust(
    app_namespace: &str,
    public_key_hex: &str,
    is_known: Option<bool>,
    is_blocked: Option<bool>,
) -> Result<SavedContact, ContactsError> {
    let pk = public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Err(ContactsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid public_key_hex",
        )));
    }
    let now = now_ms();
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let Some(i) = index_of_public_key_hex(list, &pk) else {
            return Err(ContactsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "contact not found",
            )));
        };
        let mut c = list[i].clone();
        if let Some(k) = is_known {
            c.is_known = k;
        }
        if let Some(b) = is_blocked {
            c.is_blocked = b;
        }
        c.updated_at_ms = Some(now);
        list[i] = c.clone();
        flow_log::info(
            "Contacts",
            format!(
                "trust pk={} is_known={} is_blocked={}",
                short_hex(&pk),
                c.is_known,
                c.is_blocked
            ),
        );
        Ok((c, all))
    })
}

/// Mirror the live chat-room session clock onto the foreground contact (DESIGN.md).
pub fn sync_chat_room_exit_at_ms(
    app_namespace: &str,
    public_key_hex: &str,
    at_ms: i64,
) -> Result<(), ContactsError> {
    if at_ms <= 0 {
        return Ok(());
    }
    let pk = public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Ok(());
    }
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let Some(i) = index_of_public_key_hex(list, &pk) else {
            return Ok(((), all));
        };
        let mut c = list[i].clone();
        c.chat_room_exit_at_ms = Some(at_ms);
        list[i] = c;
        Ok(((), all))
    })
}

pub fn chat_room_exit_at_ms(
    app_namespace: &str,
    public_key_hex: &str,
) -> Result<Option<i64>, ContactsError> {
    Ok(find_by_public_key(app_namespace, public_key_hex)?.and_then(|c| c.chat_room_exit_at_ms))
}

/// Hub preview for the latest line in a DM thread (`contact_public_key_hex` is the **other** party).
pub fn record_thread_message_preview(
    app_namespace: &str,
    contact_public_key_hex: &str,
    preview: &str,
    mark_unread: bool,
    message_at_ms: Option<i64>,
) -> Result<(), ContactsError> {
    record_inbound_preview(
        app_namespace,
        contact_public_key_hex,
        preview,
        mark_unread,
        message_at_ms,
    )
}

/// Update contact list preview for the latest message in a thread (`contact_public_key_hex`
/// is the **other** party — inbound sender or outbound recipient).
pub fn record_inbound_preview(
    app_namespace: &str,
    contact_public_key_hex: &str,
    preview: &str,
    mark_unread: bool,
    message_at_ms: Option<i64>,
) -> Result<(), ContactsError> {
    let pk = contact_public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Ok(());
    }
    let at = message_at_ms.unwrap_or_else(now_ms);
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let Some(i) = index_of_public_key_hex(list, &pk) else {
            return Ok(((), all));
        };
        let c = &list[i];
        // Out-of-order apply (poll replay, wire batch) must still bump unread per message.
        if c.last_message_at_ms.is_some_and(|t| at < t) {
            if mark_unread {
                list[i] = SavedContact {
                    unread_count: c.unread_count.saturating_add(1),
                    updated_at_ms: Some(now_ms()),
                    chat_room_exit_at_ms: c.chat_room_exit_at_ms,
                    ..c.clone()
                };
            }
            return Ok(((), all));
        }
        let p = truncate_preview(preview);
        list[i] = SavedContact {
            public_key_hex: c.public_key_hex.clone(),
            display_alias: c.display_alias.clone(),
            availability_status: c.availability_status.clone(),
            last_message_preview: Some(p),
            last_message_at_ms: Some(at),
            // Foreground room clears via `clear_unread`; in-room inbound uses mark_unread false without wiping backlog.
            unread_count: if mark_unread {
                c.unread_count.saturating_add(1)
            } else {
                c.unread_count
            },
            created_at_ms: c.created_at_ms,
            updated_at_ms: Some(now_ms()),
            is_known: c.is_known,
            is_blocked: c.is_blocked,
            chat_room_exit_at_ms: c.chat_room_exit_at_ms,
        };
        Ok(((), all))
    })
}

pub fn clear_unread(app_namespace: &str, public_key_hex: &str) -> Result<(), ContactsError> {
    let pk = public_key_hex.trim().to_lowercase();
    if !is_valid_public_key_hex(&pk) {
        return Ok(());
    }
    with_store(app_namespace, |_path, mut all| {
        let list = all.entry(app_namespace.to_string()).or_default();
        let Some(i) = index_of_public_key_hex(list, &pk) else {
            return Ok(((), all));
        };
        let c = list[i].clone();
        list[i] = SavedContact {
            unread_count: 0,
            updated_at_ms: Some(now_ms()),
            ..c
        };
        Ok(((), all))
    })
}

fn truncate_preview(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() <= 120 {
        return t.to_string();
    }
    let mut out: String = t.chars().take(117).collect();
    out.push('…');
    out
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_keystore_v1_with_algorithm;
    use crate::identity::IdentityAlgorithm;
    use crate::storage::{StorageConfig, create_or_unlock_identity_v1};
    use tempfile::TempDir;

    /// Guest-scanned host identity wire — never the local identity under test.
    const REMOTE_PK: &str = "02f229f167ac2337144dbeba4392a6300c8fe97fb061efdb4f81ec9f29dec76936";

    struct Isolate {
        _lock: std::sync::MutexGuard<'static, ()>,
        dir: TempDir,
    }

    impl Isolate {
        fn new() -> Self {
            let lock = crate::app_paths::test_storage_isolation_lock()
                .lock()
                .unwrap();
            let dir = TempDir::new().unwrap();
            crate::app_paths::configure_android_data_directory(dir.path().to_str().unwrap());
            Self { _lock: lock, dir }
        }

        fn cfg(&self, ns: &str) -> StorageConfig {
            StorageConfig::new(ns).with_override_data_dir(self.dir.path())
        }
    }

    impl Drop for Isolate {
        fn drop(&mut self) {
            crate::app_paths::clear_test_data_directory();
        }
    }

    #[test]
    fn upsert_display_alias_set_and_clear() {
        let iso = Isolate::new();
        let ns = "dev.contacts.alias";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let pk = "0305b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: pk.to_string(),
                display_alias: Some("Alice".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: pk.to_string(),
                display_alias: Some("Bob".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let c = find_by_public_key(ns, pk).unwrap().unwrap();
        assert_eq!(c.display_alias.as_deref(), Some("Bob"));

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: pk.to_string(),
                display_alias: Some("".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let c = find_by_public_key(ns, pk).unwrap().unwrap();
        assert_eq!(c.display_alias, None);
    }

    #[test]
    fn set_contact_trust_matches_mixed_case_wire() {
        let iso = Isolate::new();
        let ns = "dev.contacts.trust_case";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let upper = REMOTE_PK.to_ascii_uppercase();
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: false,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let c = set_contact_trust(ns, &upper, Some(true), None).unwrap();
        assert!(c.is_known);
    }

    #[test]
    fn set_contact_trust_updates_flags() {
        let iso = Isolate::new();
        let ns = "dev.contacts.trust";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: false,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();

        let c = set_contact_trust(ns, REMOTE_PK, Some(true), None).unwrap();
        assert!(c.is_known);
        assert!(!c.is_blocked);

        let c = set_contact_trust(ns, REMOTE_PK, None, Some(true)).unwrap();
        assert!(c.is_blocked);
    }

    #[test]
    fn upsert_known_clears_block_inbound_keeps_block() {
        let iso = Isolate::new();
        let ns = "dev.contacts.block_merge";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: None,
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: false,
                is_blocked: true,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let blocked = find_by_public_key(ns, REMOTE_PK).unwrap().unwrap();
        assert!(blocked.is_blocked);

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: Some("Re-added".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let added = find_by_public_key(ns, REMOTE_PK).unwrap().unwrap();
        assert!(added.is_known);
        assert!(!added.is_blocked);

        set_contact_trust(ns, REMOTE_PK, None, Some(true)).unwrap();
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: None,
                availability_status: None,
                last_message_preview: Some("hey".to_string()),
                last_message_at_ms: Some(1),
                unread_count: 1,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: false,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let preview = find_by_public_key(ns, REMOTE_PK).unwrap().unwrap();
        assert!(preview.is_blocked);
        assert_eq!(preview.last_message_preview.as_deref(), Some("hey"));
    }

    #[test]
    fn read_rejects_contacts_json_over_size_limit() {
        let iso = Isolate::new();
        let ns = "dev.contacts.huge";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = contacts_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // Sparse-ish: write a sentinel then seek — keep the test fast.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"{").unwrap();
            f.seek(SeekFrom::Start(MAX_CONTACTS_JSON_BYTES + 1)).unwrap();
            f.write_all(b"}").unwrap();
        }
        let err = list_contacts(ns).unwrap_err();
        assert!(err.to_string().contains("size limit"));
    }

    #[test]
    fn contacts_store_serializes_parallel_upserts() {
        use std::thread;
        let _iso = Isolate::new();
        let ns = "dev.contacts.parallel";
        let pk = REMOTE_PK.to_string();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let ns = ns.to_string();
                let pk = pk.clone();
                thread::spawn(move || {
                    upsert_contact(
                        &ns,
                        SavedContact {
                            public_key_hex: pk,
                            display_alias: Some(format!("alias-{i}")),
                            availability_status: None,
                            last_message_preview: None,
                            last_message_at_ms: None,
                            unread_count: 0,
                            created_at_ms: None,
                            updated_at_ms: None,
                            is_known: true,
                            is_blocked: false,
                            chat_room_exit_at_ms: None,
                        },
                    )
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap();
        }
        assert_eq!(list_contacts(ns).unwrap().len(), 1);
    }

    #[test]
    fn read_recovers_contacts_tmp_after_interrupted_save() {
        use std::io::Write;
        use std::thread;
        use std::time::Duration;

        let iso = Isolate::new();
        let ns = "dev.contacts.tmp";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: Some("Before".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let path = contacts_v1_path(&cfg).unwrap();
        let tmp_path = path.with_extension("json.tmp");
        let stale = fs::read_to_string(&path).unwrap();
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: Some("After".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: Some(99),
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let durable = fs::read_to_string(&path).unwrap();
        fs::write(&path, stale).unwrap();
        thread::sleep(Duration::from_millis(20));
        {
            let mut f = fs::File::create(&tmp_path).unwrap();
            f.write_all(durable.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        let row = list_contacts(ns).unwrap().into_iter().next().unwrap();
        assert_eq!(row.display_alias.as_deref(), Some("After"));
        assert!(!tmp_path.exists());
    }

    #[test]
    fn load_dedupes_duplicate_public_keys_keeps_newer_row() {
        let iso = Isolate::new();
        let ns = "dev.contacts.dedupe";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let path = contacts_v1_path(&cfg).unwrap();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(
            &path,
            format!(
                r#"{{
              "{ns}": [
                {{
                  "public_key_hex": "{REMOTE_PK}",
                  "display_alias": "Old",
                  "updated_at_ms": 1,
                  "is_known": true,
                  "is_blocked": false,
                  "unread_count": 0
                }},
                {{
                  "public_key_hex": "{REMOTE_PK}",
                  "display_alias": "New",
                  "updated_at_ms": 99,
                  "is_known": true,
                  "is_blocked": false,
                  "unread_count": 0
                }}
              ]
            }}"#
            ),
        )
        .unwrap();
        let rows = list_contacts(ns).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_alias.as_deref(), Some("New"));
    }

    #[test]
    fn read_recovers_contacts_json_after_suffix_garbage() {
        let iso = Isolate::new();
        let ns = "dev.contacts.corrupt";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: REMOTE_PK.to_string(),
                display_alias: Some("Safe".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();
        let path = contacts_v1_path(&cfg).unwrap();
        let good = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{good}<<<<suffix>>>>")).unwrap();
        let row = list_contacts(ns).unwrap().into_iter().next().unwrap();
        assert_eq!(row.display_alias.as_deref(), Some("Safe"));
    }

    #[test]
    fn from_json_sanitizes_alias_and_truncates_preview() {
        let raw = serde_json::json!({
            "public_key_hex": REMOTE_PK,
            "display_alias": format!("  {}\n ", "A".repeat(80)),
            "last_message_preview": "x".repeat(200),
        });
        let c = SavedContact::from_json(&raw).unwrap();
        let alias = c.display_alias.unwrap();
        assert!(alias.chars().count() <= 64);
        assert!(!alias.contains('\n'));
        assert!(c.last_message_preview.as_ref().unwrap().chars().count() <= 120);
    }

    #[test]
    fn upsert_and_find_ed25519_prefixed_identity() {
        let iso = Isolate::new();
        let ns = "dev.contacts.ed25519";
        let cfg = iso.cfg(ns);
        let _id = create_or_unlock_identity_v1(&cfg, "pw").unwrap();
        let (_remote_ks, remote) =
            create_keystore_v1_with_algorithm("pw2", IdentityAlgorithm::Ed25519, None).unwrap();
        let wire = remote.identity_wire();

        upsert_contact(
            ns,
            SavedContact {
                public_key_hex: wire.clone(),
                display_alias: Some("Ed peer".to_string()),
                availability_status: None,
                last_message_preview: None,
                last_message_at_ms: None,
                unread_count: 0,
                created_at_ms: None,
                updated_at_ms: None,
                is_known: true,
                is_blocked: false,
                chat_room_exit_at_ms: None,
            },
        )
        .unwrap();

        let found = find_by_public_key(ns, &wire).unwrap().unwrap();
        assert_eq!(found.public_key_hex, wire);
        assert_eq!(found.display_alias.as_deref(), Some("Ed peer"));
    }
}
