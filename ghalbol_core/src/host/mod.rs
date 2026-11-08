//! In-process API for the Makepad UI (`ghalbol_app`).
//!
//! The desktop shell links this crate and calls these functions directly.

mod calls;
mod contacts;
mod identity;
mod messaging;
mod platform;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use calls::*;
pub use contacts::*;
pub use identity::*;
pub use messaging::*;
pub use platform::*;

use crate::app_paths::storage_config_for_namespace;
use serde_json::Value;

pub(crate) fn cfg(app_namespace: &str) -> crate::storage::StorageConfig {
    storage_config_for_namespace(app_namespace)
}

pub(crate) fn json_error(v: &Value, fallback: &str) -> Result<(), String> {
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Err(v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or(fallback)
            .to_string());
    }
    Ok(())
}

pub(crate) fn short_key(pk: &str) -> String {
    let t = pk.trim();
    if t.len() <= 16 {
        return t.to_string();
    }
    if !t.is_ascii() || t.len() < 12 {
        return t.chars().take(16).collect();
    }
    format!("{}…{}", &t[..8], &t[t.len() - 4..])
}

/// Wire-shaped contact identity for outbound host API calls.
pub(crate) fn require_contact_pk(peer_public_key_hex: &str) -> Result<String, String> {
    let pk = peer_public_key_hex.trim();
    if !crate::contacts_v1::is_valid_public_key_hex(pk) {
        return Err("public key is not valid".into());
    }
    Ok(pk.to_string())
}

/// Mailbox / attachment offer ids (`ghalbol_delivery` caps at 128 bytes).
const MAX_DELIVERY_MESSAGE_ID_BYTES: usize = 128;

pub(crate) fn require_delivery_message_id(message_id: &str) -> Result<String, String> {
    let t = message_id.trim();
    if t.is_empty()
        || t.len() > MAX_DELIVERY_MESSAGE_ID_BYTES
        || t.chars().any(char::is_control)
    {
        return Err("message id is not valid".into());
    }
    Ok(t.to_string())
}

pub(crate) fn require_app_namespace(app_namespace: &str) -> Result<&str, String> {
    let ns = app_namespace.trim();
    if ns.is_empty() {
        return Err("app namespace is required".into());
    }
    crate::storage::sanitize_namespace(ns).map_err(|_| "app namespace is not valid".to_string())?;
    Ok(ns)
}
