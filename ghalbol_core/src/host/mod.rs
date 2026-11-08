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
        t.to_string()
    } else {
        format!("{}…{}", &t[..8], &t[t.len() - 4..])
    }
}
