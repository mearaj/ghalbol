//! Contacts, roster, invites, and availability.


use crate::contacts_v1::{self, SavedContact};

use super::short_key;
use crate::p2p_runtime;

#[derive(Clone, Debug)]
pub struct RosterEntry {
    pub public_key_hex: String,
    pub title: String,
    pub preview: String,
    pub unread: u32,
    pub is_known: bool,
    pub is_blocked: bool,
    pub availability: String,
}

pub fn list_roster(app_namespace: &str) -> Result<Vec<RosterEntry>, String> {
    let list = contacts_v1::list_contacts(app_namespace).map_err(|e| e.to_string())?;
    Ok(list
        .into_iter()
        .filter(|c| c.has_public_key())
        .map(roster_entry)
        .collect())
}

pub fn add_contact(
    app_namespace: &str,
    public_key_hex: &str,
    alias: Option<&str>,
) -> Result<(), String> {
    let pk = super::require_contact_pk(public_key_hex)?;
    let contact = SavedContact {
        public_key_hex: pk,
        display_alias: alias.map(str::to_string),
        availability_status: None,
        last_message_preview: None,
        last_message_at_ms: None,
        unread_count: 0,
        created_at_ms: None,
        updated_at_ms: None,
        is_known: true,
        is_blocked: false,
        chat_room_exit_at_ms: None,
    };
    let saved = contacts_v1::upsert_contact(app_namespace, contact).map_err(|e| e.to_string())?;
    let _ = p2p_runtime::p2p_register_dm_peer(&saved.public_key_hex);
    Ok(())
}

/// Rename (or clear) a contact's display alias. Empty alias clears the name.
pub fn rename_contact(
    app_namespace: &str,
    public_key_hex: &str,
    alias: &str,
) -> Result<(), String> {
    let pk = public_key_hex.trim();
    if !contacts_v1::is_valid_public_key_hex(pk) {
        return Err("public key is not valid".into());
    }
    let contact = SavedContact {
        public_key_hex: pk.to_string(),
        display_alias: Some(alias.to_string()),
        availability_status: None,
        last_message_preview: None,
        last_message_at_ms: None,
        unread_count: 0,
        created_at_ms: None,
        updated_at_ms: None,
        is_known: true,
        is_blocked: false,
        chat_room_exit_at_ms: None,
    };
    let _ = contacts_v1::upsert_contact(app_namespace, contact).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn mark_known(app_namespace: &str, public_key_hex: &str) -> Result<(), String> {
    let pk = super::require_contact_pk(public_key_hex)?;
    contacts_v1::set_contact_trust(app_namespace, &pk, Some(true), Some(false))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn remove_contact(app_namespace: &str, public_key_hex: &str) -> Result<(), String> {
    let pk = public_key_hex.trim();
    if !contacts_v1::is_valid_public_key_hex(pk) {
        return Err("public key is not valid".into());
    }
    let contact = contacts_v1::SavedContact {
        public_key_hex: pk.to_string(),
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
    };
    contacts_v1::remove_contact(app_namespace, &contact).map_err(|e| e.to_string())
}

pub fn set_blocked(app_namespace: &str, public_key_hex: &str, blocked: bool) -> Result<(), String> {
    let pk = super::require_contact_pk(public_key_hex)?;
    contacts_v1::set_contact_trust(app_namespace, &pk, None, Some(blocked))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn invite_links(public_key_hex: &str, alias: Option<&str>) -> Result<(String, String), String> {
    let map = crate::connect_invite_v1::build_connect_invite_wire_map(
        crate::p2p::DEFAULT_GOSSIP_TOPIC,
        public_key_hex,
        alias,
    )?;
    let https = crate::connect_invite_v1::connect_invite_https_uri_from_wire_map(&map)?;
    let app = crate::connect_invite_v1::connect_invite_app_uri_from_wire_map(&map)?;
    Ok((https, app))
}

pub fn accept_invite(app_namespace: &str, raw: &str) -> Result<String, String> {
    let value = crate::connect_invite_v1::parse_connect_invite_uri(raw.trim())?;
    let wire = crate::connect_invite_v1::identity_wire_from_invite(&value)?;
    let alias = crate::connect_invite_v1::global_alias_from_invite(&value);
    add_contact(app_namespace, &wire, alias.as_deref())?;
    Ok(wire)
}

pub fn availability_status() -> String {
    p2p_runtime::p2p_get_availability_status()
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn set_availability_status(status: &str) -> Result<(), String> {
    let v = p2p_runtime::p2p_set_availability_status(status);
    if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return Err(v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("could not save status")
            .to_string());
    }
    Ok(())
}

pub fn clear_unread(app_namespace: &str, public_key_hex: &str) {
    let _ = contacts_v1::clear_unread(app_namespace, public_key_hex);
}

/// Contact alias, else a short key — call banner and message notifications.
pub(crate) fn peer_display_name(peer_pk_hex: &str) -> String {
    let pk = peer_pk_hex.trim();
    if pk.is_empty() {
        return String::new();
    }
    if let Some(ns) = crate::dm_event_handler::active_app_namespace() {
        if let Ok(rows) = contacts_v1::list_contacts(&ns) {
            if let Some(c) = rows
                .into_iter()
                .find(|c| c.public_key_hex.eq_ignore_ascii_case(pk))
            {
                if let Some(alias) = c
                    .display_alias
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    // Notification summaries / call banners must not carry unbounded aliases.
                    return alias.chars().take(128).collect();
                }
            }
        }
    }
    short_key(pk)
}

fn roster_entry(c: SavedContact) -> RosterEntry {
    let title = c
        .display_alias
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| short_key(&c.public_key_hex));
    let preview = c
        .last_message_preview
        .unwrap_or_default()
        .trim()
        .to_string();
    RosterEntry {
        public_key_hex: c.public_key_hex,
        title,
        preview,
        unread: c.unread_count,
        is_known: c.is_known,
        is_blocked: c.is_blocked,
        availability: c.availability_status.unwrap_or_default(),
    }
}

pub(crate) fn note_outbound_trust(peer_public_key_hex: &str) {
    if let Some(ns) = crate::dm_event_handler::active_app_namespace() {
        let _ = mark_known(&ns, peer_public_key_hex);
    }
}

