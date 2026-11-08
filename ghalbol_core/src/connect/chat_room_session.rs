//! Chat room session clock (identity-wire keyed).

use std::sync::atomic::{AtomicI64, Ordering};

use super::session::{SessionState, chrono_now_ms};
use super::types::SessionPeer;
use super::ui_session::{app_ack_read_enabled, app_ui_visible, live_foreground_peer};
use crate::p2p::native_log;

static CHAT_ROOM_SESSION_AT_MS: AtomicI64 = AtomicI64::new(0);

pub fn chat_room_session_at_ms() -> i64 {
    CHAT_ROOM_SESSION_AT_MS.load(Ordering::Relaxed)
}

fn set_chat_room_session_at_ms(at_ms: i64) {
    CHAT_ROOM_SESSION_AT_MS.store(at_ms, Ordering::Relaxed);
}

pub(crate) fn clear_chat_room_session() {
    CHAT_ROOM_SESSION_AT_MS.store(0, Ordering::Relaxed);
}

fn app_namespace(session: &SessionState) -> Option<&str> {
    session
        .app_namespace
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
}

pub(crate) fn begin_chat_room_session(session: &SessionState, peer: &SessionPeer) {
    let now = chrono_now_ms();
    set_chat_room_session_at_ms(now);
    let Some(ns) = app_namespace(session) else {
        return;
    };
    if let Err(e) = crate::contacts_v1::sync_chat_room_exit_at_ms(ns, peer, now) {
        native_log::debug("read_ack", format!("chat room session begin {peer}: {e}"));
    }
}

pub fn freeze_open_chat_room_session() {
    let Some(fg_pk) = live_foreground_peer() else {
        clear_chat_room_session();
        return;
    };
    let at = chat_room_session_at_ms();
    if at <= 0 {
        clear_chat_room_session();
        return;
    };
    let Some(ns) = crate::dm_event_handler::active_app_namespace() else {
        clear_chat_room_session();
        return;
    };
    if let Err(e) = crate::contacts_v1::sync_chat_room_exit_at_ms(&ns, &fg_pk, at) {
        native_log::debug("read_ack", format!("chat room freeze on inactive: {e}"));
    } else {
        native_log::info(
            "read_ack",
            format!("chat room frozen on inactive pk={fg_pk} exit_at_ms={at}"),
        );
    }
    clear_chat_room_session();
}

pub(crate) fn tick_chat_room_session_if_active(session: &SessionState) {
    let Some(fg_pk) = live_foreground_peer() else {
        return;
    };
    if !app_ui_visible() || !app_ack_read_enabled() {
        return;
    };
    let now = chrono_now_ms();
    set_chat_room_session_at_ms(now);
    let Some(ns) = app_namespace(session) else {
        return;
    };
    let _ = crate::contacts_v1::sync_chat_room_exit_at_ms(ns, &fg_pk, now);
}

pub(crate) fn read_ack_cutoff_ms(session: &SessionState, peer: &SessionPeer) -> i64 {
    if super::ui_session::is_live_foreground_peer(peer) {
        let live = chat_room_session_at_ms();
        if live > 0 {
            return live;
        }
        return chrono_now_ms();
    }
    let Some(ns) = app_namespace(session) else {
        return chrono_now_ms();
    };
    crate::contacts_v1::chat_room_exit_at_ms(ns, peer)
        .ok()
        .flatten()
        .filter(|t| *t > 0)
        .unwrap_or_else(chrono_now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use crate::connect::session::SessionState;
    use crate::connect::ui_session;
    use crate::create_keystore_v1;

    fn test_session() -> SessionState {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        SessionState::new(id, &[], Some("com.ghalbol.test".into())).unwrap()
    }

    #[test]
    fn begin_chat_room_session_sets_live_clock() {
        clear_chat_room_session();
        let session = test_session();
        let peer: SessionPeer = "aa".repeat(32);
        begin_chat_room_session(&session, &peer);
        assert!(chat_room_session_at_ms() > 0);
        clear_chat_room_session();
        assert_eq!(chat_room_session_at_ms(), 0);
    }

    #[test]
    fn read_ack_cutoff_prefers_live_session_clock() {
        clear_chat_room_session();
        let (_ks, contact) = create_keystore_v1("pw-room", None).unwrap();
        let peer = contact.identity_wire();
        let session = test_session();
        let pinned = 1_700_000_123_456i64;
        CHAT_ROOM_SESSION_AT_MS.store(pinned, Ordering::Relaxed);
        session.set_foreground_peer(Some(peer.clone()));
        ui_session::sync_foreground_peer_now(Some(peer.clone()));
        let cutoff = read_ack_cutoff_ms(&session, &peer);
        assert_eq!(cutoff, pinned);
        ui_session::sync_foreground_peer_now(None);
        clear_chat_room_session();
    }
}
