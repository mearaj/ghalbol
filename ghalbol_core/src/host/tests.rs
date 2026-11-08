    use super::*;
    use crate::contacts_v1::{self, SavedContact};
    use crate::p2p_runtime::p2p_sync_ui_session;

    struct Isolate {
        _lock: std::sync::MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    impl Isolate {
        fn new() -> Self {
            let lock = crate::app_paths::test_storage_isolation_lock()
                .lock()
                .unwrap();
            let dir = tempfile::TempDir::new().unwrap();
            crate::app_paths::configure_android_data_directory(dir.path().to_str().unwrap());
            Self { _lock: lock, _dir: dir }
        }
    }

    impl Drop for Isolate {
        fn drop(&mut self) {
            let _ = lock();
            crate::app_paths::clear_test_data_directory();
        }
    }

    #[test]
    fn identity_invite_password_and_locale() {
        let _iso = Isolate::new();
        let ns = "test.host.production";
        assert!(!keystore_exists(ns));
        let session = unlock_with_options(ns, "correct horse", Some("secp256k1"), None).unwrap();
        assert!(keystore_exists(ns));
        assert!(session_unlocked());
        assert!(session.public_key_hex.len() >= 64);

        let revealed = reveal_secret(ns, "correct horse").unwrap();
        assert!(revealed.contains("secp256k1"));

        let exported = export_keystore(ns).unwrap();
        assert!(exported.contains("keystore") || exported.starts_with('{'));

        let (https, app) = invite_links(&session.public_key_hex, Some("Ada")).unwrap();
        assert!(https.contains("ghalbol.com/connect/"));
        assert!(app.starts_with("ghalbol://connect/"));

        let other = "test.host.production.peer";
        let joined = accept_invite(other, &app).unwrap();
        assert_eq!(joined, session.public_key_hex);
        let roster = list_roster(other).unwrap();
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].title, "Ada");
        assert!(roster[0].is_known);
        set_blocked(other, &joined, true).unwrap();
        assert!(list_roster(other).unwrap()[0].is_blocked);

        change_password(ns, "correct horse", "new horse").unwrap();
        assert!(reveal_secret(ns, "new horse").is_ok());
        assert!(reveal_secret(ns, "correct horse").is_err());

        set_ui_locale(ns, "hi").unwrap();
        assert_eq!(ui_locale(ns).as_deref(), Some("hi"));

        delete_identity(ns, "new horse").unwrap();
        assert!(!keystore_exists(ns));
        assert!(!session_unlocked());
    }

    const PEER: &str = "0305b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";

    fn unknown_peer(ns: &str) {
        contacts_v1::upsert_contact(
            ns,
            SavedContact {
                public_key_hex: PEER.into(),
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
    }

    #[test]
    fn outbound_send_marks_an_unknown_contact_known() {
        let _iso = Isolate::new();
        let ns = "test.host.trust";
        unlock_with_options(ns, "pw", Some("secp256k1"), None).unwrap();
        unknown_peer(ns);
        assert!(send_text(PEER, "hello").is_err());
        let row = list_roster(ns).unwrap().into_iter().next().unwrap();
        assert!(row.is_known);
        assert!(!row.is_blocked);
        lock();
        assert!(!session_unlocked());
    }

    #[test]
    fn availability_presets_persist_and_cap_at_64() {
        let _iso = Isolate::new();
        let ns = "test.host.status";
        unlock_with_options(ns, "pw", Some("secp256k1"), None).unwrap();
        set_availability_status("Busy").unwrap();
        assert_eq!(availability_status(), "Busy");
        set_availability_status("").unwrap();
        assert!(availability_status().is_empty());
        let long = "x".repeat(80);
        set_availability_status(&long).unwrap();
        assert_eq!(availability_status().len(), 64);
    }

    #[test]
    fn transcript_page_keeps_delivery_and_has_more() {
        let _iso = Isolate::new();
        let ns = "test.host.transcript";
        unlock_with_options(ns, "pw", Some("secp256k1"), None).unwrap();
        for i in 0..4 {
            crate::dm_transcript_store::append_if_new(
                ns,
                PEER,
                crate::dm_transcript_store::StoredChatLine {
                    local_id: format!("l{i}"),
                    text: format!("m{i}"),
                    outgoing: true,
                    from: None,
                    message_id: Some(format!("mid{i}")),
                    delivery: if i == 3 { "read" } else { "pending" }.into(),
                    created_at_ms: Some(1000 + i),
                    received_at_ms: None,
                    read_ack_sent: false,
                    msg_kind: "text".into(),
                    duration_ms: None,
                    audio_path: None,
                    file_name: None,
                    mime_type: None,
                    size_bytes: None,
                    local_path: None,
                },
            )
            .unwrap();
        }
        let page = load_transcript(ns, PEER, 2).unwrap();
        assert!(page.has_more);
        assert_eq!(page.lines.len(), 2);
        assert_eq!(page.lines[1].text, "m3");
        assert_eq!(page.lines[1].delivery, "read");
        let full = load_transcript(ns, PEER, 10).unwrap();
        assert!(!full.has_more);
        assert_eq!(full.lines.len(), 4);
    }

    #[test]
    fn hidden_room_does_not_send_a_new_read_ack() {
        let _iso = Isolate::new();
        crate::p2p::sync_foreground_peer_now(Some(PEER.into()));
        let _ = p2p_sync_ui_session(true, Some(PEER));
        let hidden = p2p_sync_ui_session(false, Some(PEER));
        assert_eq!(hidden.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(hidden.get("read_receipts").and_then(|v| v.as_bool()), Some(false));
        assert!(!crate::p2p::may_send_read_ack_for_contact_pk(PEER));
        assert_eq!(
            crate::p2p::live_foreground_peer_pk().as_deref(),
            Some(PEER)
        );
        crate::p2p::sync_foreground_peer_now(None);
        crate::p2p::set_app_ack_read_enabled(false);
        crate::p2p::set_app_ui_visible(true);
    }

    #[test]
    fn speaker_switch_changes_desktop_playback() {
        set_speaker(false).unwrap();
        assert!(!crate::call_media::desktop_speaker_on());
        set_speaker(true).unwrap();
        assert!(crate::call_media::desktop_speaker_on());
    }
