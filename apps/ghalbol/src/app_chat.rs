//! App methods (Makepad shell).
use makepad_widgets::*;
use ghalbol_core::host::{self, RosterEntry};
use crate::App;
use crate::chat_helpers::*;
use crate::env_load::*;
use crate::i18n;

impl App {

    pub(crate) fn open_import_backup_sheet(&mut self, cx: &mut Cx) {
        self.pull_password(cx);
        let lang = self.lang.clone();
        if self.password.is_empty() {
            script_eval!(cx, {
                mod.state.status = #(i18n::phrase(&lang, "enter_password"))
                ui.identity_copy.render()
            });
            return;
        }
        self.paste.clear();
        self.show_sheet(
            cx,
            "import_backup",
            "Import keystore backup",
            "Paste the full keystore JSON (the file saved as ghalbol-keystore.json). Use the same app password you enter on the unlock screen.".into(),
            "Import",
        );
        self.ui.text_input(cx, ids!(paste_input)).set_text(cx, "");
    }

    pub(crate) fn finish_import_backup(&mut self, cx: &mut Cx, session: host::UnlockedSession) {
        self.password.clear();
        let pk = session.public_key_hex.clone();
        let ns = session.app_namespace.clone();
        self.session = Some(session);
        self.page.clear();
        let status = match host::start_network(&ns) {
            Ok(_) => "Backup imported".into(),
            Err(e) => format!("Network: {e}"),
        };
        self.show_hub(cx, &pk, &status);
    }

    pub(crate) fn close_sheet(&mut self, cx: &mut Cx) {
        let lang = self.lang.clone();
        if self.needs_backup {
            self.show_sheet(
                cx,
                "backup",
                &i18n::phrase(&lang, "save_backup"),
                i18n::phrase(&lang, "save_backup_body"),
                &i18n::phrase(&lang, "save"),
            );
            return;
        }
        if self.page == "scan" {
            self.end_qr_scan_ui();
        }
        self.page.clear();
        script_eval!(cx, {
            ui.sheet_view.set_visible(false)
            ui.identity_view.set_visible(false)
            ui.call_view.set_visible(false)
            ui.hub_view.set_visible(true)
        });
        self.set_screen(cx, "hub");
        self.refresh_roster(cx);
        // Finished a sheet via Back button / action — replace so Forward does not
        // resurrect a completed flow. History walks use force_close_sheet instead.
        if !self.history_suppress {
            self.hub_history.replace_top(self.hub_snapshot());
        }
    }

    pub(crate) fn save_availability(&mut self, status: &str) -> Result<String, String> {
        let normalized = normalize_availability_status(status).unwrap_or_default();
        self.add_alias = normalized.clone();
        save_status_line(status)
    }

    pub(crate) fn apply_status_preset(&mut self, cx: &mut Cx, status: &str) {
        let msg = save_status_line(status).unwrap_or_else(|e| e);
        self.add_alias = status.to_string();
        let custom = self.add_alias.clone();
        script_eval!(cx, {
            mod.state.sheet_body = #(msg.clone())
            ui.sheet_copy.render()
        });
        self.sync_sheet_body_text(cx, &msg);
        self.ui.text_input(cx, ids!(alias_input)).set_text(cx, &custom);
        self.refresh_roster(cx);
    }

    pub(crate) fn sheet_go(&mut self, cx: &mut Cx) {
        let paste = self.ui.text_input(cx, ids!(paste_input)).text();
        if !paste.is_empty() {
            self.paste = paste;
        }
        let pk = self.ui.text_input(cx, ids!(pk_input)).text();
        if !pk.is_empty() {
            self.add_pk = pk;
        }
        let alias = self.ui.text_input(cx, ids!(alias_input)).text();
        if !alias.is_empty()
            || self.page == "about"
            || self.page == "password"
            || self.page == "contacts"
        {
            self.add_alias = alias;
        }
        let page = self.page.clone();
        let ns = self.namespace.clone();
        let result = match page.as_str() {
            "join" => match host::accept_invite(&ns, self.paste.trim()) {
                Ok(pk) => {
                    let msg = join_accept_status_line(&pk);
                    self.close_sheet(cx);
                    self.open_joined_peer_chat(cx, &pk);
                    self.show_call_line(cx, msg);
                    return;
                }
                Err(e) => Err(e),
            },
            "add" => host::add_contact(
                &ns,
                self.add_pk.trim(),
                Some(self.add_alias.trim()),
            )
            .map(|()| "Contact added".into()),
            "contacts" => {
                let pk = self.open_peer.trim().to_string();
                if pk.is_empty() {
                    Err("Open a chat first, then rename or remove that contact.".into())
                } else if self.add_alias.trim().is_empty() {
                    host::remove_contact(&ns, &pk).map(|()| "Removed".into())
                } else {
                    host::rename_contact(&ns, &pk, self.add_alias.trim())
                        .map(|()| "Renamed".into())
                }
            }
            "blocked" => {
                let pk = self.add_pk.trim().to_string();
                let blocked = host::list_roster(&ns)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|r| r.public_key_hex.eq_ignore_ascii_case(&pk))
                    .map(|r| r.is_blocked)
                    .unwrap_or(false);
                host::set_blocked(&ns, &pk, !blocked).map(|()| {
                    if blocked {
                        "Unblocked".into()
                    } else {
                        "Blocked".into()
                    }
                })
            }
            "about" => {
                let status = self.add_alias.trim().to_string();
                self.save_availability(&status)
            }
            "delivery" => {
                let mid = self.paste.trim();
                if mid.is_empty() {
                    // Refresh — reopen paints a fresh summary + quota.
                    self.open_page(cx, "delivery");
                    return;
                }
                host::extend_mailbox_ttl(mid).map(|()| "TTL extended".into())
            }
            "log" => Ok(String::new()),
            "invite" => {
                let link = self.paste.trim();
                if link.is_empty() {
                    Err("Invitation link is empty.".into())
                } else {
                    copy_to_clipboard(cx, link).map(|()| "Invitation copied".into())
                }
            }
            "scan" => {
                match host::start_qr_scan() {
                    Ok(()) => Ok("Point the camera at an invitation QR…".into()),
                    Err(e) => Err(e),
                }
            }
            "key" => host::reveal_secret(&ns, self.paste.trim()),
            "backup" => self.save_backup(),
            "import_backup" => {
                self.pull_password(cx);
                match self.import_backup_from_paste() {
                    Ok(session) => {
                        self.finish_import_backup(cx, session);
                        return;
                    }
                    Err(e) => Err(e),
                }
            }
            "password" => {
                let current = self.paste.trim();
                let new_password = self.add_alias.trim();
                let confirm = self.add_pk.trim();
                if current.is_empty() || new_password.is_empty() {
                    Err("Enter the current password and a new password.".into())
                } else if new_password != confirm {
                    Err("New password and confirmation do not match.".into())
                } else if new_password == current {
                    Err("Choose a different password.".into())
                } else {
                    host::change_password(&ns, current, new_password)
                        .map(|()| "Password changed. Export a new backup. Older backups still use the old password.".into())
                }
            }
            _ => {
                self.close_sheet(cx);
                return;
            }
        };
        match result {
            Ok(msg) => {
                if page == "delivery" || page == "log" {
                    self.open_page(cx, &page);
                } else if page == "key" || page == "password" || page == "invite" || page == "scan" {
                    script_eval!(cx, {
                        mod.state.sheet_body = #(msg.clone())
                        ui.sheet_copy.render()
                    });
                    self.sync_sheet_body_text(cx, &msg);
                } else if page == "backup" {
                    self.finish_backup(cx, msg);
                } else {
                    if page == "contacts" {
                        self.open_peer.clear();
                        self.roster_ver = u64::MAX;
                    }
                    self.close_sheet(cx);
                }
            }
            Err(e) => {
                script_eval!(cx, {
                    mod.state.sheet_body = #(e.clone())
                    ui.sheet_copy.render()
                });
                self.sync_sheet_body_text(cx, &e);
            }
        }
    }

    pub(crate) fn transcript_limit(&self) -> usize {
        if self.window_limit == 0 { 50 } else { self.window_limit }
    }

    pub(crate) fn toggle_voice_note(&mut self, cx: &mut Cx) {
        let peer = self.open_peer.clone();
        if peer.is_empty() {
            self.show_chat_error(cx, "Select a chat first".into());
            return;
        }
        let msg = match host::voice_note_toggle() {
            Ok(None) => {
                self.sync_recording_bar(cx);
                String::new()
            }
            Ok(Some((duration_ms, opus))) => {
                self.sync_recording_bar(cx);
                if duration_ms < 400 {
                    "Recording too short".into()
                } else {
                    match host::send_voice_note(&peer, duration_ms, opus) {
                        Ok(()) => "Voice note sent".into(),
                        Err(e) => e,
                    }
                }
            }
            Err(e) => {
                self.sync_recording_bar(cx);
                e
            }
        };
        let sent = msg == "Voice note sent";
        if !msg.is_empty() {
            if sent {
                self.show_call_line(cx, msg);
            } else {
                self.show_chat_error(cx, msg);
            }
        }
        if sent {
            self.refresh_transcript(cx);
        }
    }

    pub(crate) fn cancel_voice_note(&mut self, cx: &mut Cx) {
        let _ = host::voice_note_cancel();
        self.sync_recording_bar(cx);
        self.show_call_line(cx, "Recording discarded".into());
    }

    /// Show/hide the Flutter-style recording bar and refresh the elapsed timer.
    pub(crate) fn sync_recording_bar(&mut self, cx: &mut Cx) {
        let recording = host::voice_note_recording();
        if recording != self.recording_ui {
            self.recording_ui = recording;
            self.ui
                .widget(cx, ids!(recording_bar))
                .set_visible(cx, recording);
            self.ui
                .widget(cx, ids!(composer_row))
                .set_visible(cx, !recording);
            self.ui.view(cx, ids!(composer_bar)).redraw(cx);
        }
        if recording {
            let ms = host::voice_note_elapsed_ms().unwrap_or(0);
            let label = format_mmss(ms);
            script_eval!(cx, { ui.record_timer_label.set_text(#(label)) });
        }
    }

    pub(crate) fn set_chat_menu_open(&mut self, cx: &mut Cx, open: bool) {
        if self.chat_menu_open == open {
            return;
        }
        self.chat_menu_open = open;
        self.ui.widget(cx, ids!(chat_menu)).set_visible(cx, open);
        self.ui.view(cx, ids!(chat_bar)).redraw(cx);
    }

    pub(crate) fn open_languages(&mut self, cx: &mut Cx) {
        if !self.history_suppress {
            self.hub_history.replace_top(self.hub_snapshot());
        }
        self.page = "lang".into();
        script_eval!(cx, {
            mod.state.sheet_title = "Language"
            mod.state.sheet_body = "Choose the language for this app. Native names need the bundled script fonts."
            mod.state.languages = []
            ui.hub_view.set_visible(false)
            ui.sheet_view.set_visible(true)
            true
        });
        let mut last_region = "";
        for lang in i18n::LANGUAGES {
            if lang.region != last_region {
                last_region = lang.region;
                let region = lang.region.to_string();
                script_eval!(cx, {
                    mod.state.languages.push({ code: "" name: #(region) })
                    true
                });
            }
            let code = lang.code.to_string();
            let name = if lang.native_name == lang.name_en {
                lang.native_name.to_string()
            } else {
                format!("{} — {}", lang.native_name, lang.name_en)
            };
            script_eval!(cx, {
                mod.state.languages.push({ code: #(code) name: #(name) })
                true
            });
        }
        script_eval!(cx, { ui.sheet_copy.render() });
        self.sync_sheet_copy_text(
            cx,
            "Language",
            "Choose the language for this app. Native names need the bundled script fonts.",
        );
        self.ui.widget(cx, ids!(invite_frame)).set_visible(cx, false);
        self.ui.widget(cx, ids!(scan_frame)).set_visible(cx, false);
        self.ui.widget(cx, ids!(paste_row)).set_visible(cx, false);
        self.ui.widget(cx, ids!(pk_row)).set_visible(cx, false);
        self.ui.widget(cx, ids!(alias_row)).set_visible(cx, false);
        self.ui.widget(cx, ids!(status_row)).set_visible(cx, false);
        self.set_screen(cx, "sheet");
        self.record_hub_nav();
    }

    pub(crate) fn sync_play(&mut self, cx: &mut Cx) {
        let gen_val = script_eval!(cx, { mod.state.play_gen });
        let play_n = splash_f64(cx, gen_val);
        if play_n == self.seen_play {
            return;
        }
        self.seen_play = play_n;
        let path_val = script_eval!(cx, { mod.state.play_path });
        let path = splash_string(cx, path_val);
        let action_val = script_eval!(cx, { mod.state.play_action });
        let action = splash_string(cx, action_val);
        if path.is_empty() {
            return;
        }
        let peer = self.open_peer.clone();
        let msg: Result<String, String> = if action == "voice" {
            host::play_voice_file(&path)
        } else if action == "fetch" {
            host::fetch_attachment(&peer, &path)
        } else if action == "save" {
            host::save_attachment(&path)
        } else if action == "resend" {
            host::resend_failed(&peer, &path).map(|()| "Resent".into())
        } else {
            host::open_local_file(&path).map(|()| "Opened".into())
        };
        let note = match &msg {
            Ok(text) if action == "fetch" || action == "voice" || action == "resend" => {
                text.clone()
            }
            Err(e) => e.clone(),
            Ok(_) => String::new(),
        };
        if action == "resend" && msg.is_ok() {
            self.chat_rev = 0;
            self.refresh_transcript(cx);
        }
        if !note.is_empty() {
            if msg.is_err() {
                self.show_chat_error(cx, note);
            } else {
                self.show_call_line(cx, note);
            }
        }
    }

    pub(crate) fn sync_language(&mut self, cx: &mut Cx) {
        let gen_val = script_eval!(cx, { mod.state.lang_gen });
        let lang_n = splash_f64(cx, gen_val);
        if lang_n == self.seen_lang || lang_n == 0.0 {
            return;
        }
        self.seen_lang = lang_n;
        let code_val = script_eval!(cx, { mod.state.lang_code });
        let code = splash_string(cx, code_val);
        if code.is_empty() {
            return;
        }
        self.lang = code.clone();
        let _ = host::set_ui_locale(&self.namespace, &code);
        self.apply_language(cx);
        self.close_sheet(cx);
    }

    pub(crate) fn apply_language(&self, cx: &mut Cx) {
        let lang = self.lang.as_str();
        let unlock = i18n::text(lang, i18n::Key::Unlock).to_string();
        let new_chat = i18n::text(lang, i18n::Key::NewChat).to_string();
        let invitation = i18n::text(lang, i18n::Key::Invitation).to_string();
        let join = i18n::text(lang, i18n::Key::Join).to_string();
        let contacts = i18n::text(lang, i18n::Key::Contacts).to_string();
        let blocked = i18n::text(lang, i18n::Key::Blocked).to_string();
        let delivery = i18n::text(lang, i18n::Key::Delivery).to_string();
        let log = i18n::text(lang, i18n::Key::AppLog).to_string();
        let key = i18n::text(lang, i18n::Key::PrivateKey).to_string();
        let backup = i18n::text(lang, i18n::Key::Backup).to_string();
        let password = i18n::text(lang, i18n::Key::PasswordMenu).to_string();
        let about = i18n::text(lang, i18n::Key::About).to_string();
        let language = i18n::text(lang, i18n::Key::Language).to_string();
        let lock = i18n::text(lang, i18n::Key::Lock).to_string();
        let lock_hub = lock.clone();
        let logout = i18n::text(lang, i18n::Key::Logout).to_string();
        let older = i18n::text(lang, i18n::Key::Older).to_string();
        let accept = i18n::text(lang, i18n::Key::Accept).to_string();
        let mute = i18n::text(lang, i18n::Key::Mute).to_string();
        let speaker = i18n::phrase(lang, "speaker");
        let camera = if self.camera_on {
            i18n::phrase(lang, "camera_on")
        } else {
            i18n::phrase(lang, "camera_off")
        };
        let flip_camera = i18n::phrase(lang, "flip_camera").to_string();
        let end = i18n::text(lang, i18n::Key::EndCall).to_string();
        let scan = i18n::text(lang, i18n::Key::ScanQr).to_string();
        let scan_file = i18n::text(lang, i18n::Key::QrPicture).to_string();
        let chats = i18n::text(lang, i18n::Key::Chats).to_string();
        let invite_tab = i18n::text(lang, i18n::Key::InviteTab).to_string();
        let settings = i18n::text(lang, i18n::Key::Settings).to_string();
        let contacts_menu = contacts.clone();
        let voice_call = i18n::text(lang, i18n::Key::VoiceCall).to_string();
        let video_call = i18n::text(lang, i18n::Key::VideoCall).to_string();
        let share_menu = i18n::phrase(lang, "share");
        let join_menu = join.clone();
        let add_menu = i18n::phrase(lang, "add_short");
        let block_menu = i18n::text(lang, i18n::Key::Block).to_string();
        let lock_menu = lock.clone();
        let add_contact_nav = i18n::phrase(lang, "add");
        let join_nav = i18n::phrase(lang, "paste");
        let scan_nav = scan.clone();
        let delivery_nav = delivery.clone();
        let show_qr = invitation.clone();
        let nav = [
            chats.clone(),
            chats.clone(),
            chats.clone(),
            chats,
            contacts.clone(),
            contacts.clone(),
            contacts.clone(),
            contacts,
            invite_tab.clone(),
            invite_tab.clone(),
            invite_tab.clone(),
            invite_tab,
            settings.clone(),
            settings.clone(),
            settings.clone(),
            settings,
        ];
        let [
            tab_chats_l,
            tab_chats_on_l,
            bottom_chats_l,
            bottom_chats_on_l,
            tab_contacts_l,
            tab_contacts_on_l,
            bottom_contacts_l,
            bottom_contacts_on_l,
            tab_invite_l,
            tab_invite_on_l,
            bottom_invite_l,
            bottom_invite_on_l,
            tab_settings_l,
            tab_settings_on_l,
            bottom_settings_l,
            bottom_settings_on_l,
        ] = nav;
        script_eval!(cx, {
            ui.unlock_button.set_text(#(unlock))
            ui.new_chat_button.set_text(#(new_chat))
            ui.invite_button.set_text(#(invitation))
            ui.join_button.set_text(#(join))
            ui.scan_button.set_text(#(scan))
            ui.scan_file_button.set_text(#(scan_file))
            ui.contacts_button.set_text(#(contacts_menu))
            ui.blocked_button.set_text(#(blocked))
            ui.delivery_button.set_text(#(delivery))
            ui.log_button.set_text(#(log))
            ui.key_button.set_text(#(key))
            ui.backup_button.set_text(#(backup))
            ui.password_button.set_text(#(password))
            ui.about_button.set_text(#(about))
            ui.language_button.set_text(#(language))
            ui.lock_button.set_text(#(lock))
            ui.hub_lock_button.set_text(#(lock_hub))
            ui.logout_button.set_text(#(logout))
            ui.older_button.set_text(#(older))
            // Hub peers — idle + active faces share the same label.
            ui.tab_chats.set_text(#(tab_chats_l))
            ui.tab_chats_on.set_text(#(tab_chats_on_l))
            ui.bottom_chats.set_text(#(bottom_chats_l))
            ui.bottom_chats_on.set_text(#(bottom_chats_on_l))
            ui.tab_contacts.set_text(#(tab_contacts_l))
            ui.tab_contacts_on.set_text(#(tab_contacts_on_l))
            ui.bottom_contacts.set_text(#(bottom_contacts_l))
            ui.bottom_contacts_on.set_text(#(bottom_contacts_on_l))
            ui.tab_invite.set_text(#(tab_invite_l))
            ui.tab_invite_on.set_text(#(tab_invite_on_l))
            ui.bottom_invite.set_text(#(bottom_invite_l))
            ui.bottom_invite_on.set_text(#(bottom_invite_on_l))
            ui.tab_settings.set_text(#(tab_settings_l))
            ui.tab_settings_on.set_text(#(tab_settings_on_l))
            ui.bottom_settings.set_text(#(bottom_settings_l))
            ui.bottom_settings_on.set_text(#(bottom_settings_on_l))
            // Call screen keeps readable labels (not FA-only).
            ui.accept_call_button.set_text(#(accept))
            ui.mute_button.set_text(#(mute))
            ui.speaker_button.set_text(#(speaker))
            ui.camera_button.set_text(#(camera))
            ui.flip_camera_button.set_text(#(flip_camera))
            ui.end_call_button.set_text(#(end))
            // Room ⋮ menu + peer HubDest rows (composer IconBtn glyphs stay FA).
            ui.menu_call_button.set_text(#(voice_call))
            ui.menu_video_button.set_text(#(video_call))
            ui.menu_share_button.set_text(#(share_menu))
            ui.menu_join_button.set_text(#(join_menu))
            ui.menu_add_button.set_text(#(add_menu))
            ui.menu_block_button.set_text(#(block_menu))
            ui.menu_lock_button.set_text(#(lock_menu))
            ui.add_contact_button.set_text(#(add_contact_nav))
            ui.join_nav_button.set_text(#(join_nav))
            ui.scan_nav_button.set_text(#(scan_nav))
            ui.delivery_nav_button.set_text(#(delivery_nav))
            ui.invite_button_id.set_text(#(show_qr))
        });
        // Composer/mic/attach stay FA IconBtn glyphs — keep Key variants constructed
        // so catalogs stay complete without translating onto icon faces.
        let _chrome_icon_keys = (
            i18n::text(lang, i18n::Key::VoiceNote),
            i18n::text(lang, i18n::Key::ChooseFile),
            i18n::text(lang, i18n::Key::Send),
        );
        let _ = _chrome_icon_keys;
    }

    pub(crate) fn sync_open_chat(&mut self, cx: &mut Cx) {
        if self.session.is_none() {
            return;
        }
        let open_val = script_eval!(cx, { mod.state.open_gen });
        let open_gen = splash_f64(cx, open_val);
        let pk_val = script_eval!(cx, { mod.state.selected_pk });
        let pk = splash_string(cx, pk_val);
        if open_gen == self.seen_open_gen && pk == self.open_peer {
            return;
        }
        self.seen_open_gen = open_gen;
        let peer_changed = pk != self.open_peer;
        if peer_changed {
            self.clear_chat_notice();
        }
        let pk = canonical_peer_key(&pk);
        self.open_peer = pk.clone();
        if pk.is_empty() {
            host::set_open_room(None);
            self.narrow_show_room = false;
            self.sync_trust_banner(cx, &[]);
            self.release_composer_key_focus(cx);
            self.apply_shell_layout(cx);
            if peer_changed {
                self.roster_ver = u64::MAX;
                self.refresh_roster(cx);
                self.hub_history.replace_top(self.hub_snapshot());
            }
            return;
        }
        let opened_room = if !self.shell_split {
            let was = self.narrow_show_room;
            self.narrow_show_room = true;
            !was
        } else {
            peer_changed
        };
        host::set_open_room(Some(&pk));
        host::clear_unread(&self.namespace, &pk);
        // Force roster repaint so open-room green / unread blue wash update now
        // (not only after the next contacts_version bump).
        self.roster_ver = u64::MAX;
        self.refresh_roster(cx);
        let title_val = script_eval!(cx, { mod.state.selected_title });
        let title = splash_string(cx, title_val);
        if !title.is_empty() {
            script_eval!(cx, { ui.chat_title_label.set_text(#(title)) });
        }
        self.apply_shell_layout(cx);
        let rev = host::transcript_revision(&self.namespace, &pk);
        if should_refresh_transcript_on_open(
            peer_changed,
            rev,
            self.chat_rev,
            &self.chat_lines_peer,
            &pk,
        ) {
            self.refresh_transcript(cx);
        }
        if opened_room {
            self.record_hub_nav();
        }
    }

    /// Leave the open room entirely (block, remove): native leave drain via
    /// `set_open_room(None)`, hub state cleared so the poll does not reopen it.
    pub(crate) fn close_open_room(&mut self, cx: &mut Cx) {
        self.open_peer.clear();
        host::set_open_room(None);
        self.narrow_show_room = false;
        self.chat_lines_peer.clear();
        self.chat_lines_len = 0;
        self.clear_chat_notice();
        self.set_chat_menu_open(cx, false);
        self.release_composer_key_focus(cx);
        if self.recording_ui {
            let _ = host::voice_note_cancel();
            self.sync_recording_bar(cx);
        }
        script_eval!(cx, {
            mod.state.selected_pk = ""
            mod.state.selected_title = "Select a chat"
            mod.state.lines = []
            mod.state.transcript = ""
            ui.chat_title_label.set_text("Select a chat")
            ui.chat_log.render()
        });
        self.roster_ver = u64::MAX;
        self.refresh_roster(cx);
        self.apply_shell_layout(cx);
        self.hub_history.replace_top(self.hub_snapshot());
    }

    /// Contact-trust banner (Add / Block) for the open peer — visible only while
    /// `is_known` is false. Chrome only; ack policy lives in `ghalbol_core`.
    pub(crate) fn sync_trust_banner(&mut self, cx: &mut Cx, roster: &[RosterEntry]) {
        let unknown = !self.open_peer.is_empty()
            && roster
                .iter()
                .find(|r| peer_public_key_eq(&r.public_key_hex, &self.open_peer))
                .map(|r| !r.is_known && !r.is_blocked)
                .unwrap_or(false);
        let banner = self.ui.view(cx, ids!(trust_banner));
        if banner.visible() != unknown {
            banner.set_visible(cx, unknown);
            self.ui.view(cx, ids!(chat_col)).redraw(cx);
        }
    }

    /// True when the last rendered chat row sits within ~140 px of the visible
    /// bottom of `chat_log` (Flutter `_stickToBottomThreshold`), or nothing is drawn yet.
    pub(crate) fn chat_log_near_bottom(&self, cx: &mut Cx) -> bool {
        let log = self.ui.view(cx, ids!(chat_log));
        let log_rect = log.area().rect(cx);
        if log_rect.size.y <= 0.0 {
            return true;
        }
        let Some(inner) = log.borrow_mut() else {
            return true;
        };
        let Some((_, last)) = inner.children.last() else {
            return true;
        };
        let last_rect = last.area().rect(cx);
        if last_rect.size.y <= 0.0 {
            return true;
        }
        last_rect.pos.y + last_rect.size.y <= log_rect.pos.y + log_rect.size.y + 140.0
    }

    /// Scroll `chat_log` to its end once the new content height is known.
    /// `set_scroll_pos` clamps to the *last drawn* total, so an immediate call
    /// after `render()` stops short — re-apply on the next two frames.
    pub(crate) fn pin_chat_bottom(&mut self, cx: &mut Cx) {
        self.pin_chat_frames = 2;
        self.ui
            .view(cx, ids!(chat_log))
            .set_scroll_pos(cx, dvec2(0.0, 1.0e9));
        let _ = cx.new_next_frame();
    }

    pub(crate) fn apply_chat_pin_frame(&mut self, cx: &mut Cx) {
        if self.pin_chat_frames == 0 {
            return;
        }
        self.pin_chat_frames -= 1;
        self.ui
            .view(cx, ids!(chat_log))
            .set_scroll_pos(cx, dvec2(0.0, 1.0e9));
        if self.pin_chat_frames > 0 {
            let _ = cx.new_next_frame();
        }
    }

    pub(crate) fn refresh_transcript(&mut self, cx: &mut Cx) {
        let Some(session) = self.session.clone() else {
            return;
        };
        if self.open_peer.is_empty() {
            return;
        }
        self.chat_rev = host::transcript_revision(&self.namespace, &self.open_peer);
        let page = match host::load_transcript(&session.app_namespace, &self.open_peer, self.transcript_limit()) {
            Ok(page) => page,
            Err(e) => {
                let err = clamp_ui_display_line(&format!("Could not load chat: {e}"));
                if preserve_transcript_on_load_error(self.chat_lines_len) {
                    self.show_chat_error(cx, err);
                    return;
                }
                self.chat_lines_len = 0;
                script_eval!(cx, {
                    mod.state.transcript = #(err)
                    mod.state.lines = []
                    ui.chat_log.render()
                });
                return;
            }
        };
        // Stick-to-bottom (Flutter): a freshly opened room always lands on the
        // newest line; a grown transcript follows only if the user was already
        // near the end — never yank someone reading older history.
        let room_changed = self.chat_lines_peer != self.open_peer;
        // Same-room refresh with 0 rows: keep the painted chat (DESIGN.md / AGENTS
        // anti-pattern — empty merge must not clear an open room mid-session).
        if keep_painted_transcript(page.lines.len(), room_changed, self.chat_lines_len) {
            return;
        }
        let empty = if page.lines.is_empty() {
            "No messages yet".to_string()
        } else {
            String::new()
        };
        self.has_more = page.has_more;
        self.ui
            .widget(cx, ids!(older_button))
            .set_visible(cx, self.has_more);
        let grew = page.lines.len() > self.chat_lines_len;
        let follow = room_changed || (grew && self.chat_log_near_bottom(cx));
        self.chat_lines_peer = self.open_peer.clone();
        self.chat_lines_len = page.lines.len();
        let peer_title =
            roster_title_for_key(&self.roster_rows, &self.open_peer)
                .unwrap_or_else(|| short_key(&self.open_peer));
        script_eval!(cx, {
            mod.state.transcript = #(empty)
            mod.state.lines = []
            true
        });
        let playing = host::voice_play_progress();
        for line in page.lines {
            let mut bubble = bubble_of(&line, &peer_title);
            if line.kind == "voice"
                && let Some((ref path, elapsed, duration)) = playing
                && !line.audio_path.is_empty()
                && line.audio_path == *path
            {
                bubble.body = format!(
                    "■  Voice note  {} / {}",
                    format_mmss(elapsed),
                    format_mmss(duration.max(1))
                );
                bubble.detail = "Playing".into();
            }
            let body = bubble.body;
            let detail = bubble.detail;
            let caption = bubble.caption;
            let tick = bubble.tick;
            let read = if bubble.read {
                "1"
            } else if bubble.failed {
                "failed"
            } else {
                "0"
            };
            let side = if line.outgoing { "out" } else { "in" };
            let open = if line.kind == "voice" && !line.audio_path.is_empty() {
                line.audio_path.clone()
            } else if !line.local_path.is_empty() {
                line.local_path.clone()
            } else if line.kind == "attachment_offer" && !line.message_id.is_empty() {
                line.message_id.clone()
            } else {
                String::new()
            };
            let (open, action) = if line.outgoing
                && line.delivery == "failed"
                && !line.message_id.is_empty()
                && (line.kind == "text"
                    || line.kind.is_empty()
                    || line.kind == "voice"
                    || (line.kind == "attachment_offer" && !line.local_path.is_empty()))
            {
                (line.message_id.clone(), "resend".to_string())
            } else if line.kind == "voice" && !line.audio_path.is_empty() {
                (open, "voice".to_string())
            } else if line.kind == "attachment_offer" && line.local_path.is_empty() && !line.message_id.is_empty() {
                (line.message_id.clone(), "fetch".to_string())
            } else if line.kind == "attachment_offer" && !line.local_path.is_empty() {
                (open, "file".to_string())
            } else if !open.is_empty() && line.kind != "text" {
                (open, "file".to_string())
            } else {
                (open, String::new())
            };
            let body = if action == "resend" {
                format!(
                    "{body}\n{}",
                    i18n::phrase(&self.lang, "tap_to_resend")
                )
            } else {
                body
            };
            script_eval!(cx, {
                mod.state.lines.push({
                    body: #(body)
                    detail: #(detail)
                    caption: #(caption)
                    tick: #(tick)
                    read: #(read)
                    side: #(side)
                    path: #(open)
                    action: #(action)
                })
                true
            });
        }
        script_eval!(cx, { ui.chat_log.render() });
        if follow {
            self.pin_chat_bottom(cx);
        }
    }

    pub(crate) fn refresh_roster(&mut self, cx: &mut Cx) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let ver = host::contacts_version();
        if ver == self.roster_ver && self.roster_query == self.search {
            return;
        }
        let Ok(roster) = host::list_roster(&self.namespace) else {
            // Transient native error — keep the painted roster and retry on the next bump.
            return;
        };
        self.roster_ver = ver;
        self.roster_query = self.search.clone();
        let self_line = format!("You  {}", short_key(&session.public_key_hex));
        script_eval!(cx, {
            mod.state.self_line = #(self_line)
            mod.state.roster = []
            true
        });
        self.push_roster_rows(cx, roster);
        script_eval!(cx, { ui.roster_list.render() });
    }

    /// Fill `mod.state.roster` (and `self.roster_rows`) from the native roster:
    /// blocked peers are hidden, the search filter applies, and each row carries
    /// the fields `RosterRow` renders. Also syncs the open room's trust banner.
    pub(crate) fn push_roster_rows(&mut self, cx: &mut Cx, roster: Vec<RosterEntry>) {
        self.sync_trust_banner(cx, &roster);
        self.roster_rows.clear();
        let searching = !self.search.trim().is_empty();
        let mut shown = 0usize;
        for row in roster
            .into_iter()
            .filter(|row| !row.is_blocked && roster_matches(row, &self.search))
        {
            let title = row.title.clone();
            let pk = row.public_key_hex.clone();
            let initial = roster_initial(&row);
            let status = row.availability.clone();
            let preview = if row.preview.is_empty() {
                "Tap to open chat".to_string()
            } else {
                row.preview.clone()
            };
            let unknown = if row.is_known { "0" } else { "1" };
            let unread = row.unread.to_string();
            self.roster_rows.push((pk.clone(), title.clone()));
            shown += 1;
            script_eval!(cx, {
                mod.state.roster.push({
                    title: #(title)
                    initial: #(initial)
                    status: #(status)
                    preview: #(preview)
                    unknown: #(unknown)
                    pk: #(pk)
                    unread: #(unread)
                })
                true
            });
        }
        // Flutter empty-search copy — distinguish "no chats" from "no match".
        let (empty_title, empty_body) = if shown == 0 && searching {
            (
                "No matches".to_string(),
                "Try a different search.".to_string(),
            )
        } else {
            (
                "No chats yet".to_string(),
                "Scan a QR or paste an invitation to start a 1:1 chat.".to_string(),
            )
        };
        script_eval!(cx, {
            mod.state.roster_empty_title = #(empty_title)
            mod.state.roster_empty_body = #(empty_body)
        });
    }

    pub(crate) fn push_settings_pane(&self, cx: &mut Cx) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let blurb = "QR and invitation links encode your identity public key — not IP addresses. After someone adds you, the app finds you via coordination, same Wi‑Fi, or when you connect to them.".to_string();
        let detail = format!(
            "Namespace: {}\nIdentity (share this):\n{}",
            session.app_namespace, session.public_key_hex
        );
        let self_line = format!("You  {}", short_key(&session.public_key_hex));
        let display = host::local_display_name(&session.app_namespace);
        script_eval!(cx, {
            mod.state.identity_blurb = #(blurb)
            mod.state.identity_detail = #(detail)
            mod.state.self_line = #(self_line)
            ui.display_name_input.set_text(#(display))
        });
    }

    pub(crate) fn apply_shell_widths(&mut self, cx: &mut Cx, window_w: f64) {
        self.window_w = window_w;
        self.apply_shell_layout(cx);
    }

    pub(crate) fn submit_send(&mut self, cx: &mut Cx) {
        // Prefer live widget text — self.composer can lag behind Android IME.
        let typed = self.ui.text_input(cx, ids!(composer)).text();
        if !typed.is_empty() {
            self.composer = typed;
        }
        let peer = self.open_peer.clone();
        if let Some(msg) = send_text_block_reason(
            self.session.is_some(),
            self.ui_locked,
            peer.is_empty(),
        ) {
            self.show_chat_error(cx, msg.into());
            return;
        }
        let text = self.composer.trim().to_string();
        if text.is_empty() {
            return;
        }
        if text.len() > host::MAX_TEXT_DM_BYTES {
            self.show_chat_error(
                cx,
                format!(
                    "Message is too long (max {} KB).",
                    host::MAX_TEXT_DM_BYTES / 1024
                ),
            );
            return;
        }
        match host::send_text(&peer, &text) {
            Ok(()) => {
                self.composer.clear();
                script_eval!(cx, { ui.composer.set_text("") });
                self.clear_chat_notice();
                self.delivery_hint = host::delivery_offline_hint().unwrap_or_default();
                self.refresh_transcript(cx);
                self.refresh_call_line(cx);
                // Own send always lands on the new line (Flutter `force: true`).
                self.pin_chat_bottom(cx);
            }
            Err(e) => {
                self.show_chat_error(cx, e);
            }
        }
    }

    pub(crate) fn drain_events(&mut self, cx: &mut Cx) {
        let mut dirty = false;
        let mut wake_call = false;
        let mut wake_unlock = false;
        while let Some(ev) = host::poll_event() {
            match ev.get("kind").and_then(|v| v.as_str()) {
                Some("incoming_call_wake") => wake_call = true,
                Some("unlock_wake") => wake_unlock = true,
                _ => dirty = true,
            }
        }
        if wake_unlock && self.session.is_none() {
            script_eval!(cx, {
                mod.state.screen = "identity"
                ui.identity_view.set_visible(true)
                ui.hub_view.set_visible(false)
                ui.call_view.set_visible(false)
                ui.identity_copy.render()
            });
            self.set_screen(cx, "identity");
        }
        if self.session.is_none() {
            return;
        }
        if wake_call || dirty {
            self.refresh_call_line(cx);
        }
        if self.ui_locked {
            if self.page == "scan" {
                self.refresh_qr_preview(cx);
                self.take_qr(cx);
            }
            return;
        }
        if self.page.is_empty() {
            // Roster only when contacts_version moved (refresh_roster no-ops otherwise).
            self.refresh_roster(cx);
            if !self.open_peer.is_empty() {
                // Transcript only when the open room's in-memory revision moved —
                // never full re-render every poll tick (that fought IME / scroll).
                let rev = host::transcript_revision(&self.namespace, &self.open_peer);
                if rev != self.chat_rev {
                    self.refresh_transcript(cx);
                }
                self.maybe_autoload_older(cx);
            }
        }
        if self.recording_ui || host::voice_note_recording() {
            self.sync_recording_bar(cx);
        }
        // Voice-note play progress (VOICE_MESSAGES_PLAN optional progress follow-up).
        match host::voice_play_progress() {
            Some((_, elapsed, _)) => {
                let sec = elapsed / 1000;
                if !self.voice_playing_ui || sec != self.voice_play_tick_sec {
                    self.voice_playing_ui = true;
                    self.voice_play_tick_sec = sec;
                    if !self.open_peer.is_empty() && self.page.is_empty() {
                        self.refresh_transcript(cx);
                    }
                }
            }
            None if self.voice_playing_ui => {
                self.voice_playing_ui = false;
                self.voice_play_tick_sec = 0;
                if !self.open_peer.is_empty() && self.page.is_empty() {
                    self.refresh_transcript(cx);
                }
            }
            None => {}
        }
        self.refresh_video(cx);
        self.refresh_qr_preview(cx);
        self.take_qr(cx);
    }

    /// Flutter scroll-up: when the user reaches the top of `chat_log` and the
    /// store still has older pages, load the next page without yanking the
    /// viewport (stick-to-bottom stays off because `grew` near-bottom is false).
    pub(crate) fn maybe_autoload_older(&mut self, cx: &mut Cx) {
        if !self.has_more || self.open_peer.is_empty() {
            return;
        }
        let log = self.ui.view(cx, ids!(chat_log));
        let log_rect = log.area().rect(cx);
        let Some(inner) = log.borrow_mut() else {
            return;
        };
        // Skip call_label (child 0); the first message row is usually child 1.
        let Some((_, first)) = inner.children.get(1).or_else(|| inner.children.first()) else {
            return;
        };
        let first_rect = first.area().rect(cx);
        // At top when the first message sits at/above the visible top edge.
        if first_rect.pos.y < log_rect.pos.y - 8.0 {
            return;
        }
        drop(inner);
        let prev_limit = self.transcript_limit();
        self.window_limit = prev_limit.saturating_add(50).max(50);
        if self.window_limit == prev_limit {
            return;
        }
        self.refresh_transcript(cx);
    }

    pub(crate) fn refresh_video(&mut self, cx: &mut Cx) {
        if !self.call_open {
            return;
        }
        let show_video = host::call_shows_video();
        self.ui
            .widget(cx, ids!(video_row))
            .set_visible(cx, show_video);
        self.ui
            .widget(cx, ids!(call_peer_block))
            .set_visible(cx, !show_video);
        if !show_video {
            return;
        }
        let (local, remote) = host::call_picture_rgbas();
        if let Some((w, h, rgba)) = local {
            let texture = rgba_to_bgra_texture(cx, w, h, &rgba);
            let image = self.ui.image(cx, ids!(local_video));
            image.set_texture(cx, Some(texture));
            self.ui.widget(cx, ids!(local_video)).redraw(cx);
        }
        if let Some((w, h, rgba)) = remote {
            let texture = rgba_to_bgra_texture(cx, w, h, &rgba);
            let image = self.ui.image(cx, ids!(remote_video));
            image.set_texture(cx, Some(texture));
            self.ui.widget(cx, ids!(remote_video)).redraw(cx);
        }
    }

    pub(crate) fn end_qr_scan_ui(&mut self) {
        host::set_qr_scan_ui_active(false);
        host::stop_qr_scan();
    }

    pub(crate) fn refresh_qr_preview(&mut self, cx: &mut Cx) {
        if self.page != "scan" {
            return;
        }
        let Some((w, h, rgba)) = host::take_qr_preview_rgba() else {
            return;
        };
        // Live path: raw BGRA texture, no PNG, no mipmaps. `load_png_from_data` on
        // Linux builds a mip chain per frame and skips redraw outside draw events —
        // that is why the camera log showed ~30fps while the UI looked frozen.
        let texture = rgba_to_bgra_texture(cx, w, h, &rgba);
        let image = self.ui.image(cx, ids!(scan_preview));
        image.set_texture(cx, Some(texture));
        // set_texture only auto-redraws inside a draw event; Signal polls need this.
        self.ui.widget(cx, ids!(scan_preview)).redraw(cx);
    }

    /// After a successful invite accept, land on Chats with the new room open.
    pub(crate) fn open_joined_peer_chat(&mut self, cx: &mut Cx, pk: &str) {
        self.set_hub_tab(cx, 0);
        let pk = canonical_peer_key(pk);
        self.open_peer = pk.clone();
        self.refresh_roster(cx);
        let title = roster_title_for_key(&self.roster_rows, &pk)
            .unwrap_or_else(|| short_key(&pk));
        let pk_script = pk.to_string();
        let title_script = title.clone();
        script_eval!(cx, {
            mod.state.selected_pk = #(pk_script)
            mod.state.selected_title = #(title_script)
            mod.state.open_gen = mod.state.open_gen + 1
            ui.chat_title_label.set_text(#(title))
        });
        self.sync_open_chat(cx);
    }

    pub(crate) fn take_qr(&mut self, cx: &mut Cx) {
        let Some(result) = host::take_qr_scan() else {
            return;
        };
        let ns = self.namespace.clone();
        match result.and_then(|text| host::accept_invite(&ns, &text)) {
            Ok(pk) => {
                host::set_qr_scan_ui_active(false);
                let line = join_accept_status_line(&pk);
                // Leave the scan sheet and open the new chat on the Chats tab.
                self.close_sheet(cx);
                self.open_joined_peer_chat(cx, &pk);
                self.show_call_line(cx, line);
            }
            Err(e) if e == "Scan stopped" => {
                // Back / leaving the sheet — not an error for the user.
            }
            Err(e) => {
                // Camera already stopped on Ready; offer Scan again on the sheet.
                if self.page == "scan" {
                    script_eval!(cx, {
                        mod.state.sheet_body = #(e.clone())
                        ui.sheet_copy.render()
                    });
                    self.sync_sheet_body_text(cx, &e);
                } else {
                    self.show_chat_error(cx, e);
                }
            }
        }
    }

    pub(crate) fn refresh_call_line(&mut self, cx: &mut Cx) {
        let call = host::call_banner();
        host::note_call_banner(&call);
        let calling = !call.is_empty();
        if host::delivery_offline_hint().is_none() {
            self.delivery_hint.clear();
        }
        if let Some(qw) = host::take_delivery_quota_warning() {
            self.delivery_hint = qw;
        }
        // Accept is callee-only. Showing it on an outbound dial made the caller
        // think the app was asking them to accept their own call.
        let incoming = host::call_is_incoming_ringing();
        self.ui
            .widget(cx, ids!(accept_call_button))
            .set_visible(cx, calling && incoming);
        let end_label = if incoming {
            i18n::phrase(&self.lang, "decline")
        } else {
            i18n::text(&self.lang, i18n::Key::EndCall).to_string()
        };
        let peer_label = host::call_peer_label();
        let initial = call_avatar_initial(&peer_label);
        self.paint_chat_status_line(cx, &call);
        script_eval!(cx, {
            ui.end_call_button.set_text(#(end_label))
            ui.call_peer_name.set_text(#(peer_label))
            ui.call_initial.set_text(#(initial))
            ui.call_copy.render()
        });
        if calling {
            self.refresh_video(cx);
        }
        if calling == self.call_open && !needs_call_shell_reconcile(calling, self.call_view_visible)
        {
            if calling {
                self.ui.widget(cx, ids!(call_view)).redraw(cx);
            }
            return;
        }
        self.call_open = calling;
        if calling {
            script_eval!(cx, {
                ui.identity_view.set_visible(false)
                ui.hub_view.set_visible(false)
                ui.sheet_view.set_visible(false)
                ui.call_view.set_visible(true)
                ui.call_copy.render()
            });
            self.set_screen(cx, "call");
            self.refresh_video(cx);
        } else if self.session.is_some() && !self.ui_locked {
            self.ui
                .widget(cx, ids!(video_row))
                .set_visible(cx, false);
            if self.page.is_empty() {
                script_eval!(cx, {
                    ui.call_view.set_visible(false)
                    ui.sheet_view.set_visible(false)
                    ui.hub_view.set_visible(true)
                });
                self.set_screen(cx, "hub");
            } else {
                script_eval!(cx, {
                    ui.call_view.set_visible(false)
                    ui.hub_view.set_visible(false)
                    ui.sheet_view.set_visible(true)
                    ui.sheet_copy.render()
                });
                self.set_screen(cx, "sheet");
            }
        } else {
            script_eval!(cx, {
                ui.call_view.set_visible(false)
                ui.identity_view.set_visible(true)
            });
            self.set_screen(cx, "identity");
        }
    }
}

/// User-facing line after accepting an invite (unit-tested).
pub(crate) fn join_accept_status_line(pk: &str) -> String {
    format!("Joined {}", short_key(pk))
}

/// Skip a full transcript reload when the user re-taps the same open room.
pub(crate) fn should_refresh_transcript_on_open(
    peer_changed: bool,
    rev: u64,
    chat_rev: u64,
    painted_peer: &str,
    open_peer: &str,
) -> bool {
    peer_changed || rev != chat_rev || painted_peer != open_peer
}

#[cfg(test)]
mod join_flow_tests {
    use super::{join_accept_status_line, should_refresh_transcript_on_open};

    #[test]
    fn join_status_uses_short_key_not_full_hex() {
        let pk = "ab".repeat(32);
        let line = join_accept_status_line(&pk);
        assert!(line.starts_with("Joined "));
        assert!(!line.contains(&pk));
        assert!(line.len() < pk.len() + 8);
    }

    #[test]
    fn same_room_reselect_skips_transcript_reload() {
        let pk = "aa".repeat(32);
        assert!(!should_refresh_transcript_on_open(false, 5, 5, &pk, &pk));
    }

    #[test]
    fn peer_change_or_revision_bump_refreshes() {
        let pk = "aa".repeat(32);
        assert!(should_refresh_transcript_on_open(true, 5, 5, &pk, &pk));
        assert!(should_refresh_transcript_on_open(false, 6, 5, &pk, &pk));
        assert!(should_refresh_transcript_on_open(false, 5, 5, "other", &pk));
    }
}
