//! MatchEvent / action routing for the Makepad shell.
use makepad_widgets::*;
use ghalbol_core::host;
use crate::App;
use crate::chat_helpers::*;
use crate::i18n;

impl MatchEvent for App {
    fn handle_back_pressed(&mut self, cx: &mut Cx) -> bool {
        self.navigate_back(cx, true)
    }

    fn handle_actions(&mut self, cx: &mut Cx, actions: &Actions) {
        #[cfg(target_os = "android")]
        for action in actions {
            if let Some(answer) = android_pick::answer(action) {
                self.on_android_pick(cx, answer);
            }
        }
        self.sync_algorithm(cx);
        if let Some(text) = self.ui.text_input(cx, ids!(password_input)).changed(actions) {
            self.password = text;
        }
        if let Some(text) = self.ui.text_input(cx, ids!(composer)).changed(actions) {
            self.composer = text;
        }
        let unlock = self.ui.button(cx, ids!(unlock_button)).clicked(actions)
            || self
                .ui
                .text_input(cx, ids!(password_input))
                .returned(actions)
                .is_some();
        if unlock {
            if let Some((text, _)) = self
                .ui
                .text_input(cx, ids!(password_input))
                .returned(actions)
            {
                self.password = text;
            }
            self.submit_unlock(cx);
        }
        if let Some(text) = self.ui.text_input(cx, ids!(secret_input)).changed(actions) {
            self.secret = text;
        }
        if self.ui.button(cx, ids!(password_eye)).clicked(actions) {
            self.toggle_secret_field(cx, ids!(password_input), ids!(password_eye));
        }
        if self.ui.button(cx, ids!(secret_eye)).clicked(actions) {
            self.toggle_secret_field(cx, ids!(secret_input), ids!(secret_eye));
        }
        if self.ui.button(cx, ids!(paste_eye)).clicked(actions) {
            self.toggle_secret_field(cx, ids!(paste_input), ids!(paste_eye));
        }
        if self.ui.button(cx, ids!(pk_eye)).clicked(actions) {
            self.toggle_secret_field(cx, ids!(pk_input), ids!(pk_eye));
        }
        if self.ui.button(cx, ids!(alias_eye)).clicked(actions) {
            self.toggle_secret_field(cx, ids!(alias_input), ids!(alias_eye));
        }
        if let Some(text) = self.ui.text_input(cx, ids!(search_input)).changed(actions) {
            self.search = text;
            if self.page.is_empty() && self.session.is_some() {
                self.refresh_roster(cx);
            }
        }
        if let Some(text) = self.ui.text_input(cx, ids!(paste_input)).changed(actions) {
            self.paste = text;
        }
        if let Some(text) = self.ui.text_input(cx, ids!(pk_input)).changed(actions) {
            self.add_pk = text;
        }
        if let Some(text) = self.ui.text_input(cx, ids!(alias_input)).changed(actions) {
            self.add_alias = text;
        }
        if self.ui.button(cx, ids!(mode_button)).clicked(actions) {
            self.create_new = !self.create_new;
            self.push_identity_copy(cx);
        }
        if self.ui.button(cx, ids!(algo_secp)).clicked(actions) {
            self.algorithm = "secp256k1".into();
            self.mark_algorithm(cx);
        }
        if self.ui.button(cx, ids!(algo_ed)).clicked(actions) {
            self.algorithm = "ed25519".into();
            self.mark_algorithm(cx);
        }
        if self.ui.button(cx, ids!(algo_p256)).clicked(actions) {
            self.algorithm = "ecdsa-p256".into();
            self.mark_algorithm(cx);
        }
        if self.ui.button(cx, ids!(delete_button)).clicked(actions) {
            self.pull_password(cx);
            match host::delete_identity(&self.namespace, &self.password) {
                Ok(()) => {
                    self.session = None;
                    self.password.clear();
                    self.create_new = true;
                    script_eval!(cx, {
                        mod.state.status = "Identity deleted from this device"
                        ui.identity_copy.render()
                    });
                    self.push_identity_copy(cx);
                }
                Err(e) => {
                    script_eval!(cx, {
                        mod.state.status = #(e)
                        ui.identity_copy.render()
                    });
                }
            }
        }
        if self.ui.button(cx, ids!(import_backup_button)).clicked(actions) {
            self.pull_password(cx);
            #[cfg(target_os = "android")]
            {
                if self.password.is_empty() {
                    // Shows the "enter your password" hint.
                    self.open_import_backup_sheet(cx);
                } else {
                    let title = "Choose your keystore backup";
                    android_pick::open(cx, android_pick::BACKUP, title, None);
                }
            }
            #[cfg(not(target_os = "android"))]
            {
                match self.import_backup() {
                    Ok(session) => self.finish_import_backup(cx, session),
                    Err(e) => {
                        script_eval!(cx, {
                            mod.state.status = #(e)
                            ui.identity_copy.render()
                        });
                    }
                }
            }
        }
        if self.ui.button(cx, ids!(new_chat_button)).clicked(actions) {
            self.set_hub_tab(cx, 0);
            self.open_page(cx, "add");
        }
        if self.ui.button(cx, ids!(tab_chats)).clicked(actions)
            || self.ui.button(cx, ids!(tab_chats_on)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_chats)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_chats_on)).clicked(actions)
        {
            self.set_hub_tab(cx, 0);
        }
        if self.ui.button(cx, ids!(tab_contacts)).clicked(actions)
            || self.ui.button(cx, ids!(tab_contacts_on)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_contacts)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_contacts_on)).clicked(actions)
        {
            self.set_hub_tab(cx, 1);
        }
        if self.ui.button(cx, ids!(tab_invite)).clicked(actions)
            || self.ui.button(cx, ids!(tab_invite_on)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_invite)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_invite_on)).clicked(actions)
        {
            self.set_hub_tab(cx, 2);
        }
        if self.ui.button(cx, ids!(tab_settings)).clicked(actions)
            || self.ui.button(cx, ids!(tab_settings_on)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_settings)).clicked(actions)
            || self.ui.button(cx, ids!(bottom_settings_on)).clicked(actions)
        {
            self.push_settings_pane(cx);
            self.set_hub_tab(cx, 3);
        }
        if self.ui.button(cx, ids!(chat_back_button)).clicked(actions) {
            let _ = self.navigate_back(cx, false);
        }
        if self.ui.button(cx, ids!(invite_button)).clicked(actions) {
            self.open_page(cx, "invite");
        }
        if self.ui.button(cx, ids!(invite_button_id)).clicked(actions) {
            self.open_page(cx, "invite");
        }
        if self.ui.button(cx, ids!(invite_copy_button)).clicked(actions) {
            if let Some(session) = self.session.clone() {
                let alias = host::local_display_name(&self.namespace);
                let msg = match host::invite_links(
                    &session.public_key_hex,
                    if alias.is_empty() {
                        None
                    } else {
                        Some(alias.as_str())
                    },
                ) {
                    Ok((https, _)) => match copy_to_clipboard(cx, &https) {
                        Ok(()) => {
                            "Invitation copied. Paste it on the other device under Join.".to_string()
                        }
                        Err(e) => e,
                    },
                    Err(e) => e,
                };
                script_eval!(cx, { mod.state.identity_blurb = #(msg) });
            }
        }
        if self.ui.button(cx, ids!(key_copy_button)).clicked(actions) {
            if let Some(session) = self.session.clone() {
                let msg = match copy_to_clipboard(cx, &session.public_key_hex) {
                    Ok(()) => "Public key copied".to_string(),
                    Err(e) => e,
                };
                script_eval!(cx, { mod.state.identity_blurb = #(msg) });
            }
        }
        if self.ui.button(cx, ids!(join_button)).clicked(actions)
            || self.ui.button(cx, ids!(join_nav_button)).clicked(actions)
        {
            self.open_page(cx, "join");
        }
        if self.ui.button(cx, ids!(add_contact_button)).clicked(actions) {
            self.open_page(cx, "add");
        }
        if self.ui.button(cx, ids!(delivery_nav_button)).clicked(actions) {
            self.open_page(cx, "delivery");
        }
        if self.ui.button(cx, ids!(scan_button)).clicked(actions)
            || self.ui.button(cx, ids!(scan_nav_button)).clicked(actions)
        {
            self.open_page(cx, "scan");
            let msg = match host::start_qr_scan() {
                Ok(()) => "Point the camera at an invitation QR…".to_string(),
                Err(e) => e,
            };
            script_eval!(cx, {
                mod.state.sheet_body = #(msg.clone())
                ui.sheet_copy.render()
            });
            self.sync_sheet_body_text(cx, &msg);
        }
        if self.ui.button(cx, ids!(scan_file_button)).clicked(actions) {
            #[cfg(target_os = "android")]
            android_pick::open(
                cx,
                android_pick::QR_PICTURE,
                "Choose a QR picture",
                Some(("Pictures", &["png", "jpg", "jpeg"])),
            );
            #[cfg(not(target_os = "android"))]
            match rfd::FileDialog::new()
                .add_filter("Pictures", &["png", "jpg", "jpeg"])
                .pick_file()
            {
                Some(path) => self.join_from_qr_picture(cx, &path.display().to_string()),
                None => self.show_call_line(cx, "No picture chosen".into()),
            }
        }
        if self.ui.button(cx, ids!(contacts_button)).clicked(actions) {
            self.open_page(cx, "contacts");
        }
        if self.ui.button(cx, ids!(blocked_button)).clicked(actions) {
            self.open_page(cx, "blocked");
        }
        if self.ui.button(cx, ids!(about_button)).clicked(actions) {
            self.open_page(cx, "about");
        }
        if self.ui.button(cx, ids!(back_button)).clicked(actions) {
            let _ = self.navigate_back(cx, false);
        }
        if self.ui.button(cx, ids!(sheet_action)).clicked(actions) {
            self.sheet_go(cx);
        }
        if self.ui.button(cx, ids!(delivery_button)).clicked(actions) {
            self.open_page(cx, "delivery");
        }
        if self.ui.button(cx, ids!(log_button)).clicked(actions) {
            self.open_page(cx, "log");
        }
        if self.ui.button(cx, ids!(video_button)).clicked(actions) {
            let peer = self.open_peer.clone();
            if peer.is_empty() {
                script_eval!(cx, {
                    mod.state.call_line = "Select a chat first"
                    ui.chat_log.render()
                });
            } else if let Err(e) = host::start_video_call(&peer) {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.camera_on = true;
                // Open call chrome immediately — do not wait for a later poll event.
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(mute_button)).clicked(actions) {
            self.mic_muted = !self.mic_muted;
            let label = if self.mic_muted { "Unmute" } else { "Mute" };
            script_eval!(cx, { ui.mute_button.set_text(#(label)) });
            let muted = self.mic_muted;
            let msg = match host::set_mic_muted(muted) {
                Ok(()) => {
                    if muted {
                        "Microphone off".into()
                    } else {
                        "Microphone on".into()
                    }
                }
                Err(e) => e,
            };
            script_eval!(cx, {
                mod.state.call_line = #(msg)
                ui.chat_log.render()
            });
        }
        if self.ui.button(cx, ids!(speaker_button)).clicked(actions) {
            self.speaker_on = !self.speaker_on;
            let on = self.speaker_on;
            let label = if on {
                i18n::phrase(&self.lang, "speaker")
            } else {
                i18n::phrase(&self.lang, "speaker_off")
            };
            let msg = match host::set_speaker(on) {
                Ok(()) => label.clone(),
                Err(e) => e,
            };
            script_eval!(cx, {
                ui.speaker_button.set_text(#(label))
                mod.state.call_line = #(msg)
                ui.call_copy.render()
            });
        }
        if self.ui.button(cx, ids!(camera_button)).clicked(actions) {
            let on = !self.camera_on;
            let msg = match host::set_call_camera_enabled(on) {
                Ok(()) => {
                    self.camera_on = on;
                    if on {
                        i18n::phrase(&self.lang, "camera_on")
                    } else {
                        i18n::phrase(&self.lang, "camera_off")
                    }
                }
                Err(e) => e,
            };
            let label = if self.camera_on {
                i18n::phrase(&self.lang, "camera_on")
            } else {
                i18n::phrase(&self.lang, "camera_off")
            };
            script_eval!(cx, {
                ui.camera_button.set_text(#(label))
                mod.state.call_line = #(msg)
                ui.call_copy.render()
            });
        }
        if self.ui.button(cx, ids!(flip_camera_button)).clicked(actions) {
            let msg = match host::flip_call_camera() {
                Ok(()) => i18n::phrase(&self.lang, "flip_camera").to_string(),
                Err(e) => e,
            };
            script_eval!(cx, {
                mod.state.call_line = #(msg)
                ui.call_copy.render()
            });
        }
        if self.ui.button(cx, ids!(call_button)).clicked(actions) {
            let peer = self.open_peer.clone();
            if peer.is_empty() {
                script_eval!(cx, {
                    mod.state.call_line = "Select a chat first"
                    ui.chat_log.render()
                });
            } else if let Err(e) = host::start_voice_call(&peer) {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(accept_call_button)).clicked(actions) {
            if let Err(e) = host::accept_incoming_call() {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(end_call_button)).clicked(actions) {
            if let Err(e) = host::end_call() {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(status_available)).clicked(actions) {
            self.apply_status_preset(cx, "Available");
        }
        if self.ui.button(cx, ids!(status_busy)).clicked(actions) {
            self.apply_status_preset(cx, "Busy");
        }
        if self.ui.button(cx, ids!(status_away)).clicked(actions) {
            self.apply_status_preset(cx, "Away");
        }
        if self.ui.button(cx, ids!(status_call)).clicked(actions) {
            self.apply_status_preset(cx, "In a call");
        }
        if self.ui.button(cx, ids!(status_clear)).clicked(actions) {
            self.apply_status_preset(cx, "");
        }
        if self.ui.button(cx, ids!(trust_add_button)).clicked(actions)
            || self.ui.button(cx, ids!(menu_add_button)).clicked(actions)
        {
            self.set_chat_menu_open(cx, false);
            let peer = self.open_peer.clone();
            let msg = if peer.is_empty() {
                "Select a chat first".into()
            } else {
                match host::mark_known(&self.namespace, &peer) {
                    Ok(()) => "Added".into(),
                    Err(e) => e,
                }
            };
            script_eval!(cx, {
                mod.state.call_line = #(msg)
                ui.chat_log.render()
            });
            self.roster_ver = u64::MAX;
            self.refresh_roster(cx);
        }
        if self.ui.button(cx, ids!(trust_block_button)).clicked(actions)
            || self.ui.button(cx, ids!(menu_block_button)).clicked(actions)
        {
            self.set_chat_menu_open(cx, false);
            let peer = self.open_peer.clone();
            if !peer.is_empty() {
                let _ = host::set_blocked(&self.namespace, &peer, true);
                self.close_open_room(cx);
            }
        }
        if self.ui.button(cx, ids!(chat_menu_button)).clicked(actions) {
            let open = !self.chat_menu_open;
            self.set_chat_menu_open(cx, open);
        }
        if self.ui.button(cx, ids!(menu_call_button)).clicked(actions) {
            self.set_chat_menu_open(cx, false);
            let peer = self.open_peer.clone();
            if peer.is_empty() {
                script_eval!(cx, {
                    mod.state.call_line = "Select a chat first"
                    ui.chat_log.render()
                });
            } else if let Err(e) = host::start_voice_call(&peer) {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(menu_video_button)).clicked(actions) {
            self.set_chat_menu_open(cx, false);
            let peer = self.open_peer.clone();
            if peer.is_empty() {
                script_eval!(cx, {
                    mod.state.call_line = "Select a chat first"
                    ui.chat_log.render()
                });
            } else if let Err(e) = host::start_video_call(&peer) {
                script_eval!(cx, {
                    mod.state.call_line = #(e)
                    ui.chat_log.render()
                });
            } else {
                self.refresh_call_line(cx);
            }
        }
        if self.ui.button(cx, ids!(menu_share_button)).clicked(actions) {
            self.set_chat_menu_open(cx, false);
            self.open_page(cx, "invite");
        }
        if self.ui.button(cx, ids!(menu_join_button)).clicked(actions) {
            self.set_chat_menu_open(cx, false);
            self.open_page(cx, "join");
        }
        if self.ui.button(cx, ids!(menu_lock_button)).clicked(actions)
            || self.ui.button(cx, ids!(hub_lock_button)).clicked(actions)
        {
            self.set_chat_menu_open(cx, false);
            self.submit_lock(cx);
        }
        if self.ui.button(cx, ids!(record_discard_button)).clicked(actions) {
            self.cancel_voice_note(cx);
        }
        if self.ui.button(cx, ids!(record_send_button)).clicked(actions)
            || self.ui.button(cx, ids!(record_send_button)).pressed(actions)
        {
            // Stop + send (same as a second mic tap).
            self.toggle_voice_note(cx);
        }
        if self.ui.button(cx, ids!(choose_file_button)).clicked(actions) {
            let peer = self.open_peer.clone();
            if peer.is_empty() {
                self.show_call_line(cx, "Select a chat first".into());
            } else {
                #[cfg(target_os = "android")]
                android_pick::pick_attachment(cx, &peer);
                #[cfg(not(target_os = "android"))]
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    let sent = host::send_attachment(&peer, &path.display().to_string());
                    self.show_attach_result(cx, sent);
                }
            }
        }
        if self.ui.button(cx, ids!(key_button)).clicked(actions) {
            self.open_page(cx, "key");
        }
        if self.ui.button(cx, ids!(backup_button)).clicked(actions) {
            self.open_page(cx, "backup");
        }
        if self.ui.button(cx, ids!(password_button)).clicked(actions) {
            self.open_page(cx, "password");
        }
        if self.ui.button(cx, ids!(save_display_name_button)).clicked(actions) {
            let name = self.ui.text_input(cx, ids!(display_name_input)).text();
            let msg = match host::set_local_display_name(&self.namespace, &name) {
                Ok(()) => {
                    if name.trim().is_empty() {
                        "Display name cleared".to_string()
                    } else {
                        "Display name saved — new invitations include it".to_string()
                    }
                }
                Err(e) => e,
            };
            script_eval!(cx, { mod.state.identity_blurb = #(msg) });
        }
        if self.ui.button(cx, ids!(lock_button)).clicked(actions) {
            self.submit_lock(cx);
        }
        if self.ui.button(cx, ids!(logout_button)).clicked(actions) {
            self.submit_logout(cx);
        }
        if self.ui.button(cx, ids!(language_button)).clicked(actions) {
            self.open_languages(cx);
        }
        if self.ui.button(cx, ids!(older_button)).clicked(actions) {
            if self.has_more {
                self.window_limit = self.transcript_limit().saturating_add(50);
                self.refresh_transcript(cx);
            }
        }
        if self.ui.button(cx, ids!(record_button)).clicked(actions) {
            self.toggle_voice_note(cx);
        }
        // Send on Pressed (finger-down), not Clicked: with the IME up, Android
        // reflow can move the button before FingerUp so Clicked never fires.
        // IconGo keeps grab_key_focus false so this press does not dismiss IME
        // and wipe the composer. Soft-keyboard Send / desktop Enter use Returned.
        let send = self.ui.button(cx, ids!(send_button)).pressed(actions)
            || self
                .ui
                .text_input(cx, ids!(composer))
                .returned(actions)
                .is_some();
        if send {
            if let Some((text, _)) = self.ui.text_input(cx, ids!(composer)).returned(actions) {
                self.composer = text;
            }
            self.submit_send(cx);
        }
        self.sync_open_chat(cx);
        self.sync_play(cx);
        self.sync_language(cx);
    }
}
