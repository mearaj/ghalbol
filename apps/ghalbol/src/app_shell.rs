//! App methods (Makepad shell).
use makepad_widgets::*;
use ghalbol_core::host::{self};
use crate::App;
use crate::chat_helpers::*;
use crate::hub_history::*;
use crate::env_load::*;
use crate::i18n;

impl App {
    pub(crate) fn push_identity_copy(&mut self, cx: &mut Cx) {
        let exists = host::keystore_exists(&self.namespace);
        let primary = if exists {
            "Unlock"
        } else if self.create_new {
            "Create identity"
        } else {
            "Import identity"
        };
        let hint = if exists {
            "Enter your password to unlock this device. An app password encrypts your identity on this device and is never sent to a server."
        } else if self.create_new {
            "Choose a password and algorithm. An app password encrypts your identity on this device and is never sent to a server."
        } else {
            "Paste a private key and choose its algorithm (secp256k1, ed25519, or ecdsa-p256)."
        };
        let mode = if self.create_new {
            "Import an existing key"
        } else {
            "Create a new identity"
        };
        let setup = !exists && !self.ui_locked;
        let show_secret = setup && !self.create_new;
        let algo_line = if setup {
            format!("Algorithm: {}", self.algorithm)
        } else {
            String::new()
        };
        script_eval!(cx, {
            mod.state.hint = #(hint)
            mod.state.primary = #(primary)
            mod.state.algo_line = #(algo_line)
            ui.unlock_button.set_text(#(primary))
            ui.mode_button.set_text(#(mode))
            ui.mode_button.set_visible(#(setup))
            ui.secret_row.set_visible(#(show_secret))
            ui.algo_row.set_visible(#(setup))
            ui.delete_button.set_visible(#(exists))
            ui.import_backup_button.set_visible(#(setup))
            ui.identity_copy.render()
        });
        self.ui.widget(cx, ids!(mode_button)).set_visible(cx, setup);
        self.ui.widget(cx, ids!(secret_row)).set_visible(cx, show_secret);
        self.ui.widget(cx, ids!(algo_row)).set_visible(cx, setup);
        self.ui.widget(cx, ids!(delete_button)).set_visible(cx, exists);
        self.ui.widget(cx, ids!(import_backup_button)).set_visible(cx, setup);
        // Algo chips while creating or importing — never on unlock.
        if setup {
            self.mark_algorithm(cx);
            self.ui.widget(cx, ids!(algo_ed)).set_visible(cx, true);
            self.ui.widget(cx, ids!(algo_p256)).set_visible(cx, true);
        }
    }

    pub(crate) fn mark_algorithm(&self, cx: &mut Cx) {
        let secp = if self.algorithm == "secp256k1" {
            "secp256k1  [on]"
        } else {
            "secp256k1"
        };
        let ed = if self.algorithm == "ed25519" {
            "ed25519  [on]"
        } else {
            "ed25519"
        };
        let p256 = if self.algorithm == "ecdsa-p256" {
            "ecdsa-p256  [on]"
        } else {
            "ecdsa-p256"
        };
        let algo_line = format!("Algorithm: {}", self.algorithm);
        // Green chip on the active algo; Quiet white on the others.
        let (secp_on, ed_on, p256_on) = (
            self.algorithm == "secp256k1",
            self.algorithm == "ed25519",
            self.algorithm == "ecdsa-p256",
        );
        script_eval!(cx, {
            mod.state.algo_line = #(algo_line)
            ui.algo_secp.set_text(#(secp))
            ui.algo_ed.set_text(#(ed))
            ui.algo_p256.set_text(#(p256))
            ui.identity_copy.render()
        });
        self.style_algo_chip(cx, ids!(algo_secp), secp_on);
        self.style_algo_chip(cx, ids!(algo_ed), ed_on);
        self.style_algo_chip(cx, ids!(algo_p256), p256_on);
    }

    pub(crate) fn style_algo_chip(&self, cx: &mut Cx, path: &[LiveId], on: bool) {
        apply_algo_chip_style(cx, &mut self.ui.widget(cx, path), on);
    }

    pub(crate) fn set_screen(&mut self, cx: &mut Cx, screen: &str) {
        self.ui.widget(cx, ids!(identity_view)).set_visible(cx, screen == "identity");
        self.ui.widget(cx, ids!(hub_view)).set_visible(cx, screen == "hub");
        self.ui.widget(cx, ids!(sheet_view)).set_visible(cx, screen == "sheet");
        self.ui.widget(cx, ids!(call_view)).set_visible(cx, screen == "call");
        if screen == "hub" {
            self.set_hub_tab(cx, self.hub_tab);
        }
        // Only the screen that just became visible — redrawing all four roots
        // on every hop was the navigation stall, not APK size.
        let root = match screen {
            "identity" => ids!(identity_view),
            "hub" => ids!(hub_view),
            "sheet" => ids!(sheet_view),
            "call" => ids!(call_view),
            _ => return,
        };
        self.ui.widget(cx, root).redraw(cx);
    }

    pub(crate) fn set_hub_tab(&mut self, cx: &mut Cx, tab: u8) {
        let prev = self.hub_tab;
        if !self.history_suppress && prev != tab {
            // Pin the UI we are leaving (room, sheet page, …) as the tip before pushing.
            self.hub_history.replace_top(self.hub_snapshot());
        }
        self.hub_tab = tab;
        if tab != 0 {
            self.narrow_show_room = false;
            if !self.shell_split {
                host::set_open_room(None);
            }
        } else if self.shell_split && !self.open_peer.is_empty() {
            host::set_open_room(Some(&self.open_peer));
        } else if !self.shell_split && self.narrow_show_room && !self.open_peer.is_empty() {
            host::set_open_room(Some(&self.open_peer));
        }
        // 0 Chats · 1 Contacts · 2 Invite · 3 Settings (no More hub).
        let chats = tab == 0;
        self.ui.widget(cx, ids!(chats_pane)).set_visible(cx, chats);
        self.ui
            .widget(cx, ids!(contacts_pane))
            .set_visible(cx, tab == 1);
        self.ui
            .widget(cx, ids!(invite_pane))
            .set_visible(cx, tab == 2);
        self.ui
            .widget(cx, ids!(settings_pane))
            .set_visible(cx, tab == 3);
        self.paint_nav_tabs(cx);
        if !self.history_suppress && prev != tab {
            self.record_hub_nav();
        }
        self.apply_shell_layout(cx);
    }

    pub(crate) fn hub_snapshot(&self) -> HubHistoryEntry {
        HubHistoryEntry {
            hub_tab: self.hub_tab,
            narrow_show_room: self.narrow_show_room,
            conversation_key: self.open_peer.clone(),
            page: self.page.clone(),
        }
    }

    pub(crate) fn record_hub_nav(&mut self) {
        if self.history_suppress {
            return;
        }
        self.hub_history.record(self.hub_snapshot());
    }

    pub(crate) fn apply_hub_history(&mut self, cx: &mut Cx, entry: HubHistoryEntry) {
        self.history_suppress = true;
        self.open_peer = entry.conversation_key.clone();
        let pk = self.open_peer.clone();
        let title = if pk.is_empty() {
            "Select a chat".to_string()
        } else {
            // Roster display name when known (Flutter showed the alias, not the key).
            self.roster_rows
                .iter()
                .find(|(row_pk, _)| *row_pk == pk)
                .map(|(_, t)| t.clone())
                .unwrap_or_else(|| short_key(&pk))
        };
        let pk_script = pk.clone();
        let title_script = title.clone();
        script_eval!(cx, {
            mod.state.selected_pk = #(pk_script)
            mod.state.selected_title = #(title_script)
            ui.chat_title_label.set_text(#(title))
        });
        // Apply tab first (may clear narrow_show_room), then restore room flag.
        self.set_hub_tab(cx, entry.hub_tab);
        self.narrow_show_room = entry.narrow_show_room;
        if entry.hub_tab == 0
            && !pk.is_empty()
            && (entry.narrow_show_room || self.shell_split)
        {
            host::set_open_room(Some(&pk));
            self.refresh_transcript(cx);
        } else {
            host::set_open_room(None);
        }
        // Open-room wash + trust banner follow the restored room.
        self.roster_ver = u64::MAX;
        self.refresh_roster(cx);

        let want_page = entry.page.clone();
        if want_page.is_empty() {
            if !self.page.is_empty() {
                self.force_close_sheet(cx);
            } else if self.session.is_none() {
                self.set_screen(cx, "identity");
            }
        } else if want_page == "lang" {
            self.open_languages(cx);
        } else if want_page == "import_backup" {
            self.open_import_backup_sheet(cx);
        } else if want_page != self.page {
            self.open_page(cx, &want_page);
        }

        self.history_suppress = false;
        self.apply_shell_layout(cx);
    }

    /// Close sheet UI without the forced-backup re-prompt (history restore path).
    pub(crate) fn force_close_sheet(&mut self, cx: &mut Cx) {
        if self.page == "scan" {
            self.end_qr_scan_ui();
        }
        self.page.clear();
        let screen = if self.session.is_some() {
            "hub"
        } else {
            "identity"
        };
        let show_hub = screen == "hub";
        script_eval!(cx, {
            ui.sheet_view.set_visible(false)
            ui.call_view.set_visible(false)
            ui.hub_view.set_visible(#(show_hub))
            ui.identity_view.set_visible(#(!show_hub))
        });
        self.set_screen(cx, screen);
        if show_hub {
            self.refresh_roster(cx);
        }
    }

    /// One step of natural back (mouse side button, Android back/gesture, Escape, toolbar Back).
    ///
    /// Hub chrome uses a single browser-style history stack. Guards only for active call
    /// signalling and the forced first-time backup sheet. UI lock is dismissed as one step
    /// (not a hub history entry). Otherwise: `go_back` + apply. At root, `allow_quit` exits.
    pub(crate) fn navigate_back(&mut self, cx: &mut Cx, allow_quit: bool) -> bool {
        if self.call_open {
            match host::call_back_nav() {
                host::CallBackNav::Block => return true,
                host::CallBackNav::End => {
                    let _ = host::end_call();
                    self.refresh_call_line(cx);
                    return true;
                }
                host::CallBackNav::None => {}
            }
        }
        // First-time backup is required — back cannot leave until Save succeeds.
        if self.needs_backup {
            return true;
        }
        if self.ui_locked && self.session.is_some() {
            self.dismiss_ui_lock(cx);
            return true;
        }
        if self.hub_history.can_go_back() {
            let before = self.hub_snapshot();
            if let Some(prev) = self.hub_history.go_back() {
                self.apply_hub_history(cx, prev);
                if self.hub_snapshot() != before {
                    return true;
                }
                // Duplicate / no-op entry — keep walking so Back still moves.
                for _ in 0..8 {
                    let before = self.hub_snapshot();
                    let Some(prev) = self.hub_history.go_back() else {
                        break;
                    };
                    self.apply_hub_history(cx, prev);
                    if self.hub_snapshot() != before {
                        return true;
                    }
                }
            }
        }
        if allow_quit {
            let _ = host::end_call();
            cx.quit();
            return true;
        }
        false
    }

    /// Mouse forward / Alt+Right / browser-style forward through hub history.
    pub(crate) fn navigate_forward(&mut self, cx: &mut Cx) -> bool {
        if self.call_open || self.ui_locked || self.needs_backup {
            return false;
        }
        if self.session.is_none() {
            return false;
        }
        if let Some(next) = self.hub_history.go_forward() {
            self.apply_hub_history(cx, next);
            return true;
        }
        false
    }

    pub(crate) fn dismiss_ui_lock(&mut self, cx: &mut Cx) {
        if !self.ui_locked || self.session.is_none() {
            return;
        }
        self.ui_locked = false;
        self.password.clear();
        script_eval!(cx, {
            ui.password_input.set_text("")
            ui.identity_view.set_visible(false)
            ui.sheet_view.set_visible(false)
            ui.call_view.set_visible(false)
            ui.hub_view.set_visible(true)
        });
        self.configure_secret_field(cx, ids!(password_input), ids!(password_eye), true);
        self.set_screen(cx, "hub");
        self.refresh_roster(cx);
    }

    pub(crate) fn apply_shell_layout(&mut self, cx: &mut Cx) {
        // ≥720 → side rail + list + room; <720 → bottom tabs + stacked list/room.
        // Before the first WindowGeomChange, assume the Window design size (1180) so desktop
        // does not boot into the mobile chrome (missing sidebar).
        const DESIGN_DESKTOP_W: f64 = 1180.0;
        const SPLIT_BREAKPOINT: f64 = 720.0;
        let window_w = if self.window_w >= 1.0 {
            self.window_w
        } else {
            DESIGN_DESKTOP_W
        };
        let split = window_w >= SPLIT_BREAKPOINT;
        if self.shell_split && !split {
            self.narrow_show_room = false;
            host::set_open_room(None);
        }
        if !self.shell_split && split && !self.open_peer.is_empty() {
            host::set_open_room(Some(&self.open_peer));
        }
        self.shell_split = split;

        let on_hub = self.session.is_some() && !self.ui_locked;
        let chats = self.hub_tab == 0;
        let room_open = !self.open_peer.is_empty()
            && chats
            && (split || self.narrow_show_room);
        let show_rail = on_hub && split;
        let show_bottom = on_hub && !split && !(chats && self.narrow_show_room);
        let show_roster = chats && (split || !self.narrow_show_room);
        let show_chat = chats && room_open;
        let form_w = (window_w - 48.0).clamp(240.0, 360.0);
        let rail = if window_w >= 1100.0 { 220.0 } else { 176.0 };
        let roster_w = if split && show_chat {
            (window_w * 0.34).clamp(280.0, 400.0)
        } else {
            0.0
        };
        // Cheap fingerprint — geom spam / no-op tab presses must not repaint hub+identity.
        let sig = (window_w as u64)
            ^ ((self.hub_tab as u64) << 40)
            ^ ((on_hub as u64) << 44)
            ^ ((show_rail as u64) << 45)
            ^ ((show_bottom as u64) << 46)
            ^ ((show_roster as u64) << 47)
            ^ ((show_chat as u64) << 48)
            ^ ((self.narrow_show_room as u64) << 49)
            ^ ((self.ui_locked as u64) << 50)
            ^ ((form_w as u64) << 8)
            ^ ((rail as u64) << 20)
            ^ ((roster_w as u64) << 28);
        if sig == self.shell_layout_sig {
            return;
        }
        self.shell_layout_sig = sig;

        self.ui.view(cx, ids!(identity_column)).set_walk(
            cx,
            Walk {
                width: Size::Fixed(form_w),
                height: Size::fit(),
                ..Default::default()
            },
        );

        self.ui.widget(cx, ids!(nav_rail)).set_visible(cx, show_rail);
        self.ui.widget(cx, ids!(rail_divider)).set_visible(cx, show_rail);
        self.ui.widget(cx, ids!(bottom_nav)).set_visible(cx, show_bottom);
        self.ui.widget(cx, ids!(roster_col)).set_visible(cx, show_roster);
        self.ui.widget(cx, ids!(chat_col)).set_visible(cx, show_chat);
        self.ui.widget(cx, ids!(chat_back_button)).set_visible(cx, show_chat && !split);
        // Flutter puts Lock in the list AppBar on narrow; the side rail owns it on wide.
        self.ui
            .widget(cx, ids!(hub_lock_button))
            .set_visible(cx, on_hub && !show_rail);

        if show_rail {
            // Never use a skinny icon-only rail: peer labels ("Contacts", "Settings")
            // must fit with padding + nav marks. Wide windows get a roomier rail.
            self.ui.view(cx, ids!(nav_rail)).set_walk(
                cx,
                Walk {
                    width: Size::Fixed(rail),
                    height: Size::fill(),
                    ..Default::default()
                },
            );
        }
        if show_roster {
            let width = if roster_w > 0.0 {
                Size::Fixed(roster_w)
            } else {
                Size::fill()
            };
            self.ui.view(cx, ids!(roster_col)).set_walk(
                cx,
                Walk {
                    width,
                    height: Size::fill(),
                    ..Default::default()
                },
            );
        }
        if show_chat {
            self.ui.view(cx, ids!(chat_col)).set_walk(
                cx,
                Walk {
                    width: Size::fill(),
                    height: Size::fill(),
                    ..Default::default()
                },
            );
        }
        if on_hub && !chats {
            let pane = match self.hub_tab {
                1 => ids!(contacts_pane),
                2 => ids!(invite_pane),
                _ => ids!(settings_pane),
            };
            self.ui.view(cx, pane).set_walk(
                cx,
                Walk {
                    width: Size::fill(),
                    height: Size::fill(),
                    ..Default::default()
                },
            );
        }
        if on_hub {
            self.ui.widget(cx, ids!(hub_view)).redraw(cx);
        } else {
            self.ui.widget(cx, ids!(identity_view)).redraw(cx);
        }
    }

    pub(crate) fn pull_password(&mut self, cx: &mut Cx) {
        let live = self.ui.text_input(cx, ids!(password_input)).text();
        let live = live.trim();
        if !live.is_empty() {
            self.password = live.to_string();
        }
        let secret = self.ui.text_input(cx, ids!(secret_input)).text();
        let secret = secret.trim();
        if !secret.is_empty() {
            self.secret = secret.to_string();
        }
        self.sync_algorithm(cx);
    }

    pub(crate) fn sync_algorithm(&mut self, cx: &mut Cx) {
        let gen_val = script_eval!(cx, { mod.state.algo_gen });
        let algo_n = splash_f64(cx, gen_val);
        if algo_n == self.seen_algo || algo_n == 0.0 {
            return;
        }
        self.seen_algo = algo_n;
        let code_val = script_eval!(cx, { mod.state.algo });
        let code = splash_string(cx, code_val);
        if !code.is_empty() {
            self.algorithm = code;
        }
    }

    pub(crate) fn submit_unlock(&mut self, cx: &mut Cx) {
        load_env_once();
        self.pull_password(cx);
        let password = self.password.clone();
        if password.is_empty() {
            script_eval!(cx, {
                mod.state.status = "App password is required."
                ui.identity_copy.render()
            });
            return;
        }
        if self.ui_locked && self.session.is_some() {
            match host::reveal_secret(&self.namespace, &password) {
                Ok(_) => {
                    self.ui_locked = false;
                    self.password.clear();
                    let pk = self
                        .session
                        .as_ref()
                        .map(|s| s.public_key_hex.clone())
                        .unwrap_or_default();
                    self.show_hub(cx, &pk, "");
                }
                Err(e) => {
                    script_eval!(cx, {
                        mod.state.status = #(e)
                        ui.identity_copy.render()
                    });
                }
            }
            return;
        }
        let creating = !host::keystore_exists(&self.namespace) && self.create_new;
        let secret = if self.create_new { None } else { Some(self.secret.as_str()) };
        let algo = if host::keystore_exists(&self.namespace) {
            None
        } else {
            Some(self.algorithm.as_str())
        };
        match host::unlock_with_options(&self.namespace, &password, algo, secret) {
            Ok(session) => {
                self.password.clear();
                script_eval!(cx, { ui.password_input.set_text("") });
                self.configure_secret_field(cx, ids!(password_input), ids!(password_eye), true);
                self.configure_secret_field(cx, ids!(secret_input), ids!(secret_eye), true);
                let pk = session.public_key_hex.clone();
                let ns = session.app_namespace.clone();
                self.session = Some(session);
                if creating {
                    self.needs_backup = true;
                    self.show_sheet(
                        cx,
                        "backup",
                        "Save your backup",
                        "This identity exists only on this device until you export an encrypted backup. Save it, then keep the file and your app password together.".into(),
                        "Save backup",
                    );
                    return;
                }
                let net = host::start_network(&ns);
                let status = match &net {
                    Ok(_) => String::new(),
                    Err(e) => format!("Network: {e}"),
                };
                self.show_hub(cx, &pk, &status);
            }
            Err(e) => {
                script_eval!(cx, {
                    mod.state.status = #(e)
                    ui.identity_copy.render()
                });
            }
        }
    }

    pub(crate) fn take_pending_invite(&mut self) -> String {
        let raw = std::mem::take(&mut self.pending_invite);
        let raw = raw.trim();
        if raw.is_empty() {
            return String::new();
        }
        match host::accept_invite(&self.namespace, raw) {
            Ok(pk) => format!("Joined {}", short_key(&pk)),
            Err(e) => e,
        }
    }

    pub(crate) fn show_hub(&mut self, cx: &mut Cx, public_key_hex: &str, status: &str) {
        let joined = self.take_pending_invite();
        let status = if joined.is_empty() {
            status.to_string()
        } else if status.is_empty() {
            joined
        } else {
            format!("{status}\n{joined}")
        };
        let self_line = format!("You  {}", short_key(public_key_hex));
        let roster = host::list_roster(&self.namespace).unwrap_or_default();
        script_eval!(cx, {
            mod.state.screen = "hub"
            mod.state.status = #(status)
            mod.state.self_line = #(self_line)
            mod.state.selected_title = "Select a chat"
            mod.state.transcript = ""
            mod.state.roster = []
            ui.identity_view.set_visible(false)
            ui.sheet_view.set_visible(false)
            ui.hub_view.set_visible(true)
            true
        });
        self.push_roster_rows(cx, roster);
        script_eval!(cx, {
            ui.roster_list.render()
            ui.chat_log.render()
            ui.chat_title_label.set_text("Select a chat")
        });
        self.push_settings_pane(cx);
        self.apply_language(cx);
        self.hub_tab = 0;
        self.narrow_show_room = false;
        self.hub_history.reset(self.hub_snapshot());
        self.set_screen(cx, "hub");
        self.paint_nav_tabs(cx);
        self.apply_shell_layout(cx);
    }

    pub(crate) fn submit_lock(&mut self, cx: &mut Cx) {
        self.ui_locked = true;
        self.password.clear();
        script_eval!(cx, {
            mod.state.status = "Enter your password to show chats. The network stays connected."
            ui.hub_view.set_visible(false)
            ui.sheet_view.set_visible(false)
            ui.identity_view.set_visible(true)
            ui.identity_copy.render()
        });
        self.push_identity_copy(cx);
        self.set_screen(cx, "identity");
    }

    pub(crate) fn submit_logout(&mut self, cx: &mut Cx) {
        host::lock();
        self.session = None;
        self.ui_locked = false;
        self.open_peer.clear();
        self.composer.clear();
        self.password.clear();
        script_eval!(cx, {
            mod.state.screen = "identity"
            mod.state.status = ""
            mod.state.roster = []
            mod.state.selected_pk = ""
            mod.state.open_gen = 0
            ui.hub_view.set_visible(false)
            ui.sheet_view.set_visible(false)
            ui.identity_view.set_visible(true)
            ui.identity_copy.render()
        });
        self.seen_open_gen = 0.0;
        self.page.clear();
        self.push_identity_copy(cx);
        self.set_screen(cx, "identity");
    }

    /// Splash `text:` on read-only TextInput often skips relayout until resize.
    /// After `sheet_copy.render()`, push through `set_text` and redraw.
    pub(crate) fn sync_sheet_copy_text(&mut self, cx: &mut Cx, title: &str, body: &str) {
        self.ui.text_input(cx, ids!(sheet_title)).set_text(cx, title);
        self.sync_sheet_body_text(cx, body);
    }

    pub(crate) fn sync_sheet_body_text(&mut self, cx: &mut Cx, body: &str) {
        self.ui.text_input(cx, ids!(sheet_body)).set_text(cx, body);
        self.ui.widget(cx, ids!(sheet_body)).redraw(cx);
        self.ui.widget(cx, ids!(sheet_copy)).redraw(cx);
        self.ui.widget(cx, ids!(sheet_scroll)).redraw(cx);
        self.ui.widget(cx, ids!(sheet_view)).redraw(cx);
    }

    pub(crate) fn show_sheet(&mut self, cx: &mut Cx, page: &str, title: &str, body: String, action: &str) {
        if !self.history_suppress {
            // Pin hub/room under this sheet before page changes.
            self.hub_history.replace_top(self.hub_snapshot());
        }
        if self.page == "scan" && page != "scan" {
            self.end_qr_scan_ui();
        }
        self.page = page.to_string();
        if page == "scan" {
            host::set_qr_scan_ui_active(true);
        }
        let title = title.to_string();
        let action = action.to_string();
        let show_invite = page == "invite";
        let show_scan = page == "scan";
        let show_paste = matches!(
            page,
            "join" | "key" | "password" | "invite" | "import_backup" | "delivery"
        );
        let show_pk = matches!(page, "add" | "blocked" | "password");
        let show_alias = matches!(page, "add" | "about" | "password" | "contacts");
        let paste_secret = matches!(page, "key" | "password");
        let pk_secret = page == "password";
        let alias_secret = page == "password";
        let title_sync = title.clone();
        let body_sync = body.clone();
        script_eval!(cx, {
            mod.state.sheet_title = #(title)
            mod.state.sheet_body = #(body)
            mod.state.languages = []
            ui.sheet_action.set_text(#(action))
            ui.status_row.set_visible(false)
            ui.invite_frame.set_visible(#(show_invite))
            ui.scan_frame.set_visible(#(show_scan))
            ui.paste_row.set_visible(#(show_paste))
            ui.pk_row.set_visible(#(show_pk))
            ui.alias_row.set_visible(#(show_alias))
            ui.hub_view.set_visible(false)
            ui.sheet_view.set_visible(true)
            ui.sheet_copy.render()
        });
        self.sync_sheet_copy_text(cx, &title_sync, &body_sync);
        self.ui.widget(cx, ids!(status_row)).set_visible(cx, false);
        self.ui.widget(cx, ids!(invite_frame)).set_visible(cx, show_invite);
        self.ui.widget(cx, ids!(scan_frame)).set_visible(cx, show_scan);
        self.ui.widget(cx, ids!(paste_row)).set_visible(cx, show_paste);
        self.ui.widget(cx, ids!(pk_row)).set_visible(cx, show_pk);
        self.ui.widget(cx, ids!(alias_row)).set_visible(cx, show_alias);
        self.configure_secret_field(cx, ids!(paste_input), ids!(paste_eye), paste_secret);
        self.configure_secret_field(cx, ids!(pk_input), ids!(pk_eye), pk_secret);
        self.configure_secret_field(cx, ids!(alias_input), ids!(alias_eye), alias_secret);
        if paste_secret {
            self.ui
                .text_input(cx, ids!(paste_input))
                .set_empty_text(cx, "Current password".into());
        } else if page == "join" || page == "invite" {
            self.ui
                .text_input(cx, ids!(paste_input))
                .set_empty_text(cx, "Invitation link".into());
        } else if page == "import_backup" {
            self.ui
                .text_input(cx, ids!(paste_input))
                .set_empty_text(cx, "Paste keystore JSON backup".into());
        }
        if pk_secret {
            self.ui
                .text_input(cx, ids!(pk_input))
                .set_empty_text(cx, "Confirm new password".into());
            self.ui
                .text_input(cx, ids!(alias_input))
                .set_empty_text(cx, "New password".into());
        } else {
            if show_pk {
                self.ui
                    .text_input(cx, ids!(pk_input))
                    .set_empty_text(cx, "Public key".into());
            }
            if show_alias && page != "about" {
                self.ui
                    .text_input(cx, ids!(alias_input))
                    .set_empty_text(cx, "Display name".into());
            } else if show_alias {
                self.ui
                    .text_input(cx, ids!(alias_input))
                    .set_empty_text(cx, "Custom status".into());
            }
        }
        self.set_screen(cx, "sheet");
        self.record_hub_nav();
    }

    /// Mask a field and show a Show/Hide control, or clear masking for ordinary text.
    pub(crate) fn configure_secret_field(
        &mut self,
        cx: &mut Cx,
        input: &[LiveId],
        eye: &[LiveId],
        secret: bool,
    ) {
        let field = self.ui.text_input(cx, input);
        field.set_is_password(cx, secret);
        self.ui.widget(cx, eye).set_visible(cx, secret);
        if secret {
            self.ui.button(cx, eye).set_text(cx, "Show");
        }
    }

    pub(crate) fn toggle_secret_field(&mut self, cx: &mut Cx, input: &[LiveId], eye: &[LiveId]) {
        let field = self.ui.text_input(cx, input);
        field.toggle_is_password(cx);
        let label = if field.is_password() { "Show" } else { "Hide" };
        self.ui.button(cx, eye).set_text(cx, label);
    }

    pub(crate) fn open_page(&mut self, cx: &mut Cx, page: &str) {
        let Some(session) = self.session.clone() else {
            return;
        };
        let lang = self.lang.clone();
        let roster = host::list_roster(&self.namespace).unwrap_or_default();
        match page {
            "invite" => {
                let alias = host::local_display_name(&self.namespace);
                let links = host::invite_links(
                    &session.public_key_hex,
                    if alias.is_empty() {
                        None
                    } else {
                        Some(alias.as_str())
                    },
                )
                .unwrap_or_default();
                let body = "QR encodes your https://ghalbol.com invite (public key and display name). The other person taps Join and scans this code, or pastes the link.".to_string();
                self.show_sheet(
                    cx,
                    page,
                    "Your QR invitation",
                    body,
                    "Copy link",
                );
                self.paste = links.0.clone();
                self.ui.text_input(cx, ids!(paste_input)).set_text(cx, &links.0);
                if let Some(png) = qr_png(&links.0) {
                    let _ = self
                        .ui
                        .image(cx, ids!(invite_qr))
                        .load_png_from_data(cx, &png);
                }
            }
            "join" => self.show_sheet(
                cx,
                page,
                &i18n::phrase(&lang, "paste"),
                i18n::phrase(&lang, "paste_body"),
                &i18n::phrase(&lang, "join_go"),
            ),
            "scan" => {
                self.show_sheet(
                    cx,
                    page,
                    &i18n::phrase(&lang, "scan_qr"),
                    "Point the camera at a Ghal Bol invitation QR (https://ghalbol.com/connect/… or ghalbol://). Live preview below; scanning continues until an invite is read or you go Back.".into(),
                    "Scan again",
                );
                if let Some(png) = scan_placeholder_png() {
                    let _ = self
                        .ui
                        .image(cx, ids!(scan_preview))
                        .load_png_from_data(cx, &png);
                }
            }
            "add" => self.show_sheet(
                cx,
                page,
                &i18n::phrase(&lang, "add"),
                i18n::phrase(&lang, "add_body"),
                &i18n::phrase(&lang, "add_go"),
            ),
            "contacts" => {
                let body = roster
                    .iter()
                    .filter(|r| !r.is_blocked)
                    .map(|r| format!("{}  {}", r.title, short_key(&r.public_key_hex)))
                    .collect::<Vec<_>>()
                    .join("\n");
                let body = if body.is_empty() {
                    i18n::phrase(&lang, "none")
                } else {
                    body
                };
                let target = short_key(&self.open_peer);
                let body = if self.open_peer.is_empty() {
                    format!(
                        "{body}\n\nOpen a chat first to rename or remove that contact. Type a new name in Display name, then Save to rename; leave the name empty and Save to remove."
                    )
                } else {
                    format!(
                        "{body}\n\nOpen chat: {target}\nType a new name in Display name → Save to rename.\nClear the name and Save to remove."
                    )
                };
                self.show_sheet(
                    cx,
                    page,
                    &i18n::phrase(&lang, "contacts"),
                    body,
                    "Save",
                );
            }
            "blocked" => {
                let body = roster
                    .iter()
                    .filter(|r| r.is_blocked)
                    .map(|r| format!("{}  {}", r.title, r.public_key_hex))
                    .collect::<Vec<_>>()
                    .join("\n");
                let body = if body.is_empty() {
                    i18n::phrase(&lang, "blocked_empty")
                } else {
                    format!(
                        "{body}\n\n{}",
                        i18n::phrase(&lang, "blocked_help")
                    )
                };
                self.show_sheet(cx, page, &i18n::phrase(&lang, "blocked"), body, &i18n::phrase(&lang, "toggle"));
            }
            "delivery" => {
                self.show_sheet(
                    cx,
                    page,
                    &i18n::phrase(&lang, "delivery"),
                    host::delivery_summary(),
                    &i18n::phrase(&lang, "refresh"),
                );
                // Paste a message_id then Save to extend TTL (+7 days) while still queued.
            }
            "log" => {
                self.show_sheet(cx, page, &i18n::phrase(&lang, "log"), host::app_log_text(), &i18n::phrase(&lang, "refresh"));
            }
            "key" => self.show_sheet(
                cx,
                page,
                &i18n::phrase(&lang, "key"),
                i18n::phrase(&lang, "key_body"),
                &i18n::phrase(&lang, "show_key"),
            ),
            "backup" => self.show_sheet(
                cx,
                page,
                &i18n::phrase(&lang, "backup"),
                i18n::phrase(&lang, "backup_body"),
                &i18n::phrase(&lang, "save"),
            ),
            "password" => self.show_sheet(
                cx,
                page,
                &i18n::phrase(&lang, "password"),
                i18n::phrase(&lang, "password_body"),
                &i18n::phrase(&lang, "change"),
            ),
            "about" => {
                let status = host::availability_status();
                let status_line = if status.is_empty() {
                    i18n::phrase(&lang, "no_status")
                } else {
                    status.clone()
                };
                let body = format!(
                    "Ghal Bol\n{}\n\nYou  {}\n\n{}",
                    i18n::phrase(&lang, "about_body"),
                    short_key(&session.public_key_hex),
                    status_line
                );
                self.show_sheet(cx, page, &i18n::phrase(&lang, "about"), body, &i18n::phrase(&lang, "save_status"));
                self.add_alias = status;
                let custom = self.add_alias.clone();
                script_eval!(cx, { ui.status_row.set_visible(true) ui.sheet_copy.render() });
                self.ui.widget(cx, ids!(status_row)).set_visible(cx, true);
                self.ui.text_input(cx, ids!(alias_input)).set_text(cx, &custom);
            }
            _ => {}
        }
    }

    pub(crate) fn save_backup(&self) -> Result<String, String> {
        let json = host::export_keystore(&self.namespace)?;
        #[cfg(target_os = "android")]
        {
            return host::android_save_backup_json(&json);
        }
        #[cfg(not(target_os = "android"))]
        {
            let lang = self.lang.clone();
            let Some(path) = rfd::FileDialog::new()
                .set_file_name("ghalbol-keystore.json")
                .save_file()
            else {
                return Err(i18n::phrase(&lang, "must_save"));
            };
            std::fs::write(&path, json).map_err(|e| e.to_string())?;
            Ok(format!(
                "Saved {}. Keep this file and your app password. Older backups still use the password they were exported with.",
                path.display()
            ))
        }
    }

    pub(crate) fn finish_backup(&mut self, cx: &mut Cx, msg: String) {
        if !self.needs_backup {
            script_eval!(cx, {
                mod.state.sheet_body = #(msg.clone())
                ui.sheet_copy.render()
            });
            self.sync_sheet_body_text(cx, &msg);
            return;
        }
        self.needs_backup = false;
        let ns = self.namespace.clone();
        let status = match host::start_network(&ns) {
            Ok(_) => msg,
            Err(e) => format!("{msg}\nNetwork: {e}"),
        };
        let pk = self
            .session
            .as_ref()
            .map(|s| s.public_key_hex.clone())
            .unwrap_or_default();
        self.page.clear();
        self.show_hub(cx, &pk, &status);
    }

    #[cfg(not(target_os = "android"))]
    pub(crate) fn import_backup(&mut self) -> Result<host::UnlockedSession, String> {
        let lang = self.lang.clone();
        if self.password.is_empty() {
            return Err(i18n::phrase(&lang, "enter_password"));
        }
        let Some(path) = rfd::FileDialog::new().pick_file() else {
            return Err(i18n::phrase(&lang, "choose_file"));
        };
        let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        host::import_keystore(&self.namespace, &self.password, &json)
    }

    pub(crate) fn import_backup_from_paste(&mut self) -> Result<host::UnlockedSession, String> {
        let lang = self.lang.clone();
        if self.password.is_empty() {
            return Err(i18n::phrase(&lang, "enter_password"));
        }
        let json = self.paste.trim();
        if json.is_empty() {
            return Err("Paste the keystore JSON backup.".into());
        }
        if !(json.starts_with('{') && json.contains("identity_ciphertext")) {
            return Err("That does not look like a Ghal Bol keystore backup JSON.".into());
        }
        host::import_keystore(&self.namespace, &self.password, json)
    }

    /// Status line above the transcript (attach / QR picture / join results).
    pub(crate) fn show_call_line(&mut self, cx: &mut Cx, msg: String) {
        script_eval!(cx, {
            mod.state.call_line = #(msg)
            ui.chat_log.render()
        });
    }

    pub(crate) fn show_attach_result(&mut self, cx: &mut Cx, sent: Result<(), String>) {
        let queued = sent.is_ok();
        self.show_call_line(cx, sent.map(|()| "File queued".to_string()).unwrap_or_else(|e| e));
        if queued {
            self.refresh_transcript(cx);
        }
    }

    /// Decode an invite QR from a picture (desktop path or Android `content://` URI) and join.
    pub(crate) fn join_from_qr_picture(&mut self, cx: &mut Cx, picked: &str) {
        let ns = self.namespace.clone();
        let joined = host::decode_qr_file(picked).and_then(|text| host::accept_invite(&ns, &text));
        let msg = match joined {
            Ok(pk) => format!("Joined {pk}"),
            Err(e) => e,
        };
        self.show_call_line(cx, msg);
        self.refresh_roster(cx);
    }

    #[cfg(target_os = "android")]
    pub(crate) fn on_android_pick(&mut self, cx: &mut Cx, answer: android_pick::Answer) {
        use android_pick::Answer;
        match answer {
            Answer::Picked(id, uri) if id == android_pick::ATTACHMENT => {
                let peer = android_pick::take_attach_peer();
                let sent = host::send_picked_attachment(&self.namespace, &peer, &uri);
                self.show_attach_result(cx, sent);
            }
            Answer::Picked(id, uri) if id == android_pick::BACKUP => {
                let imported = host::read_picked_file(&uri, host::MAX_PICKED_BACKUP_BYTES)
                    .and_then(|(_, bytes)| {
                        String::from_utf8(bytes)
                            .map_err(|_| "That file is not a keystore backup JSON.".to_string())
                    })
                    .and_then(|json| {
                        self.paste = json;
                        self.import_backup_from_paste()
                    });
                match imported {
                    Ok(session) => self.finish_import_backup(cx, session),
                    Err(e) => {
                        script_eval!(cx, {
                            mod.state.status = #(e)
                            ui.identity_copy.render()
                        });
                    }
                }
            }
            Answer::Picked(id, uri) if id == android_pick::QR_PICTURE => {
                self.join_from_qr_picture(cx, &uri);
            }
            // No file chosen: offer pasting the backup JSON instead.
            Answer::Cancelled(id) if id == android_pick::BACKUP => {
                self.open_import_backup_sheet(cx);
            }
            _ => {}
        }
    }
}
