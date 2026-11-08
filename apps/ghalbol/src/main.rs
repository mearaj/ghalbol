//! Makepad 2 desktop shell. Product logic stays in `ghalbol_core::host`.
//!
//! Splash uses `script_mod!` (Makepad 2).

// Production Windows exe opens without a console window (`build.rs` sets the cfg).
#![cfg_attr(all(windows, ghalbol_hide_console), windows_subsystem = "windows")]

pub use makepad_widgets;

mod i18n;
mod phrases;
mod splash_faces;
mod splash_ui;
mod chat_helpers;
mod hub_history;
mod env_load;
mod app_actions;
mod app_chat;
mod app_shell;

use makepad_widgets::*;

use ghalbol_core::host::{self, UnlockedSession};
use hub_history::*;
use env_load::*;

// Android/APK only ships fonts listed here (plus the International set).
// WorldFonts `self:resources/fonts/…` members must match these logical paths
// or glyphs render as boxes / missing icons.
app_main!(
    App,
    font_assets: [
        "makepad_widgets/resources/fa-solid-900.ttf",
        "ghalbol_app/resources/fonts/NotoSans-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansDevanagari-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansBengali-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansTamil-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansTelugu-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansGujarati-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansKannada-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansMalayalam-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansGurmukhi-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansOriya-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansArabic-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansHebrew-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansThai-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansSinhala-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansMyanmar-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansKhmer-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansLao-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansTibetan-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansEthiopic-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansThaana-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansGeorgian-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansArmenian-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansMeeteiMayek-Regular.ttf",
        "ghalbol_app/resources/fonts/NotoSansOlChiki-Regular.ttf",
    ]
);


#[derive(Script, ScriptHook)]
pub struct App {
    #[live]
    ui: WidgetRef,
    #[rust]
    password: String,
    #[rust]
    composer: String,
    /// Shown above the transcript when the delivery mailbox is down after a send.
    #[rust]
    delivery_hint: String,
    /// Ephemeral chat/call feedback shown above the transcript (survives poll ticks).
    #[rust]
    chat_notice: String,
    #[rust]
    chat_notice_error: bool,
    #[rust]
    namespace: String,
    #[rust]
    session: Option<UnlockedSession>,
    #[rust]
    open_peer: String,
    #[rust]
    seen_open_gen: f64,
    #[rust]
    create_new: bool,
    #[rust]
    algorithm: String,
    #[rust]
    secret: String,
    #[rust]
    search: String,
    #[rust]
    paste: String,
    #[rust]
    add_pk: String,
    #[rust]
    add_alias: String,
    #[rust]
    page: String,
    #[rust]
    hub_tab: u8,
    /// Live window width. `0` means not measured yet — use the design desktop
    /// width so the side rail is not hidden before the first geom event.
    #[rust]
    window_w: f64,
    #[rust]
    shell_split: bool,
    #[rust]
    narrow_show_room: bool,
    #[rust]
    mic_muted: bool,
    #[rust]
    speaker_on: bool,
    #[rust]
    camera_on: bool,
    #[rust]
    call_open: bool,
    /// Mirrors whether `call_view` is the active shell (for stale-call recovery).
    #[rust]
    call_view_visible: bool,
    #[rust]
    ui_locked: bool,
    #[rust]
    needs_backup: bool,
    #[rust]
    window_limit: usize,
    #[rust]
    has_more: bool,
    #[rust]
    lang: String,
    #[rust]
    seen_play: f64,
    #[rust]
    seen_lang: f64,
    #[rust]
    seen_algo: f64,
    #[rust]
    pending_invite: String,
    #[rust]
    roster_ver: u64,
    #[rust]
    roster_query: String,
    #[rust]
    hub_history: HubHistoryStack,
    #[rust]
    history_suppress: bool,
    /// Skip `apply_shell_layout` redraw when chrome flags/walks are unchanged.
    #[rust]
    shell_layout_sig: u64,
    /// `(public_key_hex, title)` per rendered roster row, same order as
    /// `roster_list` children — maps a tapped child index back to a peer.
    #[rust]
    roster_rows: Vec<(String, String)>,
    /// Frames left in which `chat_log` is re-pinned to its end. Set after a
    /// transcript change while the user was near the bottom (Flutter
    /// stick-to-bottom); applied on NextFrame once the new content height is laid out.
    #[rust]
    pin_chat_frames: u8,
    /// Line count of the last rendered transcript — growth + near-bottom ⇒ pin.
    #[rust]
    chat_lines_len: usize,
    /// Peer whose transcript `chat_log` currently shows; a change forces a pin.
    #[rust]
    chat_lines_peer: String,
    /// `host::transcript_revision` at the last transcript load.
    #[rust]
    chat_rev: u64,
    /// Room ⋮ menu is open.
    #[rust]
    chat_menu_open: bool,
    /// Nav WebP marks loaded once into rail Image widgets.
    #[rust]
    nav_icons_loaded: bool,
    /// Last recording-bar visibility we applied (avoids redraw spam).
    #[rust]
    recording_ui: bool,
    /// Voice-note playback was active on the previous poll (drives progress refresh).
    #[rust]
    voice_playing_ui: bool,
    /// Last voice-play elapsed second painted (throttle transcript refresh).
    #[rust]
    voice_play_tick_sec: u32,
    /// Last status strip painted above the transcript (skip `chat_log.render` on poll).
    #[rust]
    painted_call_strip: String,
    #[rust]
    painted_call_strip_error: bool,
}

impl AppMain for App {
    fn script_mod(vm: &mut ScriptVm) -> ScriptValue {
        crate::makepad_widgets::script_mod(vm);
        crate::splash_faces::script_mod(vm);
        // Before the first namespace read: `GHALBOL_APP_ID` picks the data directory.
        load_env_once();
        if !vm.is_reload() {
            let ns = host::default_app_namespace();
            let exists = host::keystore_exists(&ns);
            let primary = if exists {
                "Unlock"
            } else {
                "Create identity"
            };
            let hint = if exists {
                "Enter your password to unlock this device."
            } else {
                "Choose a password. This creates a device identity on this computer."
            };
            script_eval!(vm, {
                mod.state = {
                    screen: "identity"
                    status: ""
                    hint: #(hint)
                    primary: #(primary)
                    self_line: ""
                    roster: []
                    roster_empty_title: "No chats yet"
                    roster_empty_body: "Scan a QR or paste an invitation to start a 1:1 chat."
                    transcript: ""
                    lines: []
                    selected_pk: ""
                    selected_title: "Select a chat"
                    call_line: ""
                    call_line_is_error: ""
                    open_gen: 0
                    play_gen: 0
                    play_path: ""
                    play_action: ""
                    lang_gen: 0
                    algo: "secp256k1"
                    algo_line: "Algorithm: secp256k1"
                    algo_gen: 0
                    identity_blurb: ""
                    identity_detail: ""
                    languages: []
                }
                true
            });
        }
        crate::splash_ui::script_mod(vm)
    }

    fn handle_event(&mut self, cx: &mut Cx, event: &Event) {
        if self.namespace.is_empty() {
            self.namespace = host::default_app_namespace();
            self.create_new = true;
            self.algorithm = "secp256k1".into();
            self.lang = host::ui_locale(&self.namespace).unwrap_or_else(i18n::system_code);
            self.speaker_on = true;
            self.camera_on = true;
            self.roster_ver = u64::MAX;
            #[cfg(target_os = "android")]
            {
                let vm = makepad_android_state::get_java_vm();
                let activity = makepad_android_state::get_activity();
                if !vm.is_null() && !activity.is_null() {
                    host::install_android_context(vm.cast(), activity.cast());
                }
                let _ = cx.request_permission(makepad_platform::permission::Permission::Camera);
                let _ = cx.request_permission(makepad_platform::permission::Permission::AudioInput);
            }
            if self.pending_invite.is_empty() {
                if let Some(url) = host::take_view_invite() {
                    self.pending_invite = url;
                }
            }
            host::desktop_session_start(&self.namespace);
            if let Some(arg) = std::env::args().skip(1).find(|arg| {
                let t = arg.trim();
                t.starts_with("ghalbol://") || t.contains("ghalbol.com/connect/")
            }) {
                self.pending_invite = strip_surrounding_quotes(&arg);
            }
            start_ui_poll();
            self.push_identity_copy(cx);
        }
        match event {
            Event::Shutdown | Event::QuitRequested(_) => {
                let _ = host::end_call();
                self.call_open = false;
            }
            Event::WindowGeomChange(change) => {
                self.apply_shell_widths(cx, change.new_geom.inner_size.x);
            }
            // After IME reflow shrinks chat_log, pin to the latest messages so
            // they stay above the keyboard — never left scrolled under it.
            Event::VirtualKeyboard(VirtualKeyboardEvent::DidShow { .. })
            | Event::VirtualKeyboard(VirtualKeyboardEvent::WillShow { .. }) => {
                if !self.open_peer.is_empty() {
                    self.pin_chat_bottom(cx);
                }
            }
            // The soft keyboard went down while the composer still holds key
            // focus: that is the user dismissing it (back / IME down arrow).
            // A focused TextInput re-requests the IME on its next draw, so
            // release focus — the keyboard comes back only when the user taps
            // a field again. Skipped with a hardware keyboard, where Android
            // hides the soft keyboard on its own while typing continues.
            Event::VirtualKeyboard(VirtualKeyboardEvent::DidHide { .. }) => {
                if !cx.keyboard.has_physical_keyboard() {
                    self.release_composer_key_focus(cx);
                }
            }
            Event::NextFrame(_) => self.apply_chat_pin_frame(cx),
            Event::MouseUp(mouse) if mouse.button.is_back() => {
                if self.navigate_back(cx, true) {
                    return;
                }
            }
            Event::MouseUp(mouse) if mouse.button.is_forward() => {
                if self.navigate_forward(cx) {
                    return;
                }
            }
            Event::KeyDown(key)
                if key.key_code == KeyCode::Escape
                    || (key.key_code == KeyCode::ArrowLeft && key.modifiers.alt) =>
            {
                // Escape / Alt+Left only. Android KEYCODE_BACK is Event::BackPressed
                // (MatchEvent::handle_back_pressed) — do not also handle KeyCode::Back here
                // or every gesture would pop two levels.
                if self.navigate_back(cx, false) {
                    return;
                }
            }
            Event::KeyDown(key)
                if key.key_code == KeyCode::ArrowRight && key.modifiers.alt =>
            {
                if self.navigate_forward(cx) {
                    return;
                }
            }
            _ => {}
        }
        #[cfg(target_os = "android")]
        match event {
            Event::Background => host::set_app_visible(false),
            Event::Foreground | Event::Resume => {
                host::set_app_visible(true);
                if let Some(url) = host::take_view_invite() {
                    if self.session.is_some() && !self.ui_locked {
                        match host::accept_invite(&self.namespace, &url) {
                            Ok(pk) => {
                                self.roster_ver = u64::MAX;
                                self.open_joined_peer_chat(cx, &pk);
                                self.show_call_line(
                                    cx,
                                    crate::app_chat::join_accept_status_line(&pk),
                                );
                            }
                            Err(e) => {
                                self.roster_ver = u64::MAX;
                                self.surface_invite_join_error(cx, e, Some(&url));
                            }
                        }
                    } else {
                        self.pending_invite = url;
                    }
                }
            }
            _ => {}
        }
        self.match_event(cx, event);
        self.ui.handle_event(cx, event, &mut Scope::empty());
        // `roster_list.on_item_tap` bumps `open_gen` during the FingerUp above;
        // that path does not always emit a WidgetAction, so open the room here
        // rather than waiting for a later Event::Actions.
        self.sync_open_chat(cx);
        if let Event::Signal = event {
            self.drain_events(cx);
            // Poll may join via QR / roster bumps — open the room same frame.
            self.sync_open_chat(cx);
        }
    }
}

/// Avatar glyph for a roster row: first letter of the display name, upper-cased;
/// `#` when the title is only a key fragment / punctuation (Flutter `_avatarInitial`).
impl App {
    fn paint_nav_tabs(&mut self, cx: &mut Cx) {
        let tab = self.hub_tab;
        let pairs: [(&[LiveId], &[LiveId], bool); 4] = [
            (ids!(tab_chats), ids!(tab_chats_on), tab == 0),
            (ids!(tab_contacts), ids!(tab_contacts_on), tab == 1),
            (ids!(tab_invite), ids!(tab_invite_on), tab == 2),
            (ids!(tab_settings), ids!(tab_settings_on), tab == 3),
        ];
        let bottom: [(&[LiveId], &[LiveId], bool); 4] = [
            (ids!(bottom_chats), ids!(bottom_chats_on), tab == 0),
            (ids!(bottom_contacts), ids!(bottom_contacts_on), tab == 1),
            (ids!(bottom_invite), ids!(bottom_invite_on), tab == 2),
            (ids!(bottom_settings), ids!(bottom_settings_on), tab == 3),
        ];
        for (idle, on, selected) in pairs.into_iter().chain(bottom) {
            // Clear stuck hover/focus so a deselected face never stays lit.
            self.ui.button(cx, idle).reset_hover(cx);
            self.ui.button(cx, on).reset_hover(cx);
            self.ui.widget(cx, idle).set_visible(cx, !selected);
            self.ui.widget(cx, on).set_visible(cx, selected);
        }
        self.ensure_nav_icons(cx);
    }

    fn ensure_nav_icons(&mut self, cx: &mut Cx) {
        if self.nav_icons_loaded {
            return;
        }
        let marks: [(&[LiveId], &[u8]); 5] = [
            (
                ids!(mark_chats),
                include_bytes!("../resources/nav/chats.webp"),
            ),
            (
                ids!(mark_contacts),
                include_bytes!("../resources/nav/contacts.webp"),
            ),
            (
                ids!(mark_invite),
                include_bytes!("../resources/nav/invite.webp"),
            ),
            (
                ids!(mark_settings),
                include_bytes!("../resources/nav/settings.webp"),
            ),
            (ids!(mark_lock), include_bytes!("../resources/nav/lock.webp")),
        ];
        for (path, bytes) in marks {
            let img = self.ui.image(cx, path);
            let _ = img.load_image_from_data(cx, bytes);
        }
        self.nav_icons_loaded = true;
    }
}

