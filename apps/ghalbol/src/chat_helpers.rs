//! Chat bubble + roster helpers.

use ghalbol_core::host::{self, ChatLine, RosterEntry};
use makepad_widgets::*;

/// Pack RGBA → BGRA u32 words for Makepad textures. Short buffers become opaque black.
pub(crate) fn pack_rgba_to_bgra_u32(w: u32, h: u32, rgba: &[u8]) -> Vec<u32> {
    let pixels = (w as usize).saturating_mul(h as usize);
    let need = pixels.saturating_mul(4);
    let mut data = Vec::with_capacity(pixels);
    if rgba.len() >= need {
        for px in rgba[..need].chunks_exact(4) {
            data.push(
                ((px[3] as u32) << 24)
                    | ((px[0] as u32) << 16)
                    | ((px[1] as u32) << 8)
                    | (px[2] as u32),
            );
        }
    } else {
        data.resize(pixels, 0xff00_0000);
    }
    data
}

/// Pack RGBA bytes into a Makepad `VecBGRAu8_32` texture (same path as QR preview).
pub(crate) fn rgba_to_bgra_texture(cx: &mut Cx, w: u32, h: u32, rgba: &[u8]) -> Texture {
    let data = pack_rgba_to_bgra_u32(w, h, rgba);
    Texture::new_with_format(
        cx,
        TextureFormat::VecBGRAu8_32 {
            width: w as usize,
            height: h as usize,
            data: Some(data),
            updated: TextureUpdated::Full,
        },
    )
}

pub(crate) fn roster_initial(row: &RosterEntry) -> String {
    call_avatar_initial(&row.title)
}

pub(crate) fn call_avatar_initial(title: &str) -> String {
    let title = title.trim();
    // `short_key` titles look like `0279be66…1798` — do not use a hex digit as the avatar.
    if title.contains('…') || title.contains("...") {
        return "#".to_string();
    }
    title
        .chars()
        .find(|c| c.is_alphabetic())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "#".to_string())
}

pub(crate) fn roster_matches(row: &RosterEntry, search: &str) -> bool {
    let q = search.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    row.title.to_lowercase().contains(&q)
        || row.public_key_hex.to_lowercase().contains(&q)
        || row.preview.to_lowercase().contains(&q)
}

/// Identity wires compare case-insensitively in roster + open-room state.
pub(crate) fn peer_public_key_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Match `contacts_v1` storage (trim + lowercase ASCII hex wires).
pub(crate) fn canonical_peer_key(pk: &str) -> String {
    let t = pk.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.is_ascii() {
        return t.to_ascii_lowercase();
    }
    t.to_string()
}

pub(crate) fn roster_title_for_key(rows: &[(String, String)], pk: &str) -> Option<String> {
    rows.iter()
        .find(|(row_pk, _)| peer_public_key_eq(row_pk, pk))
        .map(|(_, title)| title.clone())
}

/// Mirror `preferences_v1::sanitize_peer_display_alias` before save (UI feedback matches wire).
pub(crate) fn normalize_availability_status(raw: &str) -> Option<String> {
    let mut t = raw.trim().to_string();
    if t.is_empty() {
        return None;
    }
    for ch in ['\n', '\r', '\t'] {
        t = t.replace(ch, " ");
    }
    const MAX: usize = 64;
    if t.len() > MAX {
        t.truncate(MAX);
        while !t.is_empty() && t.ends_with(' ') {
            t.pop();
        }
    }
    let t = t.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

pub(crate) struct Bubble {
    pub(crate) body: String,
    /// Secondary line under the body (size / Downloaded / Downloading…).
    pub(crate) detail: String,
    /// Flutter `_bubbleSenderCaption`: "You" or the peer title.
    pub(crate) caption: String,
    pub(crate) tick: String,
    pub(crate) read: bool,
    /// Outbound send gave up (`delivery == "failed"`) — orange `!` tick.
    pub(crate) failed: bool,
}

pub(crate) fn format_bytes(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.0)
    } else if n > 0 {
        format!("{n} B")
    } else {
        String::new()
    }
}

pub(crate) fn format_mmss(ms: u32) -> String {
    let secs = ms / 1000;
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// Cap user-visible status / error lines so poll and host errors cannot bloat Splash state.
pub(crate) const MAX_UI_DISPLAY_CHARS: usize = 320;

pub(crate) fn clamp_ui_display_line(s: &str) -> String {
    let n = s.chars().count();
    if n <= MAX_UI_DISPLAY_CHARS {
        return s.to_string();
    }
    let mut out: String = s
        .chars()
        .take(MAX_UI_DISPLAY_CHARS.saturating_sub(1))
        .collect();
    out.push('…');
    out
}

/// Same-room reload returned zero rows — keep the painted chat (DESIGN.md anti-pattern).
pub(crate) fn keep_painted_transcript(
    loaded_lines: usize,
    room_changed: bool,
    painted_lines: usize,
) -> bool {
    loaded_lines == 0 && !room_changed && painted_lines > 0
}

/// Transient `load_transcript` failure — do not wipe a painted room.
pub(crate) fn preserve_transcript_on_load_error(painted_lines: usize) -> bool {
    painted_lines > 0
}

/// Call ended in native but the Makepad call shell is still up (`call_open` cleared elsewhere).
pub(crate) fn needs_call_shell_reconcile(in_call: bool, call_view_visible: bool) -> bool {
    !in_call && call_view_visible
}

/// User-facing block before `host::send_text` (unit-tested).
pub(crate) fn send_text_block_reason(
    has_session: bool,
    ui_locked: bool,
    peer_empty: bool,
) -> Option<&'static str> {
    if !has_session {
        return Some("Unlock to send messages.");
    }
    if ui_locked {
        return Some("Unlock the app to send messages.");
    }
    if peer_empty {
        return Some("Select a chat first");
    }
    None
}

pub(crate) fn bubble_of(line: &ChatLine, peer_title: &str) -> Bubble {
    let caption = if line.outgoing {
        "You".to_string()
    } else if peer_title.is_empty() {
        "Contact".to_string()
    } else {
        peer_title.to_string()
    };
    let (body, detail) = if line.kind == "call_event" {
        (line.text.clone(), String::new())
    } else if line.kind == "voice" {
        let secs = (line.duration_ms / 1000).max(1);
        (format!("▶  Voice note  {secs}s"), String::new())
    } else if line.kind == "attachment_offer" {
        let name = if line.text.is_empty() {
            "File".to_string()
        } else {
            line.text.clone()
        };
        let detail = if !line.local_path.is_empty() {
            "Downloaded".to_string()
        } else if line.delivery == "downloading" {
            "Downloading…".to_string()
        } else {
            let size = format_bytes(line.size_bytes);
            if size.is_empty() {
                "Tap Download".to_string()
            } else {
                size
            }
        };
        (name, detail)
    } else if line.kind == "text" || line.kind.is_empty() {
        (line.text.clone(), String::new())
    } else if line.text.is_empty() {
        (format!("[{}]", line.kind), String::new())
    } else {
        (line.text.clone(), String::new())
    };
    if !line.outgoing {
        return Bubble {
            body,
            detail,
            caption,
            tick: String::new(),
            read: false,
            failed: false,
        };
    }
    // Tick ladder (MAKEPAD_UI): pending / sent / delivered|read / failed.
    // FA PUA single glyphs — NotoSans lacks ✓ so "✓✓" became two wide FA
    // checks with a huge gap. check-double (U+F560) is one glyph.
    let read = line.delivery == "read";
    let failed = line.delivery == "failed";
    let tick = match line.delivery.as_str() {
        "pending" => "\u{f111}",       // FA circle
        "sent" => "\u{f00c}",          // FA check
        "delivered" | "read" => "\u{f560}", // FA check-double (one glyph)
        "downloaded" => "\u{f063}",    // FA arrow-down
        "failed" => "!",
        other if !other.is_empty() => other,
        _ => "",
    };
    Bubble {
        body,
        detail,
        caption,
        tick: tick.to_string(),
        read,
        failed,
    }
}

pub(crate) fn save_status_line(status: &str) -> Result<String, String> {
    let normalized = normalize_availability_status(status);
    let wire = normalized.as_deref().unwrap_or("");
    host::set_availability_status(wire).map(|()| match &normalized {
        None => "Status cleared".into(),
        Some(s) => format!("Status saved: {s}"),
    })
}

pub(crate) fn qr_png(text: &str) -> Option<Vec<u8>> {
    use ::image::ImageEncoder;
    // Match invite URI ceiling — oversized paste must not hang QR encode.
    if text.len() > 8 * 1024 {
        return None;
    }
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let img = code
        .render::<::image::Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(280, 280)
        .dark_color(::image::Luma([0]))
        .light_color(::image::Luma([255]))
        .build();
    let mut png = Vec::new();
    let encoder = ::image::codecs::png::PngEncoder::new(&mut png);
    encoder
        .write_image(
            img.as_raw(),
            img.width(),
            img.height(),
            ::image::ExtendedColorType::L8,
        )
        .ok()?;
    Some(png)
}

/// Dark placeholder so Scan never reuses leftover Invite QR pixels.
pub(crate) fn scan_placeholder_png() -> Option<Vec<u8>> {
    use ::image::ImageEncoder;
    let (w, h) = (320u32, 240u32);
    let pixels = vec![0x1Bu8; (w * h) as usize];
    let mut png = Vec::new();
    let encoder = ::image::codecs::png::PngEncoder::new(&mut png);
    encoder
        .write_image(&pixels, w, h, ::image::ExtendedColorType::L8)
        .ok()?;
    Some(png)
}

/// Android document picker (Storage Access Framework). Answers arrive later as a
/// `FileDialogAction` carrying a `content://` URI, which `host` reads for us.
#[cfg(target_os = "android")]
pub(crate) mod android_pick {
    use makepad_widgets::makepad_platform::file_dialogs::{FileDialog, FileDialogAction};
    use makepad_widgets::*;
    use std::sync::Mutex;

    pub const ATTACHMENT: LiveId = live_id!(pick_attachment);
    pub const BACKUP: LiveId = live_id!(pick_backup);
    pub const QR_PICTURE: LiveId = live_id!(pick_qr_picture);

    /// Chat that was open when Attach was tapped; the answer may arrive after a room switch.
    static ATTACH_PEER: Mutex<String> = Mutex::new(String::new());

    pub enum Answer {
        Picked(LiveId, String),
        Cancelled(LiveId),
    }

    pub fn open(cx: &mut Cx, id: LiveId, title: &str, filter: Option<(&str, &[&str])>) {
        let mut dialog = FileDialog::new().set_id(id).set_title(title.to_string());
        if let Some((name, extensions)) = filter {
            dialog = dialog.add_filter(
                name.to_string(),
                extensions.iter().map(|e| e.to_string()).collect(),
            );
        }
        cx.open_select_file_dialog(dialog);
    }

    pub fn pick_attachment(cx: &mut Cx, peer: &str) {
        if let Ok(mut g) = ATTACH_PEER.lock() {
            *g = peer.to_string();
        }
        open(cx, ATTACHMENT, "Send a file", None);
    }

    pub fn take_attach_peer() -> String {
        ATTACH_PEER
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    pub fn answer(action: &Action) -> Option<Answer> {
        match action.downcast_ref::<FileDialogAction>()? {
            FileDialogAction::FileSelected { id, paths } => Some(Answer::Picked(
                *id,
                paths.first()?.to_string_lossy().into_owned(),
            )),
            FileDialogAction::FileCancelled { id } => Some(Answer::Cancelled(*id)),
            _ => None,
        }
    }
}

/// Linux tries the desktop clipboard tools first (the copy outlives the app), then
/// Makepad's own clipboard, which every other platform uses directly.
pub(crate) fn copy_to_clipboard(cx: &mut Cx, text: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        for (bin, args) in [
            ("wl-copy", vec![] as Vec<&str>),
            ("xclip", vec!["-selection", "clipboard"]),
            ("xsel", vec!["--clipboard", "--input"]),
        ] {
            let Ok(mut child) = std::process::Command::new(bin)
                .args(&args)
                .stdin(std::process::Stdio::piped())
                .spawn()
            else {
                continue;
            };
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Ok(());
            }
        }
    }
    cx.copy_to_clipboard(text);
    Ok(())
}

pub(crate) fn apply_algo_chip_style(cx: &mut Cx, button: &mut WidgetRef, on: bool) {
    if on {
        script_apply_eval!(cx, button, {
            draw_bg.color: #D6E8FF
            draw_bg.color_hover: #BFD9FF
            draw_bg.color_down: #A8CBFF
            draw_bg.color_focus: #D6E8FF
        });
    } else {
        script_apply_eval!(cx, button, {
            draw_bg.color: #FFFFFF
            draw_bg.color_hover: #DCE4F0
            draw_bg.color_down: #C5D0DE
            draw_bg.color_focus: #FFFFFF
        });
    }
    button.redraw(cx);
}

/// Makepad Button has no selected bit — only hover/down/focus. Selection is
/// Overlay idle+active faces painted from `hub_tab` (kumkaj lesson).

#[cfg(test)]
mod bubble_tests {
    use super::bubble_of;
    use ghalbol_core::host::ChatLine;

    fn line(outgoing: bool, delivery: &str, text: &str) -> ChatLine {
        ChatLine {
            outgoing,
            text: text.into(),
            delivery: delivery.into(),
            kind: "text".into(),
            duration_ms: 0,
            audio_path: String::new(),
            local_path: String::new(),
            message_id: String::new(),
            size_bytes: 0,
        }
    }

    #[test]
    fn pack_rgba_short_buffer_fills_opaque_black() {
        let data = super::pack_rgba_to_bgra_u32(2, 2, &[1, 2, 3, 4]);
        assert_eq!(data.len(), 4);
        assert!(data.iter().all(|p| *p == 0xff00_0000));
    }

    #[test]
    fn pack_rgba_exact_buffer_preserves_channels() {
        let rgba = [10u8, 20, 30, 40, 1, 2, 3, 255];
        let data = super::pack_rgba_to_bgra_u32(1, 2, &rgba);
        assert_eq!(data.len(), 2);
        assert_eq!(data[0], (40u32 << 24) | (10 << 16) | (20 << 8) | 30);
        assert_eq!(data[1], (255u32 << 24) | (1 << 16) | (2 << 8) | 3);
    }

    #[test]
    fn qr_png_rejects_oversized_payload() {
        let huge = "a".repeat(8 * 1024 + 1);
        assert!(super::qr_png(&huge).is_none());
    }

    #[test]
    fn failed_outbound_tick_is_bang() {
        let failed = bubble_of(&line(true, "failed", "oops"), "Bob");
        assert!(failed.failed);
        assert_eq!(failed.tick, "!");
    }

    #[test]
    fn keep_painted_transcript_on_empty_same_room_reload() {
        assert!(super::keep_painted_transcript(0, false, 3));
        assert!(!super::keep_painted_transcript(0, true, 3));
        assert!(!super::keep_painted_transcript(2, false, 3));
        assert!(!super::keep_painted_transcript(0, false, 0));
    }

    #[test]
    fn preserve_transcript_when_load_errors_with_paint() {
        assert!(super::preserve_transcript_on_load_error(4));
        assert!(!super::preserve_transcript_on_load_error(0));
    }

    #[test]
    fn call_shell_reconcile_when_view_up_but_not_in_call() {
        assert!(super::needs_call_shell_reconcile(false, true));
        assert!(!super::needs_call_shell_reconcile(true, true));
        assert!(!super::needs_call_shell_reconcile(false, false));
    }

    #[test]
    fn send_text_block_reason_order() {
        assert_eq!(
            super::send_text_block_reason(false, false, false),
            Some("Unlock to send messages.")
        );
        assert_eq!(
            super::send_text_block_reason(true, true, false),
            Some("Unlock the app to send messages.")
        );
        assert_eq!(
            super::send_text_block_reason(true, false, true),
            Some("Select a chat first")
        );
        assert_eq!(super::send_text_block_reason(true, false, false), None);
    }

    #[test]
    fn clamp_ui_display_line_truncates_with_ellipsis() {
        let long = "x".repeat(super::MAX_UI_DISPLAY_CHARS + 40);
        let out = super::clamp_ui_display_line(&long);
        assert_eq!(out.chars().count(), super::MAX_UI_DISPLAY_CHARS);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn peer_key_eq_ignores_case_and_surrounding_space() {
        let a = "  ABCDEF01 ";
        let b = "abcdef01";
        assert!(super::peer_public_key_eq(a, b));
        assert!(!super::peer_public_key_eq(a, "abcdEF02"));
    }

    #[test]
    fn canonical_peer_key_lowercases_ascii_wires() {
        assert_eq!(super::canonical_peer_key("  AABB "), "aabb");
        assert_eq!(super::canonical_peer_key(""), "");
    }

    #[test]
    fn roster_title_lookup_is_case_insensitive() {
        let rows = vec![("aa11".into(), "Alice".into())];
        assert_eq!(
            super::roster_title_for_key(&rows, "AA11").as_deref(),
            Some("Alice")
        );
        assert!(super::roster_title_for_key(&rows, "zz").is_none());
    }

    #[test]
    fn normalize_availability_collapses_whitespace_and_caps_bytes() {
        assert_eq!(
            super::normalize_availability_status("  Busy\nnow  ").as_deref(),
            Some("Busy now")
        );
        let long = "x".repeat(80);
        let out = super::normalize_availability_status(&long).unwrap();
        assert!(out.len() <= 64);
        assert_eq!(super::normalize_availability_status("   "), None);
    }

    #[test]
    fn call_avatar_initial_skips_hex_short_keys() {
        assert_eq!(super::call_avatar_initial("0279be66…1798"), "#");
        assert_eq!(super::call_avatar_initial("Alice"), "A");
    }

    #[test]
    fn roster_matches_title_preview_and_key() {
        use ghalbol_core::host::RosterEntry;
        let row = RosterEntry {
            title: "Bob".into(),
            public_key_hex: "aabbcc".into(),
            preview: "See you".into(),
            unread: 0,
            availability: String::new(),
            is_known: true,
            is_blocked: false,
        };
        assert!(super::roster_matches(&row, "bob"));
        assert!(super::roster_matches(&row, "AABB"));
        assert!(super::roster_matches(&row, "see"));
        assert!(!super::roster_matches(&row, "zzz"));
    }

    #[test]
    fn format_bytes_uses_sensible_units() {
        assert_eq!(super::format_bytes(500), "500 B");
        assert!(super::format_bytes(1500).contains("KB"));
        assert!(super::format_bytes(2_000_000).contains("MB"));
    }

    #[test]
    fn read_tick_is_blue_and_inbound_has_none() {
        let pending = bubble_of(&line(true, "pending", "hi"), "Alice");
        assert_eq!(pending.tick, "\u{f111}");
        assert!(!pending.read);
        assert_eq!(pending.body, "hi");
        assert_eq!(pending.caption, "You");

        let sent = bubble_of(&line(true, "sent", "hi"), "Alice");
        assert_eq!(sent.tick, "\u{f00c}");
        assert!(!sent.read);

        let delivered = bubble_of(&line(true, "delivered", "hi"), "Alice");
        assert_eq!(delivered.tick, "\u{f560}");
        assert!(!delivered.read);

        let read = bubble_of(&line(true, "read", "hi"), "Alice");
        assert_eq!(read.tick, "\u{f560}");
        assert!(read.read);

        let inbound = bubble_of(&line(false, "read", "hi"), "Alice");
        assert!(inbound.tick.is_empty());
        assert!(!inbound.read);
        assert_eq!(inbound.caption, "Alice");
    }
}
