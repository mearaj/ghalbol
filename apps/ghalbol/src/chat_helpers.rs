//! Chat bubble + roster helpers.

use ghalbol_core::host::{self, ChatLine, RosterEntry};
use makepad_widgets::*;

/// Pack RGBA bytes into a Makepad `VecBGRAu8_32` texture (same path as QR preview).
pub(crate) fn rgba_to_bgra_texture(cx: &mut Cx, w: u32, h: u32, rgba: &[u8]) -> Texture {
    let pixels = (w as usize).saturating_mul(h as usize);
    let mut data = Vec::with_capacity(pixels);
    for px in rgba.chunks_exact(4).take(pixels) {
        data.push(
            ((px[3] as u32) << 24)
                | ((px[0] as u32) << 16)
                | ((px[1] as u32) << 8)
                | (px[2] as u32),
        );
    }
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
    host::set_availability_status(status).map(|()| {
        if status.is_empty() {
            "Status cleared".into()
        } else {
            format!("Status saved: {status}")
        }
    })
}

pub(crate) fn qr_png(text: &str) -> Option<Vec<u8>> {
    use ::image::ImageEncoder;
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
