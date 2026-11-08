//! Process env + baked dotenv.

use ghalbol_core::host;
use makepad_widgets::*;

pub(crate) fn short_key(pk: &str) -> String {
    let t = pk.trim();
    if t.len() <= 16 {
        return t.to_string();
    }
    // Identity wires are ASCII hex; never panic on a non-ASCII display string.
    if !t.is_ascii() || t.len() < 12 {
        return t.chars().take(16).collect();
    }
    format!("{}…{}", &t[..8], &t[t.len() - 4..])
}

pub(crate) fn start_ui_poll() {
    use std::sync::Once;
    static START: Once = Once::new();
    START.call_once(|| {
        std::thread::spawn(|| {
            loop {
                let ms = if host::qr_scan_ui_active() { 50 } else { 400 };
                std::thread::sleep(std::time::Duration::from_millis(ms));
                makepad_widgets::makepad_platform::SignalToUI::set_ui_signal();
            }
        });
    });
}

pub(crate) fn splash_string(cx: &mut Cx, value: ScriptValue) -> String {
    let mut out = String::new();
    cx.with_vm(|vm| {
        vm.bx.heap.cast_to_string(value, &mut out);
    });
    out
}

pub(crate) fn splash_f64(cx: &mut Cx, value: ScriptValue) -> f64 {
    let _ = cx;
    value.as_f64().unwrap_or(0.0)
}

/// `apps/ghalbol/env/<profile>.env`, selected and embedded by `build.rs`.
const BAKED_ENV: &str = include_str!(concat!(env!("OUT_DIR"), "/ghalbol.env"));

/// Load the app environment once per process. Precedence, highest first:
/// the process environment; a developer override `env/.env.<profile>` in the working
/// directory (gitignored, desktop only in practice); the per-app values baked at build time.
/// The profile is `GHALBOL_ENV` at build time, else the Cargo profile — see `build.rs`.
pub(crate) fn load_env_once() {
    static LOADED: std::sync::Once = std::sync::Once::new();
    LOADED.call_once(|| {
        let profile = env!("GHALBOL_ENV");
        let path = format!("env/.env.{profile}");
        let from_file = match std::fs::metadata(&path)
            .ok()
            .filter(|m| m.len() <= 64 * 1024)
            .and_then(|_| std::fs::read_to_string(&path).ok())
        {
            Some(raw) => {
                apply_dotenv_text(&raw);
                true
            }
            None => false,
        };
        apply_dotenv_text(BAKED_ENV);
        let coord = std::env::var("GHALBOL_COORD_URLS").unwrap_or_else(|_| "(unset)".into());
        let app_id = std::env::var("GHALBOL_APP_ID").unwrap_or_default();
        let src = if from_file { path.as_str() } else { "baked" };
        // Visible in logcat / stderr so wrong-profile installs are obvious.
        eprintln!(
            "ghalbol env profile={profile} src={src} GHALBOL_APP_ID={app_id} GHALBOL_COORD_URLS={coord}"
        );
    });
}

/// Parsed dotenv pair when the line is valid shell assignment syntax.
pub(crate) fn parse_dotenv_line(line: &str) -> Option<(String, String)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }
    let s = s.strip_prefix("export ").unwrap_or(s);
    let (key, val) = s.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    let mut val = val.trim().to_string();
    if val.len() > 8 * 1024 {
        return None;
    }
    if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
    {
        val = val[1..val.len() - 1].to_string();
    }
    Some((key.to_string(), val))
}

pub(crate) fn apply_dotenv_text(raw: &str) {
    for line in raw.lines() {
        let Some((key, val)) = parse_dotenv_line(line) else {
            continue;
        };
        if std::env::var(&key).is_ok() {
            continue;
        }
        // SAFETY: process env is set once at startup before network reads it.
        unsafe { std::env::set_var(&key, val) };
    }
}

/// Strip one layer of surrounding quotes from desktop launcher argv invites.
pub(crate) fn strip_surrounding_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].trim().to_string()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::short_key;

    #[test]
    fn short_key_abbreviates_ascii_wires() {
        let pk = "0123456789abcdef0123456789abcdef";
        let s = short_key(pk);
        assert!(s.contains('…'), "{s}");
        assert!(s.starts_with("01234567"), "{s}");
    }

    #[test]
    fn short_key_does_not_panic_on_non_ascii() {
        let s = short_key(&"é".repeat(40));
        assert!(s.chars().count() <= 16);
    }

    #[test]
    fn parse_dotenv_skips_comments_and_bad_keys() {
        use super::parse_dotenv_line;
        assert!(parse_dotenv_line("# comment").is_none());
        assert!(parse_dotenv_line("not-an-assignment").is_none());
        assert!(parse_dotenv_line("bad-key=val").is_none());
        let (k, v) = parse_dotenv_line("export GHALBOL_APP_ID=\"com.test\"").unwrap();
        assert_eq!(k, "GHALBOL_APP_ID");
        assert_eq!(v, "com.test");
    }

    #[test]
    fn strip_surrounding_quotes_from_argv() {
        use super::strip_surrounding_quotes;
        assert_eq!(
            strip_surrounding_quotes("\"ghalbol://join\""),
            "ghalbol://join"
        );
        assert_eq!(strip_surrounding_quotes("  'https://x'  "), "https://x");
    }
}
