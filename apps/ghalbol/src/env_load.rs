//! Process env + baked dotenv.

use ghalbol_core::host;
use makepad_widgets::*;

pub(crate) fn short_key(pk: &str) -> String {
    let t = pk.trim();
    if t.len() <= 16 {
        t.to_string()
    } else {
        format!("{}…{}", &t[..8], &t[t.len() - 4..])
    }
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
        let from_file = match std::fs::read_to_string(&path) {
            Ok(raw) => {
                apply_dotenv_text(&raw);
                true
            }
            Err(_) => false,
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

pub(crate) fn apply_dotenv_text(raw: &str) {
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let s = s.strip_prefix("export ").unwrap_or(s);
        let Some((key, val)) = s.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let mut val = val.trim().to_string();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = val[1..val.len() - 1].to_string();
        }
        if std::env::var(key).is_ok() {
            continue;
        }
        // SAFETY: process env is set once at startup before network reads it.
        unsafe { std::env::set_var(key, val) };
    }
}
