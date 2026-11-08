//! Cross-cutting DM / store diagnostics → Makepad App log (via P2P `native_log` sink when running).

use std::fmt::Display;

#[cfg(not(target_arch = "wasm32"))]
pub fn info(tag: &str, message: impl Display) {
    crate::p2p::native_log::info(tag, message);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn warn(tag: &str, message: impl Display) {
    crate::p2p::native_log::warn(tag, message);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn debug(tag: &str, message: impl Display) {
    crate::p2p::native_log::debug(tag, message);
}

#[cfg(target_arch = "wasm32")]
pub fn info(_tag: &str, _message: impl Display) {}

#[cfg(target_arch = "wasm32")]
pub fn warn(_tag: &str, _message: impl Display) {}

#[cfg(target_arch = "wasm32")]
pub fn debug(_tag: &str, _message: impl Display) {}

/// Shorten hex for log lines (first 8 + last 8).
pub fn short_hex(hex: &str) -> String {
    let s = hex.trim();
    if s.len() <= 20 {
        return s.to_string();
    }
    // Hex wires are ASCII; never panic on a non-ASCII diagnostic string.
    if !s.is_ascii() || s.len() < 16 {
        return s.chars().take(20).collect();
    }
    format!("{}…{}", &s[..8], &s[s.len() - 8..])
}

#[cfg(test)]
mod tests {
    use super::short_hex;

    #[test]
    fn short_hex_keeps_short_and_abbreviates_long_ascii() {
        assert_eq!(short_hex("abcd"), "abcd");
        let long = "0123456789abcdef0123456789abcdef";
        let s = short_hex(long);
        assert!(s.contains('…'), "{s}");
        assert!(s.starts_with("01234567"), "{s}");
        assert!(s.ends_with("89abcdef"), "{s}");
    }

    #[test]
    fn short_hex_stays_under_soft_latency_budget() {
        let long = "0123456789abcdef".repeat(8);
        let start = std::time::Instant::now();
        for _ in 0..50_000 {
            let _ = short_hex(&long);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "50k× short_hex took {elapsed:?}"
        );
    }

    #[test]
    fn short_hex_does_not_panic_on_non_ascii() {
        let mixed = format!("{}{}", "é".repeat(30), "tail");
        let s = short_hex(&mixed);
        assert!(!s.is_empty());
        assert!(s.chars().count() <= 20);
    }
}
