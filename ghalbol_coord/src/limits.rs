//! Sliding-window counters for abuse resistance.
//!
//! Windows are per identity (or other caller-chosen key) and bounded so a
//! scan of random keys cannot grow the map without limit.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    hits: u32,
}

pub struct KeyedRateLimit {
    windows: HashMap<String, Window>,
    max_hits: u32,
    per: Duration,
    max_keys: usize,
}

impl KeyedRateLimit {
    pub fn new(max_hits: u32, per: Duration, max_keys: usize) -> Self {
        Self {
            windows: HashMap::new(),
            max_hits: max_hits.max(1),
            per,
            max_keys: max_keys.max(1),
        }
    }

    /// `true` when this key is still inside its budget.
    pub fn allow(&mut self, key: &str) -> bool {
        let now = Instant::now();
        if let Some(window) = self.windows.get_mut(key) {
            if now.duration_since(window.start) >= self.per {
                window.start = now;
                window.hits = 1;
                return true;
            }
            if window.hits >= self.max_hits {
                return false;
            }
            window.hits += 1;
            return true;
        }
        if self.windows.len() >= self.max_keys {
            self.windows
                .retain(|_, window| now.duration_since(window.start) < self.per);
        }
        if self.windows.len() >= self.max_keys {
            return false;
        }
        self.windows.insert(
            key.to_string(),
            Window {
                start: now,
                hits: 1,
            },
        );
        true
    }
}

/// Heartbeats from a live client are about one every 25s. This stops a tight loop
/// (duplicate threads, or a peer key being poked) without touching normal upkeep.
pub const HEARTBEAT_MAX_HITS: u32 = 8;
pub const HEARTBEAT_WINDOW: Duration = Duration::from_secs(20);

/// Callee bridge poll is about one request every 3s.
pub const BRIDGE_POLL_MAX_HITS: u32 = 40;
pub const BRIDGE_POLL_WINDOW: Duration = Duration::from_secs(10);

const MAX_LIMIT_KEYS: usize = 50_000;

pub fn heartbeat_limiter() -> KeyedRateLimit {
    KeyedRateLimit::new(HEARTBEAT_MAX_HITS, HEARTBEAT_WINDOW, MAX_LIMIT_KEYS)
}

pub fn bridge_poll_limiter() -> KeyedRateLimit {
    KeyedRateLimit::new(BRIDGE_POLL_MAX_HITS, BRIDGE_POLL_WINDOW, MAX_LIMIT_KEYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_blocks_after_budget_then_allows_a_new_key() {
        let mut lim = KeyedRateLimit::new(2, Duration::from_secs(60), 8);
        assert!(lim.allow("a"));
        assert!(lim.allow("a"));
        assert!(!lim.allow("a"));
        assert!(lim.allow("b"));
    }

    #[test]
    fn full_map_rejects_new_keys() {
        let mut lim = KeyedRateLimit::new(5, Duration::from_secs(60), 2);
        assert!(lim.allow("a"));
        assert!(lim.allow("b"));
        assert!(!lim.allow("c"));
        assert!(lim.allow("a"));
    }

    #[test]
    fn expired_windows_evicted_so_map_does_not_grow_forever() {
        let mut lim = KeyedRateLimit::new(5, Duration::from_millis(40), 2);
        assert!(lim.allow("scan-0"));
        assert!(lim.allow("scan-1"));
        assert!(!lim.allow("scan-2"));
        std::thread::sleep(Duration::from_millis(45));
        assert!(lim.allow("scan-2"));
        assert!(lim.allow("scan-3"));
    }
}
