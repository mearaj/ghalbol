//! Adaptive capture/encode quality for WAN, relay, and cellular paths.
//!
//! This layer scales encode resolution and H.264 bitrate from transport pressure.

use super::{RawVideoFrame, i420_downscale_max_edge};

/// Target camera capture (even dimensions). HW/backends may deliver closest size (desktop nokhwa).
pub const CAP_WIDTH: u32 = 640;
pub const CAP_HEIGHT: u32 = 480;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    pub max_edge: u32,
    pub bitrate_bps: u32,
    pub fps: u32,
}

const TIERS: [Tier; 4] = [
    Tier {
        max_edge: 640,
        bitrate_bps: 2_000_000,
        fps: 30,
    },
    Tier {
        max_edge: 560,
        bitrate_bps: 1_500_000,
        fps: 24,
    },
    Tier {
        max_edge: 480,
        bitrate_bps: 1_000_000,
        fps: 20,
    },
    Tier {
        max_edge: 360,
        bitrate_bps: 500_000,
        fps: 12,
    },
];

/// Observes wire-queue drops and steps between [`TIERS`].
#[derive(Debug)]
pub struct AdaptiveQuality {
    tier_idx: usize,
    congested_ticks: u8,
    clear_ticks: u8,
    last_logged_tier: usize,
    /// Peer-advertised cap from `video_on` (0 = uncapped beyond local tiers).
    peer_max_edge: u32,
    /// Capture frames seen since last encode (for fps ladder skip).
    frames_seen: u32,
}

impl AdaptiveQuality {
    pub fn new() -> Self {
        Self {
            tier_idx: 0,
            congested_ticks: 0,
            clear_ticks: 0,
            last_logged_tier: 0,
            peer_max_edge: 0,
            frames_seen: 0,
        }
    }

    /// Returns true when this capture frame should be encoded at the current fps tier.
    /// Assumes capture ≈ 30 fps; skips so effective encode rate ≈ `tier.fps`.
    pub fn should_encode_frame(&mut self) -> bool {
        self.frames_seen = self.frames_seen.wrapping_add(1);
        let fps = self.tier().fps.max(1);
        // Keep every Nth frame: 30/fps rounded.
        let keep_every = (30u32 / fps).max(1);
        self.frames_seen % keep_every == 0
    }

    pub fn set_peer_max_edge(&mut self, max_edge: u32) {
        self.peer_max_edge = max_edge;
    }

    pub fn tier(&self) -> Tier {
        let mut t = TIERS[self.tier_idx];
        if self.peer_max_edge > 0 && t.max_edge > self.peer_max_edge {
            t.max_edge = self.peer_max_edge;
            // Keep bitrate proportional to the clamped edge vs the top tier.
            let scale = (self.peer_max_edge as u64 * t.bitrate_bps as u64)
                / u64::from(TIERS[0].max_edge).max(1);
            t.bitrate_bps = (scale as u32).max(250_000).min(t.bitrate_bps);
        }
        t
    }

    /// Prepare a frame for the encoder at the current tier.
    pub fn frame_for_encode(&self, frame: &RawVideoFrame) -> RawVideoFrame {
        i420_downscale_max_edge(frame, self.tier().max_edge)
    }

    /// Call once per captured frame with wire chunk send stats.
    pub fn note_wire_send(&mut self, drops: u32, total: u32) {
        // A few `try_send` misses on a 256-deep queue are normal — only treat sustained
        // heavy loss as congestion (avoids false tier steps on LAN).
        let congested = total > 0 && drops * 2 > total;
        if congested {
            self.congested_ticks = self.congested_ticks.saturating_add(1);
            self.clear_ticks = 0;
        } else {
            self.clear_ticks = self.clear_ticks.saturating_add(1);
            if self.clear_ticks >= 6 {
                self.congested_ticks = 0;
            }
        }
    }

    /// Periodic tick (~100 ms). Returns new bitrate when the tier changes.
    pub fn tick(&mut self) -> Option<u32> {
        if self.congested_ticks >= 8 && self.tier_idx + 1 < TIERS.len() {
            self.tier_idx += 1;
            self.congested_ticks = 0;
            self.clear_ticks = 0;
            return Some(self.log_tier_change());
        }
        if self.clear_ticks >= 50 && self.tier_idx > 0 {
            self.tier_idx -= 1;
            self.congested_ticks = 0;
            self.clear_ticks = 0;
            return Some(self.log_tier_change());
        }
        None
    }

    fn log_tier_change(&mut self) -> u32 {
        let t = self.tier();
        if self.last_logged_tier != self.tier_idx {
            self.last_logged_tier = self.tier_idx;
            crate::p2p::native_log::info(
                "call_video",
                format!(
                    "quality_tier max_edge={} bitrate_bps={}",
                    t.max_edge, t.bitrate_bps
                ),
            );
        }
        t.bitrate_bps
    }
}

impl Default for AdaptiveQuality {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_down_on_sustained_drops() {
        let mut q = AdaptiveQuality::new();
        assert_eq!(q.tier().max_edge, 640);
        for _ in 0..8 {
            q.note_wire_send(10, 10);
            let _ = q.tick();
        }
        assert_eq!(q.tier().max_edge, 560);
    }

    #[test]
    fn peer_cap_clamps_tier_edge() {
        let mut q = AdaptiveQuality::new();
        q.set_peer_max_edge(360);
        assert_eq!(q.tier().max_edge, 360);
        assert!(q.tier().bitrate_bps <= TIERS[0].bitrate_bps);
    }
}
