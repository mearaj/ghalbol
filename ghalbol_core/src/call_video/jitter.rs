//! Keyframe-aware video jitter buffer.
//!
//! Unlike the audio jitter buffer, video frames have inter-frame dependencies: a
//! delta (inter) frame is undecodable without its reference chain back to a
//! keyframe. So this buffer:
//!   - never starts before it has a keyframe (can't decode delta-first),
//!   - reorders by `frame_seq` and emits in order,
//!   - on an unrecoverable gap, **jumps forward to the next keyframe** rather than
//!     feeding the decoder garbage, and
//!   - raises a **keyframe request** flag (the transport sends `key_request` so the
//!     sender forces an IDR) when it is stalled behind a gap with no newer keyframe.

use std::collections::BTreeMap;

use super::codec::EncodedVideoFrame;

pub struct VideoJitter {
    map: BTreeMap<u32, EncodedVideoFrame>,
    next_seq: Option<u32>,
    started: bool,
    max_depth: usize,
    keyframe_request: bool,
}

impl VideoJitter {
    pub fn new(max_depth: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            next_seq: None,
            started: false,
            max_depth: max_depth.max(2),
            keyframe_request: false,
        }
    }

    /// How far ahead of the play cursor / buffer base we accept (bounds sparse-seq DoS).
    fn forward_window(&self) -> u32 {
        (self.max_depth as u32).saturating_add(8)
    }

    fn forward_base(&self, incoming: u32) -> u32 {
        match (self.next_seq, self.map.keys().next().copied()) {
            (Some(n), _) => n,
            (None, Some(k)) => k,
            (None, None) => incoming,
        }
    }

    /// Insert a completed encoded frame. Frames older than the play cursor are
    /// dropped; overflow drops the oldest and flags that a keyframe is needed to
    /// resync cleanly.
    pub fn push(&mut self, frame_seq: u32, frame: EncodedVideoFrame) {
        if let Some(n) = self.next_seq {
            if frame_seq < n {
                return;
            }
        }
        let base = self.forward_base(frame_seq);
        if frame_seq > base.saturating_add(self.forward_window()) {
            self.keyframe_request = true;
            return;
        }
        self.map.insert(frame_seq, frame);
        while self.map.len() > self.max_depth {
            let oldest = match self.map.keys().next().copied() {
                Some(k) => k,
                None => break,
            };
            self.map.remove(&oldest);
            if let Some(n) = self.next_seq {
                if oldest >= n {
                    self.next_seq = Some(oldest + 1);
                }
            }
            self.keyframe_request = true;
        }
    }

    /// Produce the next frame to decode/render, or `None` if nothing is renderable
    /// this tick (still buffering, missing frame, or waiting for a keyframe).
    pub fn pop(&mut self) -> Option<EncodedVideoFrame> {
        if self.map.is_empty() {
            return None;
        }
        if !self.started {
            // Can't decode a delta before a keyframe — start at the earliest keyframe.
            match self.map.iter().find(|(_, f)| f.keyframe).map(|(&s, _)| s) {
                Some(s) => {
                    let pre: Vec<u32> = self.map.range(..s).map(|(&k, _)| k).collect();
                    for k in pre {
                        self.map.remove(&k);
                    }
                    self.next_seq = Some(s);
                    self.started = true;
                }
                None => {
                    self.keyframe_request = true;
                    return None;
                }
            }
        }
        let n = self.next_seq?;
        if let Some(frame) = self.map.remove(&n) {
            self.next_seq = Some(n + 1);
            return Some(frame);
        }
        // `n` is missing. Recover cleanly by jumping to the next keyframe if one is
        // buffered (a delta after a gap can't be decoded anyway).
        if let Some(ks) = self.map.iter().find(|(_, f)| f.keyframe).map(|(&s, _)| s) {
            let pre: Vec<u32> = self.map.range(..ks).map(|(&k, _)| k).collect();
            for k in pre {
                self.map.remove(&k);
            }
            let Some(frame) = self.map.remove(&ks) else {
                self.keyframe_request = true;
                return None;
            };
            self.next_seq = Some(ks + 1);
            return Some(frame);
        }
        // Gap with no recovery keyframe buffered: stall (don't render garbage) and
        // ask the sender for a keyframe. The transport throttles the actual request.
        self.keyframe_request = true;
        None
    }

    /// Take and clear the pending keyframe-request flag (polled by the transport).
    pub fn take_keyframe_request(&mut self) -> bool {
        let r = self.keyframe_request;
        self.keyframe_request = false;
        r
    }

    #[cfg(test)]
    fn buffered_len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_video::codec::EncodedVideoFrame;

    fn enc(keyframe: bool) -> EncodedVideoFrame {
        EncodedVideoFrame {
            keyframe,
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn push_rejects_sparse_seq_far_ahead_of_window() {
        let mut j = VideoJitter::new(4);
        j.push(10, enc(true));
        assert_eq!(j.buffered_len(), 1);
        j.push(10 + j.forward_window() + 1, enc(false));
        assert_eq!(j.buffered_len(), 1);
        assert!(j.take_keyframe_request());
    }
}
