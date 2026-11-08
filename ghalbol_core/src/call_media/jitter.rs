//! Adaptive jitter buffer: reorders out-of-order media frames, drops stale ones,
//! and signals gaps so the decoder can run packet-loss concealment (PLC).

use std::collections::BTreeMap;

use super::MediaFrame;

/// What the playout tick should do for this 20 ms slot.
pub enum Playout {
    /// A real frame is ready to decode.
    Frame(MediaFrame),
    /// The next frame is genuinely missing (later frames exist) → run PLC.
    Conceal,
    /// Not enough buffered yet, or underrun → play silence, do not advance.
    Silence,
}

pub struct JitterBuffer {
    /// Frames buffered before playout starts (prebuffer depth).
    target_depth: usize,
    /// Hard cap; beyond this we drop oldest to bound latency.
    max_depth: usize,
    map: BTreeMap<u64, MediaFrame>,
    next_seq: Option<u64>,
    started: bool,
}

impl JitterBuffer {
    pub fn new(target_depth: usize, max_depth: usize) -> Self {
        Self {
            target_depth: target_depth.max(1),
            max_depth: max_depth.max(target_depth.max(1)),
            map: BTreeMap::new(),
            next_seq: None,
            started: false,
        }
    }

    /// How far ahead of the play cursor / buffer base we accept (bounds sparse-seq DoS).
    fn forward_window(&self) -> u64 {
        self.max_depth as u64 + 8
    }

    /// Seq anchor for the forward window: play cursor if set, else earliest buffered.
    fn forward_base(&self, incoming: u64) -> u64 {
        match (self.next_seq, self.map.keys().next().copied()) {
            (Some(n), _) => n,
            (None, Some(k)) => k,
            (None, None) => incoming,
        }
    }

    /// Insert a received frame. Frames older than the play cursor are dropped.
    pub fn push(&mut self, frame: MediaFrame) {
        if let Some(n) = self.next_seq {
            if frame.seq < n {
                return; // too late — already played past this
            }
        }
        let base = self.forward_base(frame.seq);
        if frame.seq > base.saturating_add(self.forward_window()) {
            return; // too far ahead — adversarial sparse seq
        }
        self.map.insert(frame.seq, frame);
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
        }
    }

    /// Drop buffered frames (call teardown / engine reset).
    pub fn clear(&mut self) {
        self.map.clear();
        self.next_seq = None;
        self.started = false;
    }

    #[cfg(test)]
    pub(crate) fn buffered_len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub(crate) fn play_cursor(&self) -> Option<u64> {
        self.next_seq
    }

    /// Produce the next playout decision (call once per 20 ms).
    pub fn pop(&mut self) -> Playout {
        if !self.started {
            if self.map.len() < self.target_depth {
                return Playout::Silence;
            }
            self.started = true;
            self.next_seq = self.map.keys().next().copied();
        }
        let n = match self.next_seq {
            Some(n) => n,
            None => return Playout::Silence,
        };
        if let Some(frame) = self.map.remove(&n) {
            self.next_seq = Some(n + 1);
            return Playout::Frame(frame);
        }
        // n is missing: is there anything newer? then it's a real loss.
        if self.map.range((n + 1)..).next().is_some() {
            self.next_seq = Some(n + 1);
            return Playout::Conceal;
        }
        // Underrun: nothing to play and nothing ahead → re-prebuffer.
        self.started = false;
        Playout::Silence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64, pad: u8) -> MediaFrame {
        MediaFrame {
            seq,
            ts: 0,
            flags: 0,
            payload: vec![pad],
        }
    }

    #[test]
    fn push_is_bounded_by_max_depth() {
        let mut j = JitterBuffer::new(2, 3);
        for seq in 0..20u64 {
            j.push(frame(seq, seq as u8));
        }
        assert!(j.buffered_len() <= 3);
    }

    #[test]
    fn push_rejects_sparse_adversarial_seq() {
        let mut j = JitterBuffer::new(2, 4);
        j.push(frame(0, 1));
        for i in 1..200u64 {
            j.push(frame(i * 10_000, i as u8));
        }
        assert!(
            j.buffered_len() <= 4,
            "sparse far-future seq must not grow the buffer"
        );
    }

    #[test]
    fn forward_window_allows_near_reorder() {
        let mut j = JitterBuffer::new(2, 8);
        j.push(frame(0, 0));
        j.push(frame(5, 5));
        j.push(frame(10, 10));
        assert_eq!(j.buffered_len(), 3);
    }

    #[test]
    fn forward_window_tracks_play_cursor() {
        let mut j = JitterBuffer::new(1, 4);
        for seq in 0..6u64 {
            j.push(frame(seq, seq as u8));
        }
        let _ = j.pop();
        let _ = j.pop();
        let cursor = j.play_cursor().expect("started");
        j.push(frame(cursor + 1_000, 0xAA));
        assert!(j.buffered_len() <= 4);
        j.push(frame(cursor + 4, 0xBB));
        assert!(j.buffered_len() <= 4);
    }

    #[test]
    fn clear_drops_buffered_frames() {
        let mut j = JitterBuffer::new(1, 8);
        j.push(frame(0, 1));
        j.push(frame(1, 2));
        j.clear();
        assert_eq!(j.buffered_len(), 0);
        assert!(j.play_cursor().is_none());
    }
}
