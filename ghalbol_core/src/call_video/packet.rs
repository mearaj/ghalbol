//! Video frame fragmentation + reassembly.
//!
//! A coded video frame is far larger than one media packet (and far larger than a
//! UDP datagram for the future QUIC-datagram transport), so each frame is split
//! into ordered chunks. Each chunk becomes one sealed media packet on the wire.
//! The receiver reassembles chunks by `frame_seq` until `chunk_cnt` are present.
//!
//! Chunk payload (the plaintext that `call_media::MediaCrypto` seals):
//! `frame_seq(4 LE) | chunk_idx(2 LE) | chunk_cnt(2 LE) | flags(1) | codec_bytes`

use std::collections::{BTreeMap, HashMap};

use super::codec::EncodedVideoFrame;

pub const VIDEO_CHUNK_HEADER_LEN: usize = 4 + 2 + 2 + 1;
const FLAG_KEYFRAME: u8 = 0x01;
/// Hard cap on chunks per frame (DoS / reassembly RAM).
const MAX_CHUNKS_PER_FRAME: u16 = 512;
/// Hard cap on codec bytes in one chunk payload.
const MAX_CHUNK_DATA_BYTES: usize = 64 * 1024;
/// Hard cap on reassembled encoded frame size.
const MAX_REASSEMBLED_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Max GCM plaintext for one sealed video chunk (`ts`/`flags` + chunk payload).
pub const MAX_VIDEO_MEDIA_PLAINTEXT: usize =
    5 + VIDEO_CHUNK_HEADER_LEN + MAX_CHUNK_DATA_BYTES;
/// Max sealed on-wire bytes for one video chunk (dir/counter + GCM ciphertext).
pub const MAX_VIDEO_MEDIA_WIRE: usize = 9 + MAX_VIDEO_MEDIA_PLAINTEXT + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoChunk {
    pub frame_seq: u32,
    pub chunk_idx: u16,
    pub chunk_cnt: u16,
    pub keyframe: bool,
    pub data: Vec<u8>,
}

impl VideoChunk {
    pub fn to_payload(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(VIDEO_CHUNK_HEADER_LEN + self.data.len());
        p.extend_from_slice(&self.frame_seq.to_le_bytes());
        p.extend_from_slice(&self.chunk_idx.to_le_bytes());
        p.extend_from_slice(&self.chunk_cnt.to_le_bytes());
        p.push(if self.keyframe { FLAG_KEYFRAME } else { 0 });
        p.extend_from_slice(&self.data);
        p
    }

    pub fn from_payload(payload: &[u8]) -> Result<VideoChunk, String> {
        if payload.len() < VIDEO_CHUNK_HEADER_LEN {
            return Err("video chunk payload too short".to_string());
        }
        let frame_seq = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let chunk_idx = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let chunk_cnt = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        let keyframe = payload[8] & FLAG_KEYFRAME != 0;
        if chunk_cnt == 0 || chunk_cnt > MAX_CHUNKS_PER_FRAME || chunk_idx >= chunk_cnt {
            return Err("video chunk indices invalid".to_string());
        }
        let data = &payload[VIDEO_CHUNK_HEADER_LEN..];
        if data.len() > MAX_CHUNK_DATA_BYTES {
            return Err("video chunk data too large".to_string());
        }
        Ok(VideoChunk {
            frame_seq,
            chunk_idx,
            chunk_cnt,
            keyframe,
            data: data.to_vec(),
        })
    }
}

/// Split one encoded frame into ordered chunks of at most `chunk_data_bytes` codec
/// bytes each. An empty frame still yields one (empty) chunk so it is delivered.
pub fn fragment_frame(
    frame_seq: u32,
    enc: &EncodedVideoFrame,
    chunk_data_bytes: usize,
) -> Vec<VideoChunk> {
    let cdb = chunk_data_bytes.max(1);
    if enc.data.is_empty() {
        return vec![VideoChunk {
            frame_seq,
            chunk_idx: 0,
            chunk_cnt: 1,
            keyframe: enc.keyframe,
            data: Vec::new(),
        }];
    }
    let total = enc.data.len().div_ceil(cdb);
    let take = total.min(MAX_CHUNKS_PER_FRAME as usize);
    let chunk_cnt = take as u16;
    let mut chunks = Vec::with_capacity(take);
    for (i, slice) in enc.data.chunks(cdb).take(take).enumerate() {
        chunks.push(VideoChunk {
            frame_seq,
            chunk_idx: i as u16,
            chunk_cnt,
            keyframe: enc.keyframe,
            data: slice.to_vec(),
        });
    }
    chunks
}

struct Partial {
    chunk_cnt: u16,
    keyframe: bool,
    chunks: BTreeMap<u16, Vec<u8>>,
}

/// Reassembles chunks into complete encoded frames. Bounds memory by capping the
/// number of in-flight partial frames (drops the oldest partial on overflow — a
/// frame that lost a chunk and will never complete).
pub struct Reassembler {
    pending: HashMap<u32, Partial>,
    max_pending: usize,
}

impl Reassembler {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: max_pending.max(2),
        }
    }

    /// Push a received chunk. Returns the completed `(frame_seq, frame)` when the
    /// last missing chunk of a frame arrives.
    pub fn push(&mut self, c: VideoChunk) -> Option<(u32, EncodedVideoFrame)> {
        if c.chunk_cnt == 0
            || c.chunk_cnt > MAX_CHUNKS_PER_FRAME
            || c.chunk_idx >= c.chunk_cnt
            || c.data.len() > MAX_CHUNK_DATA_BYTES
        {
            return None;
        }
        let fs = c.frame_seq;
        if let Some(existing) = self.pending.get(&fs) {
            if existing.chunk_cnt != c.chunk_cnt {
                self.pending.remove(&fs);
                return None;
            }
        }
        let entry = self.pending.entry(fs).or_insert_with(|| Partial {
            chunk_cnt: c.chunk_cnt,
            keyframe: false,
            chunks: BTreeMap::new(),
        });
        entry.keyframe |= c.keyframe;
        let pending_bytes: usize = entry.chunks.values().map(|d| d.len()).sum();
        if pending_bytes.saturating_add(c.data.len()) > MAX_REASSEMBLED_FRAME_BYTES {
            self.pending.remove(&fs);
            return None;
        }
        entry.chunks.insert(c.chunk_idx, c.data);
        let complete = (0..c.chunk_cnt).all(|i| entry.chunks.contains_key(&i));
        if complete {
            let p = self.pending.remove(&fs).unwrap();
            let mut data = Vec::new();
            for (_, d) in p.chunks {
                data.extend_from_slice(&d);
            }
            if data.len() > MAX_REASSEMBLED_FRAME_BYTES {
                return None;
            }
            return Some((
                fs,
                EncodedVideoFrame {
                    keyframe: p.keyframe,
                    data,
                },
            ));
        }
        while self.pending.len() > self.max_pending {
            let oldest = self.pending.keys().min().copied();
            match oldest {
                Some(k) => {
                    self.pending.remove(&k);
                }
                None => break,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_payload_rejects_absurd_chunk_cnt() {
        let mut payload = vec![0u8; VIDEO_CHUNK_HEADER_LEN];
        payload[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(VideoChunk::from_payload(&payload).is_err());
    }

    #[test]
    fn reassembler_drops_chunk_cnt_mismatch() {
        let mut r = Reassembler::new(4);
        assert!(
            r.push(VideoChunk {
                frame_seq: 1,
                chunk_idx: 0,
                chunk_cnt: 2,
                keyframe: false,
                data: vec![1],
            })
            .is_none()
        );
        assert!(
            r.push(VideoChunk {
                frame_seq: 1,
                chunk_idx: 0,
                chunk_cnt: 3,
                keyframe: false,
                data: vec![2],
            })
            .is_none()
        );
        assert!(r.pending.is_empty());
    }

    #[test]
    fn reassembler_waits_for_every_chunk_index() {
        let mut r = Reassembler::new(4);
        assert!(
            r.push(VideoChunk {
                frame_seq: 9,
                chunk_idx: 0,
                chunk_cnt: 2,
                keyframe: false,
                data: vec![1],
            })
            .is_none()
        );
        assert!(
            r.push(VideoChunk {
                frame_seq: 9,
                chunk_idx: 0,
                chunk_cnt: 2,
                keyframe: false,
                data: vec![1],
            })
            .is_none(),
            "duplicate index must not complete early"
        );
        let (_, frame) = r
            .push(VideoChunk {
                frame_seq: 9,
                chunk_idx: 1,
                chunk_cnt: 2,
                keyframe: false,
                data: vec![2],
            })
            .expect("complete");
        assert_eq!(frame.data, vec![1, 2]);
    }

    #[test]
    fn production_chunk_size_fits_video_media_wire() {
        use crate::call_media::MediaCrypto;
        let chunk = VideoChunk {
            frame_seq: 1,
            chunk_idx: 0,
            chunk_cnt: 1,
            keyframe: true,
            data: vec![0u8; 16 * 1024],
        };
        let frame = crate::call_media::MediaFrame {
            seq: 1,
            ts: 1,
            flags: 0,
            payload: chunk.to_payload(),
        };
        let key = [1u8; 32];
        let crypto =
            MediaCrypto::with_limits(&key, true, MAX_VIDEO_MEDIA_WIRE, MAX_VIDEO_MEDIA_PLAINTEXT);
        let wire = crypto.seal(&frame).expect("production-sized chunk must seal");
        assert!(wire.len() <= MAX_VIDEO_MEDIA_WIRE);
        let peer =
            MediaCrypto::with_limits(&key, false, MAX_VIDEO_MEDIA_WIRE, MAX_VIDEO_MEDIA_PLAINTEXT);
        assert!(peer.open(&wire).is_ok());
    }

    #[test]
    fn reassembler_drops_oversized_pending_bytes() {
        let mut r = Reassembler::new(4);
        let per = MAX_CHUNK_DATA_BYTES;
        let chunk_cnt =
            ((MAX_REASSEMBLED_FRAME_BYTES / per) + 1).min(MAX_CHUNKS_PER_FRAME as usize) as u16;
        for idx in 0..chunk_cnt.saturating_sub(1) {
            assert!(
                r.push(VideoChunk {
                    frame_seq: 42,
                    chunk_idx: idx,
                    chunk_cnt,
                    keyframe: true,
                    data: vec![0u8; per],
                })
                .is_none()
            );
        }
        assert!(
            r.push(VideoChunk {
                frame_seq: 42,
                chunk_idx: chunk_cnt - 1,
                chunk_cnt,
                keyframe: true,
                data: vec![0u8; per],
            })
            .is_none(),
            "final chunk would exceed reassembly cap"
        );
        assert!(r.pending.is_empty());
    }

    #[test]
    fn reassembler_completes_two_chunks() {
        let mut r = Reassembler::new(4);
        assert!(
            r.push(VideoChunk {
                frame_seq: 7,
                chunk_idx: 0,
                chunk_cnt: 2,
                keyframe: true,
                data: b"ab".to_vec(),
            })
            .is_none()
        );
        let (seq, frame) = r
            .push(VideoChunk {
                frame_seq: 7,
                chunk_idx: 1,
                chunk_cnt: 2,
                keyframe: false,
                data: b"cd".to_vec(),
            })
            .expect("complete");
        assert_eq!(seq, 7);
        assert!(frame.keyframe);
        assert_eq!(frame.data, b"abcd");
    }
}
