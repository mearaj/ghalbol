//! Per-frame AES-GCM seal using the call media transport key
//! Per-frame AES-GCM seal for call media (`call_media_key::derive_call_media_keys_from_transport`).
//!
//! Both peers share the **same** `frame_key`, so a per-direction byte is mixed
//! into the nonce to guarantee nonce uniqueness across the two senders (GCM
//! nonce reuse under one key is catastrophic). The sender counter is monotonic
//! per direction; together `(dir, counter)` is a unique nonce per (key, packet).
//!
//! Wire packet: `dir(1) || counter(8 LE) || GCM(ts(4) || flags(1) || payload)`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use super::MediaFrame;

/// Opus 20 ms packet upper bound (~1500; [`NullCodec`] test passthrough is 1920).
pub const MAX_AUDIO_CODEC_BYTES: usize = 1920;
/// GCM plaintext: `ts(4) + flags(1) + codec`.
pub const MAX_AUDIO_MEDIA_PLAINTEXT: usize = 5 + MAX_AUDIO_CODEC_BYTES;
/// Sealed voice packet on the wire (`dir + counter + ciphertext`).
pub const MAX_AUDIO_MEDIA_WIRE: usize = 9 + MAX_AUDIO_MEDIA_PLAINTEXT + 16;
/// AES-GCM authentication tag length.
const MEDIA_GCM_TAG_LEN: usize = 16;
/// Minimum GCM plaintext: `ts(4) + flags(1)` (payload may be empty).
const MIN_MEDIA_PLAINTEXT: usize = 5;
/// Minimum on-wire bytes: header + tag + minimum plaintext header.
const MIN_MEDIA_WIRE_LEN: usize = 9 + MEDIA_GCM_TAG_LEN + MIN_MEDIA_PLAINTEXT;

pub struct MediaCrypto {
    cipher: Aes256Gcm,
    /// 0 when local identity sorts lower than peer, else 1 — opposite on each side.
    dir: u8,
    max_wire: usize,
    max_plaintext: usize,
}

impl MediaCrypto {
    pub fn new(frame_key: &[u8; 32], local_is_a: bool) -> Self {
        Self::with_limits(
            frame_key,
            local_is_a,
            MAX_AUDIO_MEDIA_WIRE,
            MAX_AUDIO_MEDIA_PLAINTEXT,
        )
    }

    /// Video chunks carry far larger plaintext than Opus; use limits from `call_video::packet`.
    pub fn with_limits(
        frame_key: &[u8; 32],
        local_is_a: bool,
        max_wire: usize,
        max_plaintext: usize,
    ) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(frame_key));
        Self {
            cipher,
            dir: if local_is_a { 0 } else { 1 },
            max_wire: max_wire.max(64),
            max_plaintext: max_plaintext.max(5),
        }
    }

    fn nonce(dir: u8, counter: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = dir;
        n[4..12].copy_from_slice(&counter.to_le_bytes());
        n
    }

    /// Seal a frame for transmission. Uses our [`dir`] + `frame.seq` as the nonce.
    pub fn seal(&self, frame: &MediaFrame) -> Result<Vec<u8>, String> {
        let mut pt = Vec::with_capacity(5 + frame.payload.len());
        pt.extend_from_slice(&frame.ts.to_le_bytes());
        pt.push(frame.flags);
        pt.extend_from_slice(&frame.payload);
        if pt.len() > self.max_plaintext {
            return Err("media plaintext too large".to_string());
        }

        let nonce = Self::nonce(self.dir, frame.seq);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), pt.as_ref())
            .map_err(|_| "media seal failed".to_string())?;

        let mut wire = Vec::with_capacity(9 + ct.len());
        wire.push(self.dir);
        wire.extend_from_slice(&frame.seq.to_le_bytes());
        wire.extend_from_slice(&ct);
        if wire.len() > self.max_wire {
            return Err("media wire too large".to_string());
        }
        Ok(wire)
    }

    /// Open a received wire packet. The nonce direction comes from the wire (the
    /// peer's direction), so the same shared key decrypts the opposite stream.
    pub fn open(&self, wire: &[u8]) -> Result<MediaFrame, String> {
        if wire.len() < MIN_MEDIA_WIRE_LEN {
            return Err("media wire too short".to_string());
        }
        if wire.len() > self.max_wire {
            return Err("media wire too large".to_string());
        }
        let dir = wire[0];
        if dir > 1 || dir == self.dir {
            return Err("media direction invalid".to_string());
        }
        let counter = u64::from_le_bytes(
            wire[1..9]
                .try_into()
                .map_err(|_| "media counter bytes".to_string())?,
        );
        let ct_len = wire.len() - 9;
        let min_ct = MEDIA_GCM_TAG_LEN + MIN_MEDIA_PLAINTEXT;
        if ct_len < min_ct || ct_len > self.max_plaintext + MEDIA_GCM_TAG_LEN {
            return Err("media ciphertext length invalid".to_string());
        }
        let nonce = Self::nonce(dir, counter);
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), &wire[9..])
            .map_err(|_| "media open failed".to_string())?;
        if pt.len() < 5 || pt.len() > self.max_plaintext {
            return Err("media plaintext length invalid".to_string());
        }
        let ts = u32::from_le_bytes(
            pt[0..4]
                .try_into()
                .map_err(|_| "media ts bytes".to_string())?,
        );
        let flags = pt[4];
        let payload = pt[5..].to_vec();
        Ok(MediaFrame {
            seq: counter,
            ts,
            flags,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_oversized_wire_before_decrypt() {
        let key = [9u8; 32];
        let crypto = MediaCrypto::new(&key, true);
        let huge = vec![0u8; 3_000];
        assert!(crypto.open(&huge).unwrap_err().contains("too large"));
    }

    #[test]
    fn voice_crypto_rejects_video_sized_wire() {
        let key = [2u8; 32];
        let voice = MediaCrypto::new(&key, true);
        let huge = vec![0u8; MAX_AUDIO_MEDIA_WIRE + 1];
        assert!(voice.open(&huge).unwrap_err().contains("too large"));
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [3u8; 32];
        let a = MediaCrypto::new(&key, true);
        let b = MediaCrypto::new(&key, false);
        let frame = MediaFrame {
            seq: 7,
            ts: 42,
            flags: 0,
            payload: b"pcm".to_vec(),
        };
        let wire = a.seal(&frame).unwrap();
        let opened = b.open(&wire).unwrap();
        assert_eq!(opened.seq, 7);
        assert_eq!(opened.payload, b"pcm");
    }

    #[test]
    fn open_rejects_own_direction_byte() {
        let key = [4u8; 32];
        let a = MediaCrypto::new(&key, true);
        let frame = MediaFrame {
            seq: 1,
            ts: 0,
            flags: 0,
            payload: b"x".to_vec(),
        };
        let wire = a.seal(&frame).unwrap();
        assert!(a.open(&wire).unwrap_err().contains("direction invalid"));
    }

    #[test]
    fn open_rejects_invalid_direction() {
        let key = [5u8; 32];
        let rx = MediaCrypto::new(&key, true);
        let mut wire = vec![2u8; MIN_MEDIA_WIRE_LEN];
        assert!(rx.open(&wire).unwrap_err().contains("direction invalid"));
        wire[0] = 0;
        assert!(rx.open(&wire).unwrap_err().contains("direction invalid"));
    }

    #[test]
    fn open_rejects_wire_shorter_than_gcm_tag() {
        let key = [6u8; 32];
        let rx = MediaCrypto::new(&key, true);
        let wire = vec![1u8; MIN_MEDIA_WIRE_LEN - 1];
        assert!(rx.open(&wire).unwrap_err().contains("too short"));
    }

    #[test]
    fn open_rejects_oversized_ciphertext_before_decrypt() {
        let key = [7u8; 32];
        let rx = MediaCrypto::with_limits(&key, true, 5000, 64);
        // dir=1 (peer), counter=0, ciphertext 200 B (> 64 + tag) but wire under max_wire.
        let wire = vec![1u8; 9 + 200];
        assert!(
            rx.open(&wire)
                .unwrap_err()
                .contains("ciphertext length invalid")
        );
    }

    #[test]
    fn open_rejects_tag_only_wire_before_decrypt() {
        let key = [8u8; 32];
        let rx = MediaCrypto::new(&key, true);
        // Ciphertext shorter than tag + 5 B media header — reject before AES-GCM.
        let wire = vec![1u8; 9 + MEDIA_GCM_TAG_LEN + 4];
        let err = rx.open(&wire).unwrap_err();
        assert!(
            err.contains("ciphertext length invalid") || err.contains("too short"),
            "{err}"
        );
    }

    #[test]
    fn seal_rejects_oversized_plaintext() {
        let key = [10u8; 32];
        let tx = MediaCrypto::with_limits(&key, true, 10_000, 32);
        let frame = MediaFrame {
            seq: 0,
            ts: 0,
            flags: 0,
            payload: vec![0u8; 40],
        };
        assert!(
            tx.seal(&frame)
                .unwrap_err()
                .contains("plaintext too large")
        );
    }
}
