//! AES-256-GCM seal/open with a pre-derived symmetric key (random 12-byte nonce).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand_core::{OsRng, RngCore};

const AES_GCM_NONCE_LEN: usize = 12;
/// Upper bound for session/DM sealed blobs opened via this helper (DoS hardening).
const MAX_SYMMETRIC_SEALED_BYTES: usize = 8 * 1024 * 1024;

/// Seal `plaintext` with `key` — wire: `nonce || ciphertext+tag`.
pub fn seal_symmetric(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_SYMMETRIC_SEALED_BYTES.saturating_sub(AES_GCM_NONCE_LEN + 16) {
        return Err("symmetric plaintext too large".to_string());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "aes-gcm encrypt failed".to_string())?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal_symmetric`].
pub fn open_symmetric(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < AES_GCM_NONCE_LEN + 16 {
        return Err("symmetric sealed blob too short".to_string());
    }
    if sealed.len() > MAX_SYMMETRIC_SEALED_BYTES {
        return Err("symmetric sealed blob too large".to_string());
    }
    let (nonce, ct) = sealed.split_at(AES_GCM_NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "aes-gcm decrypt failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let sealed = seal_symmetric(&key, b"dm session").unwrap();
        let plain = open_symmetric(&key, &sealed).unwrap();
        assert_eq!(plain, b"dm session");
    }

    #[test]
    fn rejects_oversized_sealed_blob() {
        let key = [7u8; 32];
        let huge = vec![0u8; MAX_SYMMETRIC_SEALED_BYTES + 1];
        assert!(open_symmetric(&key, &huge).unwrap_err().contains("too large"));
    }

    #[test]
    fn seal_rejects_oversized_plaintext() {
        let key = [7u8; 32];
        let huge = vec![0u8; MAX_SYMMETRIC_SEALED_BYTES.saturating_sub(AES_GCM_NONCE_LEN + 16) + 1];
        assert!(seal_symmetric(&key, &huge)
            .unwrap_err()
            .contains("plaintext too large"));
    }

    #[test]
    fn open_rejects_corrupt_ciphertext_valid_length() {
        let key = [9u8; 32];
        let sealed = seal_symmetric(&key, b"integrity-check").unwrap();
        let min_len = AES_GCM_NONCE_LEN + 16;
        assert_eq!(sealed.len(), min_len + b"integrity-check".len());
        let mut tampered = sealed.clone();
        let flip = tampered.len() - 3;
        tampered[flip] ^= 0x55;
        let err = open_symmetric(&key, &tampered).unwrap_err();
        assert!(err.contains("decrypt"), "err={err}");
    }

    #[test]
    fn open_rejects_corrupt_nonce_valid_length() {
        let key = [11u8; 32];
        let sealed = seal_symmetric(&key, b"nonce-bound").unwrap();
        let mut tampered = sealed;
        tampered[0] ^= 0x01;
        assert!(open_symmetric(&key, &tampered).is_err());
    }

    /// Soft latency guard — catches accidental O(n²) / huge-alloc regressions on the
    /// mailbox seal hot path. Bound is deliberately loose for slow CI hosts.
    #[test]
    fn seal_open_1kib_stays_under_soft_latency_budget() {
        let key = [3u8; 32];
        let plain = vec![0xA5u8; 1024];
        let start = std::time::Instant::now();
        for _ in 0..200 {
            let sealed = seal_symmetric(&key, &plain).unwrap();
            let out = open_symmetric(&key, &sealed).unwrap();
            assert_eq!(out, plain);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "200× 1KiB seal/open took {elapsed:?} (budget 2s)"
        );
    }
}
