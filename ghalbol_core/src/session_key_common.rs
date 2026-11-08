//! Shared HKDF helpers for transport KEM key expansion.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::identity::Identity;

/// Sorted normalized identity wire strings so both peers expand identical HKDF `info`.
pub(crate) fn identity_pair_binding(local_wire: &str, peer_wire: &str) -> Result<Vec<u8>, String> {
    let mut a = Identity::parse(local_wire)?.to_wire();
    let mut b = Identity::parse(peer_wire)?.to_wire();
    if a == b {
        return Err("peer identity must differ from local identity".to_string());
    }
    if a > b {
        std::mem::swap(&mut a, &mut b);
    }
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a.as_bytes());
    out.extend_from_slice(b.as_bytes());
    Ok(out)
}

/// Soft ceiling — HKDF info is protocol strings / short wires, not megabyte blobs.
const MAX_HKDF_INFO_BYTES: usize = 4_096;

pub(crate) fn hkdf_expand_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    if info.len() > MAX_HKDF_INFO_BYTES {
        return Err("hkdf info too large".to_string());
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_pair_rejects_same_peer() {
        let w = "02".to_string() + &"ab".repeat(32);
        assert!(identity_pair_binding(&w, &w).is_err());
    }

    #[test]
    fn hkdf_rejects_oversized_info() {
        let huge = vec![0u8; MAX_HKDF_INFO_BYTES + 1];
        assert!(hkdf_expand_32(&[1u8; 32], b"salt", &huge)
            .unwrap_err()
            .contains("info too large"));
    }

    #[test]
    fn hkdf_expand_is_deterministic() {
        let a = hkdf_expand_32(b"ikm", b"salt", b"info").unwrap();
        let b = hkdf_expand_32(b"ikm", b"salt", b"info").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_expand_stays_under_soft_latency_budget() {
        let ikm = [7u8; 32];
        let salt = b"ghalbol-soft-latency";
        let info = b"ghalbol:session_key_common:latency";
        let start = std::time::Instant::now();
        for _ in 0..2_000 {
            let _ = hkdf_expand_32(&ikm, salt, info).unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "2000× hkdf_expand_32 took {elapsed:?}"
        );
    }
}
