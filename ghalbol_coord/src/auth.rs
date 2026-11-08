//! Challenge nonce issuance and per-algorithm registration signature verification.

use crate::error::{ApiResult, ServerError};
use crate::identity::{Identity, IdentityAlgorithm, normalize_identity_wire};
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
use p256::ecdsa::{
    Signature as EcdsaSig, VerifyingKey as EcdsaVerifyingKey, signature::Verifier as EcdsaVerifier,
};
use rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Register and bridge nonces must not share a slot. A call-setup challenge used
/// to overwrite an in-flight presence challenge for the same identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChallengePurpose {
    Register,
    Bridge,
}

impl ChallengePurpose {
    fn key_prefix(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Bridge => "bridge",
        }
    }
}

/// Pending challenge returned to the caller.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub expires_at: Instant,
}

/// Cap on distinct pending challenges. Re-issuing an existing one does not take a new slot.
pub const MAX_PENDING_CHALLENGES: usize = 8_192;

/// Real signatures are 64 bytes (ed25519) or about 72 (DER).
pub const MAX_SIGNATURE_BYTES: usize = 128;

/// In-memory challenge table (per process; replace with Redis etc. when scaling).
pub struct ChallengeStore {
    pending: HashMap<String, PendingChallenge>,
    max_pending: usize,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: MAX_PENDING_CHALLENGES,
        }
    }
}

impl ChallengeStore {
    #[cfg(test)]
    pub fn with_max_pending(max_pending: usize) -> Self {
        Self {
            pending: HashMap::new(),
            max_pending: max_pending.max(1),
        }
    }

    fn map_key(&self, purpose: ChallengePurpose, identity_wire: &str) -> ApiResult<String> {
        let identity = normalize_identity_wire(identity_wire)?;
        Ok(format!("{}\n{identity}", purpose.key_prefix()))
    }

    /// Issue a nonce, or return the current unexpired one.
    ///
    /// Rotating on every request lets a second caller invalidate a signature
    /// that is already in flight.
    pub fn issue(
        &mut self,
        purpose: ChallengePurpose,
        identity_wire: &str,
        ttl: Duration,
    ) -> ApiResult<PendingChallenge> {
        self.purge_expired();
        let key = self.map_key(purpose, identity_wire)?;
        if let Some(existing) = self.pending.get(&key) {
            return Ok(existing.clone());
        }
        if self.pending.len() >= self.max_pending {
            return Err(ServerError::RateLimited(
                "too many pending challenges".into(),
            ));
        }
        let mut nonce = [0u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        let challenge = PendingChallenge {
            nonce,
            expires_at: Instant::now() + ttl,
        };
        self.pending.insert(key, challenge.clone());
        Ok(challenge)
    }

    /// Match the nonce without consuming it. Call [`Self::take_valid`] only after
    /// the signature verifies, still under the same lock.
    pub fn peek_valid(
        &mut self,
        purpose: ChallengePurpose,
        identity_wire: &str,
        nonce: &[u8; 32],
    ) -> ApiResult<()> {
        self.nonce_status(purpose, identity_wire, nonce, false)
    }

    pub fn take_valid(
        &mut self,
        purpose: ChallengePurpose,
        identity_wire: &str,
        nonce: &[u8; 32],
    ) -> ApiResult<()> {
        self.nonce_status(purpose, identity_wire, nonce, true)
    }

    fn nonce_status(
        &mut self,
        purpose: ChallengePurpose,
        identity_wire: &str,
        nonce: &[u8; 32],
        consume: bool,
    ) -> ApiResult<()> {
        let key = self.map_key(purpose, identity_wire)?;
        let Some(ch) = self.pending.get(&key).cloned() else {
            return Err(ServerError::Unauthorized(
                "no pending challenge for this identity".into(),
            ));
        };
        if Instant::now() > ch.expires_at {
            self.pending.remove(&key);
            return Err(ServerError::Unauthorized("challenge expired".into()));
        }
        if !nonce_eq(&ch.nonce, nonce) {
            // A wrong guess must not force the legitimate client to re-issue.
            return Err(ServerError::Unauthorized("challenge nonce mismatch".into()));
        }
        if consume {
            self.pending.remove(&key);
        }
        Ok(())
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.pending.retain(|_, ch| now <= ch.expires_at);
    }
}

/// 32-byte challenge nonces are at most 64 hex digits.
pub const MAX_NONCE_HEX_LEN: usize = 64;

pub fn decode_nonce_hex(hex_s: &str) -> ApiResult<[u8; 32]> {
    let trimmed = hex_s.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_NONCE_HEX_LEN
        || !trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ServerError::BadRequest("nonce_hex: invalid".into()));
    }
    let bytes = hex::decode(trimmed).map_err(|_| ServerError::BadRequest("nonce_hex: invalid".into()))?;
    if bytes.len() != 32 {
        return Err(ServerError::BadRequest(format!(
            "nonce_hex: expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_signature_hex(hex_s: &str) -> ApiResult<Vec<u8>> {
    let trimmed = hex_s.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_SIGNATURE_BYTES * 2
        || !trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ServerError::BadRequest("signature length invalid".into()));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| ServerError::BadRequest("signature_hex: invalid".into()))?;
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(ServerError::BadRequest("signature length invalid".into()));
    }
    Ok(bytes)
}

fn nonce_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Matches client `coord_register_auth` / delivery identity wire ceilings.
const MAX_REGISTER_IDENTITY_WIRE_BYTES: usize = 256;

/// Canonical registration challenge bytes (all algorithms).
/// Returns empty when the wire is empty or oversized (verify paths already normalize first).
pub fn registration_challenge_bytes(nonce: &[u8; 32], identity_wire: &str) -> Vec<u8> {
    let wire = identity_wire.trim();
    if wire.is_empty() || wire.len() > MAX_REGISTER_IDENTITY_WIRE_BYTES {
        return Vec::new();
    }
    format!(
        "ghalbol:register:v1\n{}\n{}",
        hex::encode(nonce),
        wire.to_ascii_lowercase()
    )
    .into_bytes()
}

/// secp256k1 digest of [`registration_challenge_bytes`] — legacy helper for coord_client.
pub fn registration_message_digest(nonce: &[u8; 32], identity_wire: &str) -> Message {
    let body = registration_challenge_bytes(nonce, identity_wire);
    let hash = Sha256::digest(&body);
    Message::from_digest(hash.into())
}

pub fn verify_registration_signature(
    identity_wire: &str,
    nonce: &[u8; 32],
    signature: &[u8],
) -> ApiResult<()> {
    let wire = normalize_identity_wire(identity_wire)?;
    let id = Identity::parse(&wire)?;
    let challenge = registration_challenge_bytes(nonce, &wire);
    match id.algorithm {
        IdentityAlgorithm::Secp256k1 => {
            let pk = PublicKey::from_slice(&id.public_key)
                .map_err(|_| ServerError::BadRequest("secp256k1 public key invalid".into()))?;
            let msg = registration_message_digest(nonce, &wire);
            let sig = Signature::from_der(signature)
                .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?;
            Secp256k1::verification_only()
                .verify_ecdsa(msg, &sig, &pk)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
        IdentityAlgorithm::Ed25519 => {
            let arr: [u8; 32] = id.public_key.as_slice().try_into().map_err(|_| {
                ServerError::BadRequest("ed25519 public key: invalid length".into())
            })?;
            let vk = VerifyingKey::from_bytes(&arr)
                .map_err(|_| ServerError::BadRequest("ed25519 public key invalid".into()))?;
            let sig = Ed25519Sig::from_slice(signature)
                .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?;
            vk.verify(&challenge, &sig)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
        IdentityAlgorithm::EcdsaP256 => {
            let vk = EcdsaVerifyingKey::from_sec1_bytes(&id.public_key)
                .map_err(|_| ServerError::BadRequest("ecdsa-p256 public key invalid".into()))?;
            let sig = EcdsaSig::from_der(signature)
                .or_else(|_| EcdsaSig::from_slice(signature))
                .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?;
            EcdsaVerifier::verify(&vk, &challenge, &sig)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use secp256k1::SecretKey;

    #[test]
    fn secp256k1_roundtrip_sign_verify() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([1u8; 32]).expect("test key");
        let pk_hex = hex::encode(sk.public_key(&secp).serialize());
        let nonce = [7u8; 32];
        let msg = registration_message_digest(&nonce, &pk_hex);
        let sig = secp.sign_ecdsa(msg, &sk);
        verify_registration_signature(&pk_hex, &nonce, &sig.serialize_der()).unwrap();
    }

    #[test]
    fn ed25519_roundtrip_sign_verify() {
        let signing = SigningKey::from_bytes(&[2u8; 32]);
        let wire = format!(
            "ed25519:{}",
            hex::encode(signing.verifying_key().to_bytes())
        );
        let nonce = [8u8; 32];
        let challenge = registration_challenge_bytes(&nonce, &wire);
        let sig = signing.sign(&challenge);
        verify_registration_signature(&wire, &nonce, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn explicit_secp256k1_prefix_roundtrip() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([4u8; 32]).expect("test key");
        let bare = hex::encode(sk.public_key(&secp).serialize());
        let wire = format!("secp256k1:{bare}");
        let normalized = normalize_identity_wire(&wire).unwrap();
        let nonce = [5u8; 32];
        let msg = registration_message_digest(&nonce, &normalized);
        let sig = secp.sign_ecdsa(msg, &sk);
        verify_registration_signature(&wire, &nonce, &sig.serialize_der()).unwrap();
    }

    fn wire_from_seed(seed: u8) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array([seed; 32]).expect("test key");
        hex::encode(sk.public_key(&secp).serialize())
    }

    #[test]
    fn challenge_consumed_and_replay_rejected() {
        let mut store = ChallengeStore::default();
        let wire = wire_from_seed(3);
        let ch = store
            .issue(ChallengePurpose::Register, &wire, Duration::from_secs(60))
            .unwrap();
        store
            .take_valid(ChallengePurpose::Register, &wire, &ch.nonce)
            .unwrap();
        let replay = store
            .take_valid(ChallengePurpose::Register, &wire, &ch.nonce)
            .unwrap_err();
        assert!(matches!(replay, ServerError::Unauthorized(_)));
    }

    #[test]
    fn challenge_nonce_mismatch_rejected() {
        let mut store = ChallengeStore::default();
        let wire = wire_from_seed(3);
        let ch = store
            .issue(ChallengePurpose::Register, &wire, Duration::from_secs(60))
            .unwrap();
        let wrong = [0u8; 32];
        let err = store
            .take_valid(ChallengePurpose::Register, &wire, &wrong)
            .unwrap_err();
        assert!(matches!(
            err,
            ServerError::Unauthorized(ref m) if m.contains("nonce mismatch")
        ));
        // Wrong nonce must leave the challenge so the legitimate client can still register.
        store
            .take_valid(ChallengePurpose::Register, &wire, &ch.nonce)
            .unwrap();
    }

    #[test]
    fn reissue_keeps_nonce_and_purposes_do_not_clobber() {
        let mut store = ChallengeStore::default();
        let wire = wire_from_seed(6);
        let ttl = Duration::from_secs(60);
        let first = store.issue(ChallengePurpose::Register, &wire, ttl).unwrap();
        let second = store.issue(ChallengePurpose::Register, &wire, ttl).unwrap();
        assert_eq!(first.nonce, second.nonce);
        let bridge = store.issue(ChallengePurpose::Bridge, &wire, ttl).unwrap();
        assert_ne!(bridge.nonce, first.nonce);
        store
            .take_valid(ChallengePurpose::Register, &wire, &first.nonce)
            .unwrap();
        store
            .peek_valid(ChallengePurpose::Bridge, &wire, &bridge.nonce)
            .unwrap();
    }

    #[test]
    fn pending_cap_rejects_new_identity_but_not_reissue() {
        let mut store = ChallengeStore::with_max_pending(1);
        let a = wire_from_seed(6);
        let b = wire_from_seed(7);
        let ttl = Duration::from_secs(60);
        let first = store.issue(ChallengePurpose::Register, &a, ttl).unwrap();
        let again = store.issue(ChallengePurpose::Register, &a, ttl).unwrap();
        assert_eq!(first.nonce, again.nonce);
        let err = store
            .issue(ChallengePurpose::Register, &b, ttl)
            .unwrap_err();
        assert!(matches!(err, ServerError::RateLimited(_)));
    }

    #[test]
    fn decode_nonce_hex_rejects_oversized_before_decode() {
        let huge = "aa".repeat(MAX_NONCE_HEX_LEN + 1);
        assert!(matches!(
            decode_nonce_hex(&huge),
            Err(ServerError::BadRequest(ref m)) if m.contains("nonce_hex")
        ));
        assert!(decode_nonce_hex(&"00".repeat(32)).is_ok());
    }

    #[test]
    fn decode_signature_hex_rejects_empty_and_oversized() {
        assert!(matches!(
            decode_signature_hex(""),
            Err(ServerError::BadRequest(ref m)) if m.contains("length invalid")
        ));
        let huge = "00".repeat(MAX_SIGNATURE_BYTES + 1);
        assert!(matches!(
            decode_signature_hex(&huge),
            Err(ServerError::BadRequest(ref m)) if m.contains("length invalid")
        ));
        assert!(decode_signature_hex(&"00".repeat(64)).is_ok());
    }

    #[test]
    fn peek_valid_does_not_consume_on_verify_failure_path() {
        let mut store = ChallengeStore::default();
        let wire = wire_from_seed(8);
        let ch = store
            .issue(ChallengePurpose::Register, &wire, Duration::from_secs(60))
            .unwrap();
        store
            .peek_valid(ChallengePurpose::Register, &wire, &ch.nonce)
            .unwrap();
        store
            .take_valid(ChallengePurpose::Register, &wire, &ch.nonce)
            .unwrap();
    }

    #[test]
    fn expired_challenge_frees_pending_cap_after_purge() {
        let mut store = ChallengeStore::with_max_pending(2);
        let ttl = Duration::from_millis(50);
        let a = wire_from_seed(20);
        let b = wire_from_seed(21);
        let ch_a = store.issue(ChallengePurpose::Register, &a, ttl).unwrap();
        store.issue(ChallengePurpose::Register, &b, ttl).unwrap();
        let err = store
            .issue(ChallengePurpose::Register, &wire_from_seed(22), ttl)
            .unwrap_err();
        assert!(matches!(err, ServerError::RateLimited(_)));

        std::thread::sleep(Duration::from_millis(60));
        let err = store
            .take_valid(ChallengePurpose::Register, &a, &ch_a.nonce)
            .unwrap_err();
        assert!(matches!(
            err,
            ServerError::Unauthorized(ref m) if m.contains("expired")
        ));
        store.purge_expired();
        let after = store
            .issue(ChallengePurpose::Register, &wire_from_seed(22), Duration::from_secs(60))
            .unwrap();
        assert_eq!(after.nonce.len(), 32);
    }

    #[test]
    fn verify_registration_rejects_signature_from_wrong_key() {
        let secp = Secp256k1::new();
        let sk_real = SecretKey::from_byte_array([1u8; 32]).expect("test key");
        let sk_other = SecretKey::from_byte_array([9u8; 32]).expect("test key");
        let pk_hex = hex::encode(sk_real.public_key(&secp).serialize());
        let nonce = [7u8; 32];
        let msg = registration_message_digest(&nonce, &pk_hex);
        let sig = secp.sign_ecdsa(msg, &sk_other);
        assert!(verify_registration_signature(&pk_hex, &nonce, &sig.serialize_der()).is_err());
    }

    #[test]
    fn registration_challenge_bytes_rejects_empty_and_oversized_wire() {
        let nonce = [3u8; 32];
        assert!(registration_challenge_bytes(&nonce, "").is_empty());
        assert!(registration_challenge_bytes(&nonce, "  ").is_empty());
        let huge = "a".repeat(MAX_REGISTER_IDENTITY_WIRE_BYTES + 1);
        assert!(registration_challenge_bytes(&nonce, &huge).is_empty());
        let ok = registration_challenge_bytes(&nonce, &"ab".repeat(32));
        assert!(!ok.is_empty());
        assert!(ok.starts_with(b"ghalbol:register:v1\n"));
    }
}
