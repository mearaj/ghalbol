//! Challenge nonce issuance and signature verification.

use crate::error::{DeliveryError, Result};
use crate::identity::{Identity, IdentityAlgorithm, normalize_identity_wire};
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
use p256::ecdsa::{
    Signature as EcdsaSig, VerifyingKey as EcdsaVerifyingKey,
    signature::Verifier as EcdsaVerifier,
};
use rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Decoded signature cap. Matches the client verifier.
pub const MAX_SIGNATURE_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub nonce: [u8; 32],
    pub expires_at: Instant,
}

struct Slot {
    identity: String,
    challenge: PendingChallenge,
}

/// One session challenge and one op nonce. Each WebSocket owns a store so a
/// second connection cannot replace this socket's handshake or upload nonce.
#[derive(Default)]
pub struct ChallengeStore {
    session: Option<Slot>,
    op: Option<Slot>,
}

fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

impl ChallengeStore {
    pub fn issue_session(&mut self, identity_wire: &str, ttl: Duration) -> Result<PendingChallenge> {
        let key = normalize_identity_wire(identity_wire)?;
        self.purge_expired();
        let challenge = PendingChallenge {
            nonce: random_nonce(),
            expires_at: Instant::now() + ttl,
        };
        self.session = Some(Slot {
            identity: key,
            challenge: challenge.clone(),
        });
        Ok(challenge)
    }

    pub fn take_session_valid(&mut self, identity_wire: &str, nonce: &[u8; 32]) -> Result<()> {
        let key = normalize_identity_wire(identity_wire)?;
        let Some(slot) = self.session.as_ref() else {
            return Err(DeliveryError::Unauthorized(
                "no pending challenge for this identity".into(),
            ));
        };
        if slot.identity != key {
            return Err(DeliveryError::Unauthorized("challenge nonce mismatch".into()));
        }
        if Instant::now() > slot.challenge.expires_at {
            self.session = None;
            return Err(DeliveryError::Unauthorized("challenge expired".into()));
        }
        if slot.challenge.nonce != *nonce {
            // Keep pending: a wrong guess must not force a legitimate client to re-issue.
            return Err(DeliveryError::Unauthorized("challenge nonce mismatch".into()));
        }
        self.session = None;
        Ok(())
    }

    pub fn issue_op_nonce(&mut self, identity_wire: &str, ttl: Duration) -> Result<[u8; 32]> {
        let key = normalize_identity_wire(identity_wire)?;
        self.purge_expired();
        let nonce = random_nonce();
        self.op = Some(Slot {
            identity: key,
            challenge: PendingChallenge {
                nonce,
                expires_at: Instant::now() + ttl,
            },
        });
        Ok(nonce)
    }

    pub fn take_op_valid(&mut self, identity_wire: &str, nonce: &[u8; 32]) -> Result<()> {
        let key = normalize_identity_wire(identity_wire)?;
        let Some(slot) = self.op.as_ref() else {
            return Err(DeliveryError::Unauthorized("no op nonce".into()));
        };
        if slot.identity != key {
            return Err(DeliveryError::Unauthorized("op nonce mismatch".into()));
        }
        if Instant::now() > slot.challenge.expires_at {
            self.op = None;
            return Err(DeliveryError::Unauthorized("op nonce expired".into()));
        }
        if slot.challenge.nonce != *nonce {
            return Err(DeliveryError::Unauthorized("op nonce mismatch".into()));
        }
        self.op = None;
        Ok(())
    }

    /// Put a consumed op nonce back when the mailbox write failed.
    /// Does not overwrite a newer nonce already issued on this connection.
    pub fn restore_op_nonce(
        &mut self,
        identity_wire: &str,
        nonce: [u8; 32],
        ttl: Duration,
    ) -> Result<()> {
        let key = normalize_identity_wire(identity_wire)?;
        if let Some(slot) = self.op.as_ref() {
            if slot.identity != key || slot.challenge.nonce != nonce {
                return Ok(());
            }
        }
        self.op = Some(Slot {
            identity: key,
            challenge: PendingChallenge {
                nonce,
                expires_at: Instant::now() + ttl,
            },
        });
        Ok(())
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        if self
            .session
            .as_ref()
            .is_some_and(|slot| now > slot.challenge.expires_at)
        {
            self.session = None;
        }
        if self
            .op
            .as_ref()
            .is_some_and(|slot| now > slot.challenge.expires_at)
        {
            self.op = None;
        }
    }
}

pub fn session_challenge_bytes(nonce: &[u8; 32], identity_wire: &str) -> Vec<u8> {
    format!(
        "ghalbol:delivery:session:v1\n{}\n{}",
        hex::encode(nonce),
        identity_wire.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

pub fn upload_challenge_bytes(
    nonce: &[u8; 32],
    message_id: &str,
    recipient_wire: &str,
) -> Vec<u8> {
    format!(
        "ghalbol:delivery:upload:v1\n{}\n{}\n{}",
        hex::encode(nonce),
        message_id.trim(),
        recipient_wire.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

pub fn extend_challenge_bytes(nonce: &[u8; 32], message_id: &str) -> Vec<u8> {
    format!(
        "ghalbol:delivery:extend:v1\n{}\n{}",
        hex::encode(nonce),
        message_id.trim()
    )
    .into_bytes()
}

pub fn verify_signature(identity_wire: &str, msg: &[u8], signature: &[u8]) -> Result<()> {
    let wire = normalize_identity_wire(identity_wire)?;
    let id = Identity::parse(&wire)?;
    match id.algorithm {
        IdentityAlgorithm::Secp256k1 => {
            let pk = PublicKey::from_slice(&id.public_key)
                .map_err(|e| DeliveryError::Unauthorized(format!("secp256k1 public key: {e}")))?;
            let hash = Sha256::digest(msg);
            let digest_msg = Message::from_digest(hash.into());
            let sig = Signature::from_der(signature)
                .map_err(|e| DeliveryError::Unauthorized(format!("invalid signature: {e}")))?;
            Secp256k1::verification_only()
                .verify_ecdsa(digest_msg, &sig, &pk)
                .map_err(|e| {
                    DeliveryError::Unauthorized(format!("signature verify failed: {e}"))
                })?;
        }
        IdentityAlgorithm::Ed25519 => {
            let arr: [u8; 32] = id.public_key.as_slice().try_into().map_err(|_| {
                DeliveryError::BadRequest("ed25519 public key: invalid length".into())
            })?;
            let vk = VerifyingKey::from_bytes(&arr)
                .map_err(|e| DeliveryError::BadRequest(format!("ed25519 public key: {e}")))?;
            let sig = Ed25519Sig::from_slice(signature)
                .map_err(|e| DeliveryError::Unauthorized(format!("ed25519 signature: {e}")))?;
            vk.verify(msg, &sig)
                .map_err(|e| DeliveryError::Unauthorized(format!("ed25519 verify: {e}")))?;
        }
        IdentityAlgorithm::EcdsaP256 => {
            let vk = EcdsaVerifyingKey::from_sec1_bytes(&id.public_key)
                .map_err(|e| DeliveryError::BadRequest(format!("ecdsa-p256 public key: {e}")))?;
            let sig = EcdsaSig::from_der(signature)
                .or_else(|_| EcdsaSig::from_slice(signature))
                .map_err(|e| DeliveryError::Unauthorized(format!("ecdsa-p256 signature: {e}")))?;
            EcdsaVerifier::verify(&vk, msg, &sig)
                .map_err(|e| DeliveryError::Unauthorized(format!("ecdsa-p256 verify: {e}")))?;
        }
    }
    Ok(())
}

pub fn parse_nonce_hex(hex_s: &str) -> Result<[u8; 32]> {
    let s = hex_s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DeliveryError::BadRequest("nonce must be 32 bytes".into()));
    }
    let bytes = hex::decode(s)
        .map_err(|e| DeliveryError::BadRequest(format!("nonce hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeliveryError::BadRequest("nonce must be 32 bytes".into()))?;
    Ok(arr)
}

pub fn parse_signature_hex(hex_s: &str) -> Result<Vec<u8>> {
    let s = hex_s.trim();
    if s.is_empty()
        || s.len() > MAX_SIGNATURE_BYTES * 2
        || s.len() % 2 != 0
        || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(DeliveryError::BadRequest("signature hex invalid".into()));
    }
    let bytes = hex::decode(s)
        .map_err(|e| DeliveryError::BadRequest(format!("signature hex: {e}")))?;
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(DeliveryError::BadRequest("signature hex invalid".into()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wire(seed: u8) -> String {
        let sk = secp256k1::SecretKey::from_byte_array([seed; 32]).expect("key");
        let secp = secp256k1::Secp256k1::new();
        hex::encode(sk.public_key(&secp).serialize())
    }

    #[test]
    fn session_wrong_nonce_keeps_challenge() {
        let mut store = ChallengeStore::default();
        let wire = test_wire(3);
        let ch = store
            .issue_session(&wire, Duration::from_secs(60))
            .unwrap();
        let wrong = [0u8; 32];
        assert!(store.take_session_valid(&wire, &wrong).is_err());
        store.take_session_valid(&wire, &ch.nonce).unwrap();
        assert!(store.take_session_valid(&wire, &ch.nonce).is_err());
    }

    #[test]
    fn op_wrong_nonce_keeps_challenge() {
        let mut store = ChallengeStore::default();
        let wire = test_wire(4);
        let nonce = store.issue_op_nonce(&wire, Duration::from_secs(60)).unwrap();
        let wrong = [1u8; 32];
        assert!(store.take_op_valid(&wire, &wrong).is_err());
        store.take_op_valid(&wire, &nonce).unwrap();
    }

    #[test]
    fn reissue_drops_the_previous_connection_challenge() {
        let mut store = ChallengeStore::default();
        let first_id = test_wire(2);
        let second_id = test_wire(3);
        let first = store
            .issue_session(&first_id, Duration::from_secs(60))
            .unwrap();
        let second = store
            .issue_session(&second_id, Duration::from_secs(60))
            .unwrap();
        assert!(store.take_session_valid(&first_id, &first.nonce).is_err());
        store
            .take_session_valid(&second_id, &second.nonce)
            .unwrap();
    }

    #[test]
    fn failed_op_can_be_restored() {
        let mut store = ChallengeStore::default();
        let wire = test_wire(5);
        let nonce = store.issue_op_nonce(&wire, Duration::from_secs(60)).unwrap();
        store.take_op_valid(&wire, &nonce).unwrap();
        store
            .restore_op_nonce(&wire, nonce, Duration::from_secs(60))
            .unwrap();
        store.take_op_valid(&wire, &nonce).unwrap();
    }

    #[test]
    fn parse_nonce_and_signature_reject_oversized_input() {
        assert!(parse_nonce_hex(&"ab".repeat(10_000)).is_err());
        assert!(parse_signature_hex(&"ab".repeat(MAX_SIGNATURE_BYTES + 8)).is_err());
        assert!(parse_signature_hex("abcd").is_ok());
    }

    #[test]
    fn op_nonce_is_single_use() {
        let mut store = ChallengeStore::default();
        let wire = test_wire(9);
        let nonce = store.issue_op_nonce(&wire, Duration::from_secs(60)).unwrap();
        store.take_op_valid(&wire, &nonce).unwrap();
        assert!(store.take_op_valid(&wire, &nonce).is_err());
    }

    #[test]
    fn issue_op_nonce_purges_expired_slot() {
        let mut store = ChallengeStore::default();
        let wire = test_wire(10);
        let nonce = store.issue_op_nonce(&wire, Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let next = store.issue_op_nonce(&wire, Duration::from_secs(60)).unwrap();
        assert_ne!(nonce, next);
        assert!(store.take_op_valid(&wire, &nonce).is_err());
        store.take_op_valid(&wire, &next).unwrap();
    }

    #[test]
    fn extend_signature_does_not_verify_upload_challenge() {
        let wire = test_wire(6);
        let nonce = [7u8; 32];
        let message_id = "ttl-msg";
        let recipient = test_wire(8);
        let upload_msg = upload_challenge_bytes(&nonce, message_id, &recipient);
        let extend_msg = extend_challenge_bytes(&nonce, message_id);
        assert_ne!(upload_msg, extend_msg);

        let sk = secp256k1::SecretKey::from_byte_array([6; 32]).expect("key");
        let secp = secp256k1::Secp256k1::new();
        let digest =
            secp256k1::Message::from_digest(sha2::Sha256::digest(&extend_msg).into());
        let extend_sig = secp.sign_ecdsa(digest, &sk).serialize_der();
        assert!(verify_signature(&wire, &upload_msg, &extend_sig).is_err());
        assert!(verify_signature(&wire, &extend_msg, &extend_sig).is_ok());
    }
}
