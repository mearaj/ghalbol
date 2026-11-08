//! Signed bridge request verification (`docs/GHALBOL_CONNECT_V1.md`).

use crate::bridge::validate_call_id;
use crate::error::{ApiResult, ServerError};
use crate::identity::{Identity, normalize_identity_wire};
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as EcdsaSig, VerifyingKey as EcdsaVerifyingKey};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};

/// Canonical bridge request bytes.
pub fn bridge_request_bytes(
    nonce: &[u8; 32],
    caller_wire: &str,
    peer_identity_wire: &str,
    call_id: &str,
) -> ApiResult<Vec<u8>> {
    let caller = normalize_identity_wire(caller_wire)?;
    let peer = normalize_identity_wire(peer_identity_wire)?;
    let call_id = validate_call_id(call_id)?;
    Ok(format!(
        "ghalbol:bridge:request:v1\n{}\n{}\n{}\n{}",
        hex::encode(nonce),
        caller.to_ascii_lowercase(),
        peer.to_ascii_lowercase(),
        call_id
    )
    .into_bytes())
}

pub fn verify_bridge_request_signature(
    caller_wire: &str,
    nonce: &[u8; 32],
    peer_identity_wire: &str,
    call_id: &str,
    signature: &[u8],
) -> ApiResult<()> {
    let wire = normalize_identity_wire(caller_wire)?;
    let msg = bridge_request_bytes(nonce, &wire, peer_identity_wire, call_id)?;
    let id = Identity::parse(&wire)?;
    match id.algorithm {
        crate::identity::IdentityAlgorithm::Secp256k1 => {
            let pk = PublicKey::from_slice(&id.public_key)
                .map_err(|_| ServerError::BadRequest("secp256k1 public key invalid".into()))?;
            let hash = Sha256::digest(&msg);
            let digest = Message::from_digest(hash.into());
            let sig = Signature::from_der(signature)
                .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?;
            Secp256k1::new()
                .verify_ecdsa(digest, &sig, &pk)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
        crate::identity::IdentityAlgorithm::Ed25519 => {
            let pk = VerifyingKey::from_bytes(
                id.public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| ServerError::BadRequest("ed25519 public key invalid".into()))?,
            )
            .map_err(|_| ServerError::BadRequest("ed25519 public key invalid".into()))?;
            let sig = Ed25519Sig::from_bytes(
                signature
                    .try_into()
                    .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?,
            );
            pk.verify(&msg, &sig)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
        crate::identity::IdentityAlgorithm::EcdsaP256 => {
            let pk = EcdsaVerifyingKey::from_sec1_bytes(&id.public_key)
                .map_err(|_| ServerError::BadRequest("ecdsa-p256 public key invalid".into()))?;
            let sig = EcdsaSig::from_der(signature)
                .or_else(|_| EcdsaSig::from_slice(signature))
                .map_err(|_| ServerError::Unauthorized("signature invalid".into()))?;
            pk.verify(&msg, &sig)
                .map_err(|_| ServerError::Unauthorized("signature verify failed".into()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;
    use sha2::{Digest, Sha256};

    fn secp_wire(seed: u8) -> (SecretKey, String) {
        let sk = SecretKey::from_byte_array([seed; 32]).expect("test key");
        let secp = Secp256k1::new();
        let wire = hex::encode(sk.public_key(&secp).serialize());
        (sk, wire)
    }

    fn sign_secp_bridge(sk: &SecretKey, nonce: &[u8; 32], caller: &str, peer: &str, call_id: &str) -> Vec<u8> {
        let msg = bridge_request_bytes(nonce, caller, peer, call_id).unwrap();
        let hash = Sha256::digest(&msg);
        let digest = Message::from_digest(hash.into());
        Secp256k1::new()
            .sign_ecdsa(digest, sk)
            .serialize_der()
            .to_vec()
    }

    #[test]
    fn bridge_request_bytes_rejects_control_call_id() {
        let nonce = [1u8; 32];
        assert!(bridge_request_bytes(&nonce, "aa", "bb", "bad\nid").is_err());
    }

    #[test]
    fn secp256k1_roundtrip_and_explicit_peer_prefix() {
        let (sk, caller) = secp_wire(20);
        let (_sk2, callee_bare) = secp_wire(21);
        let callee_prefixed = format!("secp256k1:{callee_bare}");
        let nonce = [6u8; 32];
        let call_id = "call-test-1";
        let sig = sign_secp_bridge(&sk, &nonce, &caller, &callee_prefixed, call_id);
        verify_bridge_request_signature(&caller, &nonce, &callee_prefixed, call_id, &sig).unwrap();
        let sig2 = sign_secp_bridge(&sk, &nonce, &caller, &callee_bare, call_id);
        verify_bridge_request_signature(&caller, &nonce, &callee_bare, call_id, &sig2).unwrap();
    }
}
