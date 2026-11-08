//! Delivery server challenge signing.

use sha2::{Digest, Sha256};

use crate::identity::IdentityAlgorithm;
use crate::keystore_v1::DecryptedIdentity;

pub fn session_challenge_bytes(nonce: &[u8; 32], identity_wire: &str) -> Vec<u8> {
    format!(
        "ghalbol:delivery:session:v1\n{}\n{}",
        hex::encode(nonce),
        identity_wire.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

pub fn upload_challenge_bytes(nonce: &[u8; 32], message_id: &str, recipient_wire: &str) -> Vec<u8> {
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

pub fn sign_delivery_challenge(ident: &DecryptedIdentity, msg: &[u8]) -> Result<Vec<u8>, String> {
    match ident.algorithm() {
        IdentityAlgorithm::Secp256k1 => {
            let hash = Sha256::digest(msg);
            let digest = secp256k1::Message::from_digest(hash.into());
            let sig =
                secp256k1::Secp256k1::new().sign_ecdsa(digest, ident.try_secp256k1_secret()?);
            Ok(sig.serialize_der().to_vec())
        }
        IdentityAlgorithm::Ed25519 | IdentityAlgorithm::EcdsaP256 => ident.sign_message(msg),
    }
}

/// Verify delivery-server signatures (DER secp256k1 — matches `ghalbol_delivery::auth`).
pub fn verify_delivery_signature(
    identity_wire: &str,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use crate::identity::Identity;
    use crate::public_key_util::normalize_contact_identity_wire;
    use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
    use p256::ecdsa::{
        Signature as EcdsaSig, VerifyingKey as EcdsaVerifyingKey,
        signature::Verifier as EcdsaVerifier,
    };
    use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature as Secp256k1Sig};

    let wire = normalize_contact_identity_wire(identity_wire)?;
    let id = Identity::parse(&wire)?;
    match id.algorithm {
        IdentityAlgorithm::Secp256k1 => {
            let pk = PublicKey::from_slice(&id.public_key)
                .map_err(|e| format!("secp256k1 public key: {e}"))?;
            let hash = Sha256::digest(msg);
            let digest_msg = Message::from_digest(hash.into());
            let sig = Secp256k1Sig::from_der(signature)
                .map_err(|e| format!("secp256k1 signature: {e}"))?;
            Secp256k1::verification_only()
                .verify_ecdsa(digest_msg, &sig, &pk)
                .map_err(|e| format!("secp256k1 verify: {e}"))?;
        }
        IdentityAlgorithm::Ed25519 => {
            let arr: [u8; 32] = id
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| "ed25519 public key: invalid length".to_string())?;
            let vk =
                VerifyingKey::from_bytes(&arr).map_err(|e| format!("ed25519 public key: {e}"))?;
            let sig =
                Ed25519Sig::from_slice(signature).map_err(|e| format!("ed25519 signature: {e}"))?;
            vk.verify(msg, &sig)
                .map_err(|e| format!("ed25519 verify: {e}"))?;
        }
        IdentityAlgorithm::EcdsaP256 => {
            let vk = EcdsaVerifyingKey::from_sec1_bytes(&id.public_key)
                .map_err(|e| format!("ecdsa-p256 public key: {e}"))?;
            let sig = EcdsaSig::from_der(signature)
                .or_else(|_| EcdsaSig::from_slice(signature))
                .map_err(|e| format!("ecdsa-p256 signature: {e}"))?;
            EcdsaVerifier::verify(&vk, msg, &sig).map_err(|e| format!("ecdsa-p256 verify: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityAlgorithm;
    use crate::keystore_v1::{create_keystore_v1, create_keystore_v1_with_algorithm};

    #[test]
    fn session_challenge_is_stable_and_case_folds_wire() {
        let nonce = [7u8; 32];
        let a = session_challenge_bytes(&nonce, "ABCD");
        let b = session_challenge_bytes(&nonce, "abcd");
        assert_eq!(a, b);
        let s = String::from_utf8(a).unwrap();
        assert!(s.starts_with("ghalbol:delivery:session:v1\n"));
        assert!(s.contains(&hex::encode(nonce)));
        assert!(s.ends_with("\nabcd"));
    }

    #[test]
    fn upload_and_extend_challenges_include_fields() {
        let nonce = [1u8; 32];
        let up = String::from_utf8(upload_challenge_bytes(&nonce, " mid ", "EEFF")).unwrap();
        assert!(up.contains("ghalbol:delivery:upload:v1\n"));
        assert!(up.contains("\nmid\n"));
        assert!(up.ends_with("\neeff"));
        let ex = String::from_utf8(extend_challenge_bytes(&nonce, " mid ")).unwrap();
        assert!(ex.contains("ghalbol:delivery:extend:v1\n"));
        assert!(ex.ends_with("\nmid"));
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        let msg = session_challenge_bytes(&[9u8; 32], &id.identity_wire());
        let sig = sign_delivery_challenge(&id, &msg).unwrap();
        verify_delivery_signature(&id.identity_wire(), &msg, &sig).unwrap();
    }

    #[test]
    fn ed25519_and_p256_sign_verify_roundtrip() {
        for algo in [IdentityAlgorithm::Ed25519, IdentityAlgorithm::EcdsaP256] {
            let (_ks, id) = create_keystore_v1_with_algorithm("pw", algo, None).unwrap();
            let msg = upload_challenge_bytes(&[3u8; 32], "m1", &id.identity_wire());
            let sig = sign_delivery_challenge(&id, &msg).unwrap();
            verify_delivery_signature(&id.identity_wire(), &msg, &sig).unwrap();
        }
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        let msg = extend_challenge_bytes(&[2u8; 32], "ok");
        let sig = sign_delivery_challenge(&id, &msg).unwrap();
        let bad = extend_challenge_bytes(&[2u8; 32], "nope");
        assert!(verify_delivery_signature(&id.identity_wire(), &bad, &sig).is_err());
    }
}
