//! Offline encrypt-to-identity (no active transport session).
//!
//! Used by the delivery mailbox (`delivery_msg_v1`) so text / voice / files can be
//! sealed to a contact's identity key without a live P2P session.
//!
//! | Prefix | Algorithm | KEM |
//! |--------|-----------|-----|
//! | `0x10` | secp256k1 | ephemeral secp256k1 ECDH |
//! | `0x11` | ed25519 | ephemeral X25519 after birational map |
//! | `0x12` | ecdsa-p256 | ephemeral P-256 ECDH |
//!
//! Wire body (all prefixes): `u32le(ephemeral_pub_len) ‖ ephemeral_pub ‖ nonce12 ‖ aes-gcm-ct`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand_core::{OsRng, RngCore};
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey as SecpSecretKey};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::identity::IdentityAlgorithm;
use crate::keystore_v1::DecryptedIdentity;

pub const OFFLINE_CIPHER_SECP256K1_V1: u8 = 0x10;
pub const OFFLINE_CIPHER_ED25519_V1: u8 = 0x11;
pub const OFFLINE_CIPHER_ECDSA_P256_V1: u8 = 0x12;

const AES_GCM_NONCE_LEN: usize = 12;
const HKDF_INFO_ED25519: &[u8] = b"ghalbol_offline_seal_ed25519_v1";
const HKDF_INFO_P256: &[u8] = b"ghalbol_offline_seal_p256_v1";

fn random_secp_secret_key() -> Result<SecpSecretKey, String> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SecpSecretKey::from_byte_array(bytes).map_err(|e| format!("ephemeral secret: {e}"))
}

fn aes_key_from_shared(shared: &[u8], info: &[u8]) -> Result<Key<Aes256Gcm>, String> {
    let hk = hkdf::Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| "offline seal hkdf expand failed".to_string())?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

fn aes_key_sha256(shared: &[u8; 32]) -> Key<Aes256Gcm> {
    // Legacy secp256k1 path — keep SHA-256(shared) so existing mailbox ciphertext still opens.
    let digest = Sha256::digest(shared);
    *Key::<Aes256Gcm>::from_slice(&digest)
}

fn pack_sealed(prefix: u8, ephemeral_pub: &[u8], nonce: &[u8; AES_GCM_NONCE_LEN], ct: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + ephemeral_pub.len() + nonce.len() + ct.len());
    body.extend_from_slice(&(ephemeral_pub.len() as u32).to_le_bytes());
    body.extend_from_slice(ephemeral_pub);
    body.extend_from_slice(nonce);
    body.extend_from_slice(ct);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(prefix);
    out.extend_from_slice(&body);
    out
}

fn unpack_sealed(sealed: &[u8]) -> Result<(u8, &[u8], &[u8], &[u8]), String> {
    let prefix = *sealed
        .first()
        .ok_or_else(|| "offline seal: empty blob".to_string())?;
    let sealed = &sealed[1..];
    if sealed.len() < 4 + 1 + AES_GCM_NONCE_LEN + 16 {
        return Err("sealed blob too short".to_string());
    }
    let pub_len = u32::from_le_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]) as usize;
    if pub_len == 0 || pub_len > 128 || sealed.len() < 4 + pub_len + AES_GCM_NONCE_LEN + 16 {
        return Err("invalid ephemeral pubkey length".to_string());
    }
    let ep_start = 4;
    let ep_end = ep_start + pub_len;
    let nonce_start = ep_end;
    let nonce_end = nonce_start + AES_GCM_NONCE_LEN;
    Ok((
        prefix,
        &sealed[ep_start..ep_end],
        &sealed[nonce_start..nonce_end],
        &sealed[nonce_end..],
    ))
}

fn encrypt_with_key(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> Result<([u8; AES_GCM_NONCE_LEN], Vec<u8>), String> {
    let cipher = Aes256Gcm::new(key);
    // Random nonce per seal. Keys are already ECDH-ephemeral (unique per message), but a
    // fixed zero nonce is brittle if any shared-secret collision or key-reuse path appears.
    // Wire format unchanged: nonce is carried in the sealed blob, so old zero-nonce rows still open.
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "aes-gcm encrypt failed".to_string())?;
    Ok((nonce, ct))
}

fn decrypt_with_key(key: &Key<Aes256Gcm>, nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "aes-gcm decrypt failed".to_string())
}

/// Seal `plaintext` to a secp256k1 public key (33-byte compressed).
pub fn seal_to_secp256k1_public(recipient_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let secp = Secp256k1::new();
    let recipient =
        SecpPublicKey::from_slice(recipient_pk).map_err(|e| format!("recipient pubkey: {e}"))?;
    let ephemeral = random_secp_secret_key()?;
    let ephemeral_pub = ephemeral.public_key(&secp);
    let shared = secp256k1::ecdh::SharedSecret::new(&recipient, &ephemeral);
    let mut shared_arr = [0u8; 32];
    shared_arr.copy_from_slice(&shared.secret_bytes());
    let key = aes_key_sha256(&shared_arr);
    let (nonce, ct) = encrypt_with_key(&key, plaintext)?;
    Ok(pack_sealed(
        OFFLINE_CIPHER_SECP256K1_V1,
        &ephemeral_pub.serialize(),
        &nonce,
        &ct,
    ))
}

/// Open offline seal (`OFFLINE_CIPHER_SECP256K1_V1` only).
pub fn open_sealed_secp256k1(recipient_sk: &SecpSecretKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let (prefix, ephemeral_pub, nonce, ct) = unpack_sealed(sealed)?;
    if prefix != OFFLINE_CIPHER_SECP256K1_V1 {
        return Err("offline seal: unsupported cipher prefix".to_string());
    }
    let ephemeral_pub =
        SecpPublicKey::from_slice(ephemeral_pub).map_err(|e| format!("ephemeral pubkey: {e}"))?;
    let shared = secp256k1::ecdh::SharedSecret::new(&ephemeral_pub, recipient_sk);
    let mut shared_arr = [0u8; 32];
    shared_arr.copy_from_slice(&shared.secret_bytes());
    decrypt_with_key(&aes_key_sha256(&shared_arr), nonce, ct)
}

/// Convert an Ed25519 verifying key to a Montgomery (X25519) public key.
fn ed25519_pk_to_x25519(pk: &[u8]) -> Result<[u8; 32], String> {
    let arr: [u8; 32] = pk
        .try_into()
        .map_err(|_| "ed25519 public key: invalid length".to_string())?;
    let point = CompressedEdwardsY(arr)
        .decompress()
        .ok_or_else(|| "ed25519 public key: invalid point".to_string())?;
    Ok(point.to_montgomery().to_bytes())
}

/// libsodium-compatible Ed25519 seed → X25519 secret (SHA-512 then clamp via StaticSecret).
fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> StaticSecret {
    let hash = Sha512::digest(seed);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&hash[..32]);
    StaticSecret::from(sk)
}

fn seal_to_ed25519_public(recipient_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipient_x = ed25519_pk_to_x25519(recipient_pk)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let ephemeral = StaticSecret::from(seed);
    let ephemeral_pub = X25519Public::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&X25519Public::from(recipient_x));
    let key = aes_key_from_shared(shared.as_bytes(), HKDF_INFO_ED25519)?;
    let (nonce, ct) = encrypt_with_key(&key, plaintext)?;
    Ok(pack_sealed(
        OFFLINE_CIPHER_ED25519_V1,
        ephemeral_pub.as_bytes(),
        &nonce,
        &ct,
    ))
}

fn open_sealed_ed25519(signing: &ed25519_dalek::SigningKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let (prefix, ephemeral_pub, nonce, ct) = unpack_sealed(sealed)?;
    if prefix != OFFLINE_CIPHER_ED25519_V1 {
        return Err("offline seal: expected ed25519 cipher prefix".to_string());
    }
    let eph_arr: [u8; 32] = ephemeral_pub
        .try_into()
        .map_err(|_| "ed25519 seal: ephemeral pubkey length".to_string())?;
    let local = ed25519_seed_to_x25519(&signing.to_bytes());
    let shared = local.diffie_hellman(&X25519Public::from(eph_arr));
    let key = aes_key_from_shared(shared.as_bytes(), HKDF_INFO_ED25519)?;
    decrypt_with_key(&key, nonce, ct)
}

fn seal_to_p256_public(recipient_pk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipient = p256::PublicKey::from_sec1_bytes(recipient_pk)
        .map_err(|e| format!("ecdsa-p256 recipient pubkey: {e}"))?;
    let mut seed = [0u8; 32];
    let ephemeral = loop {
        OsRng.fill_bytes(&mut seed);
        if let Ok(sk) = p256::SecretKey::from_slice(&seed) {
            break sk;
        }
    };
    let ephemeral_pub = ephemeral.public_key();
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let key = aes_key_from_shared(shared.raw_secret_bytes(), HKDF_INFO_P256)?;
    let (nonce, ct) = encrypt_with_key(&key, plaintext)?;
    let ep_bytes = ephemeral_pub.to_sec1_bytes();
    Ok(pack_sealed(
        OFFLINE_CIPHER_ECDSA_P256_V1,
        ep_bytes.as_ref(),
        &nonce,
        &ct,
    ))
}

fn open_sealed_p256(signing: &p256::ecdsa::SigningKey, sealed: &[u8]) -> Result<Vec<u8>, String> {
    let (prefix, ephemeral_pub, nonce, ct) = unpack_sealed(sealed)?;
    if prefix != OFFLINE_CIPHER_ECDSA_P256_V1 {
        return Err("offline seal: expected ecdsa-p256 cipher prefix".to_string());
    }
    let ephemeral = p256::PublicKey::from_sec1_bytes(ephemeral_pub)
        .map_err(|e| format!("ecdsa-p256 ephemeral pubkey: {e}"))?;
    let sk = p256::SecretKey::from(signing.clone());
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), ephemeral.as_affine());
    let key = aes_key_from_shared(shared.raw_secret_bytes(), HKDF_INFO_P256)?;
    decrypt_with_key(&key, nonce, ct)
}

/// Seal plaintext to any shipping identity public key.
pub fn seal_to_identity_public(
    algorithm: IdentityAlgorithm,
    recipient_pk: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        IdentityAlgorithm::Secp256k1 => seal_to_secp256k1_public(recipient_pk, plaintext),
        IdentityAlgorithm::Ed25519 => seal_to_ed25519_public(recipient_pk, plaintext),
        IdentityAlgorithm::EcdsaP256 => seal_to_p256_public(recipient_pk, plaintext),
    }
}

/// Open a sealed blob with the unlocked device identity (all three algorithms).
pub fn open_sealed_for_identity(
    ident: &DecryptedIdentity,
    sealed: &[u8],
) -> Result<Vec<u8>, String> {
    match ident.algorithm() {
        IdentityAlgorithm::Secp256k1 => {
            let sk = ident.try_secp256k1_secret()?;
            open_sealed_secp256k1(sk, sealed)
        }
        IdentityAlgorithm::Ed25519 => {
            let signing = ident
                .ed25519_signing_key()
                .ok_or_else(|| "ed25519 seal: missing signing key".to_string())?;
            open_sealed_ed25519(signing, sealed)
        }
        IdentityAlgorithm::EcdsaP256 => {
            let signing = ident
                .ecdsa_p256_signing_key()
                .ok_or_else(|| "ecdsa-p256 seal: missing signing key".to_string())?;
            open_sealed_p256(signing, sealed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityAlgorithm, generate_secret, public_key_from_secret};
    use crate::keystore_v1::create_keystore_v1_with_algorithm;

    #[test]
    fn roundtrip_secp256k1() {
        let secp = Secp256k1::new();
        let sk = random_secp_secret_key().unwrap();
        let pk = sk.public_key(&secp).serialize();
        let sealed = seal_to_secp256k1_public(&pk, b"hello ghalbol").unwrap();
        assert_eq!(sealed.first(), Some(&OFFLINE_CIPHER_SECP256K1_V1));
        let plain = open_sealed_secp256k1(&sk, &sealed).unwrap();
        assert_eq!(plain, b"hello ghalbol");
    }

    #[test]
    fn secp_seals_use_distinct_nonces() {
        let secp = Secp256k1::new();
        let sk = random_secp_secret_key().unwrap();
        let pk = sk.public_key(&secp).serialize();
        let a = seal_to_secp256k1_public(&pk, b"same plaintext").unwrap();
        let b = seal_to_secp256k1_public(&pk, b"same plaintext").unwrap();
        assert_ne!(a, b, "fresh ephemeral + random nonce must diversify ciphertext");
        // Nonce is after prefix + u32le pub_len + ephemeral pub (33 bytes for secp).
        let (_pa, _ea, na, _ca) = unpack_sealed(&a).unwrap();
        let (_pb, _eb, nb, _cb) = unpack_sealed(&b).unwrap();
        assert_ne!(na, nb);
        assert_eq!(open_sealed_secp256k1(&sk, &a).unwrap(), b"same plaintext");
        assert_eq!(open_sealed_secp256k1(&sk, &b).unwrap(), b"same plaintext");
    }

    #[test]
    fn legacy_zero_nonce_secp_still_opens() {
        let secp = Secp256k1::new();
        let sk = random_secp_secret_key().unwrap();
        let recipient = sk.public_key(&secp);
        let ephemeral = random_secp_secret_key().unwrap();
        let ephemeral_pub = ephemeral.public_key(&secp);
        let shared = secp256k1::ecdh::SharedSecret::new(&recipient, &ephemeral);
        let mut shared_arr = [0u8; 32];
        shared_arr.copy_from_slice(&shared.secret_bytes());
        let key = aes_key_sha256(&shared_arr);
        let cipher = Aes256Gcm::new(&key);
        let zero = [0u8; AES_GCM_NONCE_LEN];
        let ct = cipher
            .encrypt(Nonce::from_slice(&zero), b"legacy-zero".as_ref())
            .unwrap();
        let sealed = pack_sealed(
            OFFLINE_CIPHER_SECP256K1_V1,
            &ephemeral_pub.serialize(),
            &zero,
            &ct,
        );
        assert_eq!(
            open_sealed_secp256k1(&sk, &sealed).unwrap(),
            b"legacy-zero"
        );
    }

    #[test]
    fn roundtrip_ed25519_via_identity() {
        let (_ks, id) =
            create_keystore_v1_with_algorithm("pw", IdentityAlgorithm::Ed25519, None).unwrap();
        let sealed = seal_to_identity_public(
            IdentityAlgorithm::Ed25519,
            id.public_key_bytes(),
            b"ed note",
        )
        .unwrap();
        assert_eq!(sealed.first(), Some(&OFFLINE_CIPHER_ED25519_V1));
        assert_eq!(open_sealed_for_identity(&id, &sealed).unwrap(), b"ed note");
    }

    #[test]
    fn roundtrip_ecdsa_p256_via_identity() {
        let (_ks, id) =
            create_keystore_v1_with_algorithm("pw", IdentityAlgorithm::EcdsaP256, None).unwrap();
        let sealed = seal_to_identity_public(
            IdentityAlgorithm::EcdsaP256,
            id.public_key_bytes(),
            b"p256 note",
        )
        .unwrap();
        assert_eq!(sealed.first(), Some(&OFFLINE_CIPHER_ECDSA_P256_V1));
        assert_eq!(
            open_sealed_for_identity(&id, &sealed).unwrap(),
            b"p256 note"
        );
    }

    #[test]
    fn seal_dispatch_matches_raw_pk() {
        let secret = generate_secret(IdentityAlgorithm::Ed25519).unwrap();
        let pk = public_key_from_secret(IdentityAlgorithm::Ed25519, &secret).unwrap();
        let sealed = seal_to_identity_public(IdentityAlgorithm::Ed25519, &pk, b"x").unwrap();
        assert_eq!(sealed.first(), Some(&OFFLINE_CIPHER_ED25519_V1));
    }
}
