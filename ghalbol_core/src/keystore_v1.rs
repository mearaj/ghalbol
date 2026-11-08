use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use crate::identity::{self, Identity, IdentityAlgorithm};

const KEYSTORE_V1_AAD_PREFIX: &[u8] = b"ghalbol.keystore.v1";
/// AAD prefix written before the `ghal_bol` → `ghalbol` rename. Unlock still accepts it so
/// existing keystores and exported backups keep working; new writes use the current prefix.
const LEGACY_KEYSTORE_V1_AAD_PREFIX: &[u8] = b"ghal_bol.keystore.v1";

/// Reject untrusted keystores that crank Argon2 past our create-time defaults (DoS on unlock).
const MAX_KDF_M_COST_KIB: u32 = 256 * 1024;
const MAX_KDF_T_COST: u32 = 8;
const MAX_KDF_P_COST: u32 = 4;
const MAX_KDF_SALT_LEN: usize = 64;
/// Identity secret ciphertext is a single AEAD blob (32-byte key + 16-byte tag at most).
const MAX_IDENTITY_CIPHERTEXT_LEN: usize = 128;
const MAX_IDENTITY_PUBLIC_KEY_LEN: usize = 128;
/// Defense-in-depth for `from_json_str` (import picker uses the same ceiling in `storage`).
const MAX_KEYSTORE_JSON_BYTES: usize = 1024 * 1024;
/// Import path hex cap (ecdsa-p256 secrets are at most 66 bytes → 132 hex digits).
const MAX_SECRET_IMPORT_HEX_CHARS: usize = 140;

fn bytes_equal_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("keystore json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid keystore: {0}")]
    Invalid(&'static str),

    #[error("invalid keystore: {0}")]
    InvalidMsg(String),

    #[error("kdf parameters rejected")]
    KdfParams,

    #[error("kdf failed")]
    Kdf,

    #[error("decrypt failed (wrong password or corrupted data)")]
    Decrypt,
}

#[derive(Debug, Error)]
pub enum Libp2pIdentityError {
    #[error("legacy libp2p identity removed: {0}")]
    Removed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreV1KdfParams {
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreV1 {
    pub format: String,
    pub kdf: KeystoreV1KdfParams,
    /// Wire algorithm id (`secp256k1`, `ed25519`, …). **Omitted → implicit `secp256k1`**.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_algorithm: Option<String>,
    #[serde(with = "serde_bytes")]
    pub identity_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub identity_ciphertext: Vec<u8>,
}

#[derive(Clone)]
enum IdentityKeyMaterial {
    Secp256k1 { secret: SecretKey },
    Ed25519 { signing: ed25519_dalek::SigningKey },
    EcdsaP256 { signing: p256::ecdsa::SigningKey },
}

/// Unlocked device identity (multi-algorithm; shipping default is secp256k1).
#[derive(Clone)]
pub struct DecryptedIdentity {
    algorithm: IdentityAlgorithm,
    public_key: Vec<u8>,
    material: IdentityKeyMaterial,
}

impl core::fmt::Debug for DecryptedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecryptedIdentity")
            .field("algorithm", &self.algorithm.wire_id())
            .field("public_key", &"<redacted>")
            .finish()
    }
}

impl DecryptedIdentity {
    pub fn algorithm(&self) -> IdentityAlgorithm {
        self.algorithm
    }

    pub fn secp256k1_secret(&self) -> &SecretKey {
        self.try_secp256k1_secret()
            .expect("secp256k1_secret() requires secp256k1 identity")
    }

    /// Prefer this over [`Self::secp256k1_secret`] on mailbox / delivery paths so a
    /// non-secp identity returns `Err` instead of panicking the process.
    pub fn try_secp256k1_secret(&self) -> Result<&SecretKey, String> {
        match &self.material {
            IdentityKeyMaterial::Secp256k1 { secret } => Ok(secret),
            _ => Err(format!(
                "secp256k1 secret required (have {})",
                self.algorithm().wire_id()
            )),
        }
    }

    /// Bare public key hex when algorithm is implicit `secp256k1` (no prefix on wire).
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// Full wire identity per `docs/MULTI_ALGO.md`.
    pub fn identity_wire(&self) -> String {
        Identity::from_public_key_bytes(self.algorithm, self.public_key.clone())
            .expect("unlocked identity public key must be valid")
            .to_wire()
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Whether this identity can run the native connect stack.
    pub fn p2p_ready(&self) -> bool {
        true
    }

    pub(crate) fn ed25519_signing_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        match &self.material {
            IdentityKeyMaterial::Ed25519 { signing } => Some(signing),
            _ => None,
        }
    }

    pub(crate) fn ecdsa_p256_signing_key(&self) -> Option<&p256::ecdsa::SigningKey> {
        match &self.material {
            IdentityKeyMaterial::EcdsaP256 { signing } => Some(signing),
            _ => None,
        }
    }
}

fn validate_kdf_params(kdf: &KeystoreV1KdfParams) -> Result<(), KeystoreError> {
    if kdf.salt.len() < 16 || kdf.salt.len() > MAX_KDF_SALT_LEN {
        return Err(KeystoreError::Invalid("salt length out of range"));
    }
    if kdf.m_cost_kib == 0 || kdf.m_cost_kib > MAX_KDF_M_COST_KIB {
        return Err(KeystoreError::Invalid("kdf m_cost out of range"));
    }
    if kdf.t_cost == 0 || kdf.t_cost > MAX_KDF_T_COST {
        return Err(KeystoreError::Invalid("kdf t_cost out of range"));
    }
    if kdf.p_cost == 0 || kdf.p_cost > MAX_KDF_P_COST {
        return Err(KeystoreError::Invalid("kdf p_cost out of range"));
    }
    Ok(())
}

fn derive_master_key(
    password: &[u8],
    kdf: &KeystoreV1KdfParams,
) -> Result<[u8; 32], KeystoreError> {
    validate_kdf_params(kdf)?;
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|_| KeystoreError::KdfParams)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password, &kdf.salt, &mut out)
        .map_err(|_| KeystoreError::Kdf)?;
    Ok(out)
}

fn derive_aead_key(master: &[u8; 32], purpose: &'static [u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, master);
    let mut okm = [0u8; 32];
    hk.expand(purpose, &mut okm)
        .expect("hkdf expand to 32 bytes cannot fail");
    okm
}

fn aad_for_algorithm(prefix: &[u8], algorithm: IdentityAlgorithm) -> Vec<u8> {
    if algorithm == IdentityAlgorithm::Secp256k1 {
        // Legacy on-disk keystores (no identity_algorithm field) use this AAD.
        aad(prefix, b"identity")
    } else {
        let purpose = format!("identity:{}", algorithm.wire_id());
        aad(prefix, purpose.as_bytes())
    }
}

fn aad(prefix: &[u8], purpose: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + 1 + purpose.len());
    v.extend_from_slice(prefix);
    v.push(b':');
    v.extend_from_slice(purpose);
    v
}

fn keystore_algorithm(ks: &KeystoreV1) -> Result<IdentityAlgorithm, KeystoreError> {
    IdentityAlgorithm::from_keystore_field(ks.identity_algorithm.as_deref())
        .map_err(|e| KeystoreError::InvalidMsg(e))
}

fn validate_public_key_for_keystore(
    algorithm: IdentityAlgorithm,
    public_key: &[u8],
) -> Result<(), KeystoreError> {
    identity::validate_public_key(algorithm, public_key).map_err(|e| KeystoreError::InvalidMsg(e))
}

fn is_legacy_secp256k1_keystore(ks: &KeystoreV1) -> bool {
    ks.identity_algorithm
        .as_deref()
        .map(str::trim)
        .is_none_or(|s| s.is_empty())
}

fn secp256k1_secret_from_bytes(sk: &[u8]) -> Result<SecretKey, KeystoreError> {
    if sk.len() != 32 {
        return Err(KeystoreError::Invalid("bad secret length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(sk);
    SecretKey::from_byte_array(arr).map_err(|_| KeystoreError::Invalid("invalid secp256k1 secret"))
}

fn decrypted_from_secret(
    algorithm: IdentityAlgorithm,
    secret: &[u8],
) -> Result<DecryptedIdentity, KeystoreError> {
    let public_key = identity::public_key_from_secret(algorithm, secret)
        .map_err(|e| KeystoreError::InvalidMsg(e))?;
    let material = match algorithm {
        IdentityAlgorithm::Secp256k1 => {
            let secret = secp256k1_secret_from_bytes(secret)?;
            IdentityKeyMaterial::Secp256k1 { secret }
        }
        IdentityAlgorithm::Ed25519 => {
            let arr: [u8; 32] = secret
                .try_into()
                .map_err(|_| KeystoreError::Invalid("ed25519 secret must be 32 bytes"))?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&arr);
            IdentityKeyMaterial::Ed25519 { signing }
        }
        IdentityAlgorithm::EcdsaP256 => {
            let signing = p256::ecdsa::SigningKey::from_slice(secret)
                .map_err(|_| KeystoreError::Invalid("invalid ecdsa-p256 secret"))?;
            IdentityKeyMaterial::EcdsaP256 { signing }
        }
    };
    Ok(DecryptedIdentity {
        algorithm,
        public_key,
        material,
    })
}

fn encrypt_identity_secret(
    password: &str,
    algorithm: IdentityAlgorithm,
    secret: &[u8],
    public_key: &[u8],
    kdf_override: Option<KeystoreV1KdfParams>,
) -> Result<KeystoreV1, KeystoreError> {
    encrypt_identity_secret_with_aad_prefix(
        password,
        algorithm,
        secret,
        public_key,
        kdf_override,
        KEYSTORE_V1_AAD_PREFIX,
    )
}

fn encrypt_identity_secret_with_aad_prefix(
    password: &str,
    algorithm: IdentityAlgorithm,
    secret: &[u8],
    public_key: &[u8],
    kdf_override: Option<KeystoreV1KdfParams>,
    aad_prefix: &[u8],
) -> Result<KeystoreV1, KeystoreError> {
    let mut rng = OsRng;
    let kdf = if let Some(k) = kdf_override {
        k
    } else {
        let mut salt = vec![0u8; 16];
        rng.fill_bytes(&mut salt);
        KeystoreV1KdfParams {
            salt,
            m_cost_kib: 64 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    };

    let mut master = derive_master_key(password.as_bytes(), &kdf)?;
    let mut identity_key = derive_aead_key(&master, b"identity");
    master.zeroize();
    let aead = ChaCha20Poly1305::new(Key::from_slice(&identity_key));
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut sk_plain = secret.to_vec();
    let ct = aead
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sk_plain,
                aad: &aad_for_algorithm(aad_prefix, algorithm),
            },
        )
        .map_err(|_| KeystoreError::Invalid("encrypt identity failed"))?;
    sk_plain.zeroize();
    identity_key.zeroize();

    Ok(KeystoreV1 {
        format: "keystore_v1".to_string(),
        kdf,
        identity_algorithm: if algorithm == IdentityAlgorithm::Secp256k1 {
            None
        } else {
            Some(algorithm.wire_id().to_string())
        },
        identity_public_key: public_key.to_vec(),
        identity_nonce: nonce.to_vec(),
        identity_ciphertext: ct,
    })
}

/// Parse a 32-byte secp256k1 secret as 64 hex digits (legacy import path).
pub fn parse_secret_key_hex(secret_hex: &str) -> Result<[u8; 32], KeystoreError> {
    parse_secret_bytes_for_algorithm(IdentityAlgorithm::Secp256k1, secret_hex)?
        .try_into()
        .map_err(|_| KeystoreError::Invalid("secret key must be 32 bytes"))
}

/// Parse secret key hex for the given identity algorithm.
pub fn parse_secret_bytes_for_algorithm(
    algorithm: IdentityAlgorithm,
    secret_hex: &str,
) -> Result<Vec<u8>, KeystoreError> {
    let s = secret_hex.trim();
    if s.len() > MAX_SECRET_IMPORT_HEX_CHARS {
        return Err(KeystoreError::Invalid("secret key hex too long"));
    }
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeystoreError::Invalid("invalid secret key hex"));
    }
    if s.len() % 2 != 0 {
        return Err(KeystoreError::Invalid(
            "secret key hex must have even length",
        ));
    }
    let bytes = hex::decode(s).map_err(|_| KeystoreError::Invalid("invalid secret key hex"))?;
    match algorithm {
        IdentityAlgorithm::Secp256k1 | IdentityAlgorithm::Ed25519 => {
            if bytes.len() != 32 {
                return Err(KeystoreError::Invalid(
                    "secret key must be 32 bytes (64 hex chars)",
                ));
            }
        }
        IdentityAlgorithm::EcdsaP256 => {
            if bytes.len() < 32 || bytes.len() > 66 {
                return Err(KeystoreError::Invalid(
                    "ecdsa-p256 secret hex length out of range",
                ));
            }
            p256::ecdsa::SigningKey::from_slice(&bytes)
                .map_err(|_| KeystoreError::Invalid("invalid ecdsa-p256 secret"))?;
        }
    }
    Ok(bytes)
}

/// Create encrypted keystore with the given algorithm (default shipping: secp256k1).
pub fn create_keystore_v1_with_algorithm(
    password: &str,
    algorithm: IdentityAlgorithm,
    kdf_override: Option<KeystoreV1KdfParams>,
) -> Result<(KeystoreV1, DecryptedIdentity), KeystoreError> {
    let secret = identity::generate_secret(algorithm).map_err(|e| KeystoreError::InvalidMsg(e))?;
    create_keystore_v1_from_secret_with_algorithm(password, algorithm, &secret, kdf_override)
}

/// Build an encrypted keystore from an existing secret (import path).
pub fn create_keystore_v1_from_secret_with_algorithm(
    password: &str,
    algorithm: IdentityAlgorithm,
    secret: &[u8],
    kdf_override: Option<KeystoreV1KdfParams>,
) -> Result<(KeystoreV1, DecryptedIdentity), KeystoreError> {
    let id = decrypted_from_secret(algorithm, secret)?;
    let keystore =
        encrypt_identity_secret(password, algorithm, secret, &id.public_key, kdf_override)?;
    Ok((keystore, id))
}

/// Build an encrypted keystore from an existing 32-byte secp256k1 secret (legacy import).
pub fn create_keystore_v1_from_secret(
    password: &str,
    secret: &[u8; 32],
    kdf_override: Option<KeystoreV1KdfParams>,
) -> Result<(KeystoreV1, DecryptedIdentity), KeystoreError> {
    create_keystore_v1_from_secret_with_algorithm(
        password,
        IdentityAlgorithm::Secp256k1,
        secret,
        kdf_override,
    )
}

pub fn create_keystore_v1(
    password: &str,
    kdf_override: Option<KeystoreV1KdfParams>,
) -> Result<(KeystoreV1, DecryptedIdentity), KeystoreError> {
    create_keystore_v1_with_algorithm(password, IdentityAlgorithm::Secp256k1, kdf_override)
}

/// Secret key hex for export (secp256k1: 64 hex chars). Other algorithms return raw secret hex.
pub fn secret_key_hex_from_identity(id: &DecryptedIdentity) -> String {
    match &id.material {
        IdentityKeyMaterial::Secp256k1 { secret, .. } => hex::encode(secret.secret_bytes()),
        IdentityKeyMaterial::Ed25519 { signing } => hex::encode(signing.to_bytes()),
        IdentityKeyMaterial::EcdsaP256 { signing } => hex::encode(signing.to_bytes()),
    }
}

pub fn unlock_keystore_v1(
    password: &str,
    keystore: &KeystoreV1,
) -> Result<DecryptedIdentity, KeystoreError> {
    keystore.validate_fields()?;

    let algorithm = keystore_algorithm(keystore)?;
    validate_public_key_for_keystore(algorithm, &keystore.identity_public_key)?;

    let mut master = derive_master_key(password.as_bytes(), &keystore.kdf)?;
    let mut identity_key = derive_aead_key(&master, b"identity");
    master.zeroize();
    let aead = ChaCha20Poly1305::new(Key::from_slice(&identity_key));
    identity_key.zeroize();
    let mut sk_plain = [KEYSTORE_V1_AAD_PREFIX, LEGACY_KEYSTORE_V1_AAD_PREFIX]
        .iter()
        .find_map(|prefix| {
            aead.decrypt(
                Nonce::from_slice(&keystore.identity_nonce),
                Payload {
                    msg: &keystore.identity_ciphertext,
                    aad: &aad_for_algorithm(prefix, algorithm),
                },
            )
            .ok()
        })
        .ok_or(KeystoreError::Decrypt)?;

    let id = decrypted_from_secret(algorithm, &sk_plain)?;
    sk_plain.zeroize();
    if !bytes_equal_ct(id.public_key.as_slice(), keystore.identity_public_key.as_slice()) {
        return Err(KeystoreError::Invalid("identity public key mismatch"));
    }

    // Extra guard for legacy files written before multi-algo (33-byte compressed secp256k1).
    if algorithm == IdentityAlgorithm::Secp256k1 && is_legacy_secp256k1_keystore(keystore) {
        if keystore.identity_public_key.len() != 33 {
            return Err(KeystoreError::Invalid("bad identity public key length"));
        }
    }

    Ok(id)
}

impl KeystoreV1 {
    /// Structural bounds checked before Argon2 / AEAD (import, load, unlock).
    pub fn validate_fields(&self) -> Result<(), KeystoreError> {
        if self.format != "keystore_v1" {
            return Err(KeystoreError::Invalid("unknown format"));
        }
        validate_kdf_params(&self.kdf)?;
        if self.identity_nonce.len() != 12 {
            return Err(KeystoreError::Invalid("bad nonce length"));
        }
        if self.identity_ciphertext.is_empty()
            || self.identity_ciphertext.len() > MAX_IDENTITY_CIPHERTEXT_LEN
        {
            return Err(KeystoreError::Invalid("identity ciphertext length out of range"));
        }
        if self.identity_public_key.is_empty()
            || self.identity_public_key.len() > MAX_IDENTITY_PUBLIC_KEY_LEN
        {
            return Err(KeystoreError::Invalid("identity public key length out of range"));
        }
        let _ = keystore_algorithm(self)?;
        Ok(())
    }

    pub fn to_json_string(&self) -> Result<String, KeystoreError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_json_str(s: &str) -> Result<Self, KeystoreError> {
        if s.len() > MAX_KEYSTORE_JSON_BYTES {
            return Err(KeystoreError::Invalid("keystore JSON exceeds size limit"));
        }
        let ks: KeystoreV1 = serde_json::from_str(s)?;
        ks.validate_fields()?;
        Ok(ks)
    }

    pub fn identity_algorithm_resolved(&self) -> Result<IdentityAlgorithm, KeystoreError> {
        keystore_algorithm(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock_roundtrip() {
        let (ks, id) = create_keystore_v1("pass123", None).unwrap();
        assert!(ks.identity_algorithm.is_none());
        let id2 = unlock_keystore_v1("pass123", &ks).unwrap();
        assert_eq!(id.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn legacy_json_without_algorithm_field_unlocks() {
        let (ks, id) = create_keystore_v1("pass123", None).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&ks.to_json_string().unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("identity_algorithm");
        let legacy: KeystoreV1 = serde_json::from_value(v).unwrap();
        let id2 = unlock_keystore_v1("pass123", &legacy).unwrap();
        assert_eq!(id.public_key_hex(), id2.public_key_hex());
    }

    #[test]
    fn pre_rename_aad_keystores_still_unlock() {
        for algorithm in [IdentityAlgorithm::Secp256k1, IdentityAlgorithm::Ed25519] {
            let secret = identity::generate_secret(algorithm).unwrap();
            let id = decrypted_from_secret(algorithm, &secret).unwrap();
            let legacy = encrypt_identity_secret_with_aad_prefix(
                "pw",
                algorithm,
                &secret,
                &id.public_key,
                None,
                LEGACY_KEYSTORE_V1_AAD_PREFIX,
            )
            .unwrap();
            let unlocked = unlock_keystore_v1("pw", &legacy).unwrap();
            assert_eq!(unlocked.public_key_hex(), id.public_key_hex());
            assert!(matches!(
                unlock_keystore_v1("wrong", &legacy),
                Err(KeystoreError::Decrypt)
            ));
        }
    }

    #[test]
    fn import_secret_matches_create() {
        let (ks1, id1) = create_keystore_v1("pw", None).unwrap();
        let sk = id1.secp256k1_secret().secret_bytes();
        let (ks2, id2) = create_keystore_v1_from_secret("pw2", &sk, None).unwrap();
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_ne!(ks1.identity_ciphertext, ks2.identity_ciphertext);
        let id3 = unlock_keystore_v1("pw2", &ks2).unwrap();
        assert_eq!(id1.public_key_hex(), id3.public_key_hex());
    }

    #[test]
    fn ed25519_roundtrip() {
        let (ks, id) =
            create_keystore_v1_with_algorithm("pw", IdentityAlgorithm::Ed25519, None).unwrap();
        assert_eq!(ks.identity_algorithm.as_deref(), Some("ed25519"));
        let id2 = unlock_keystore_v1("pw", &ks).unwrap();
        assert_eq!(id.algorithm(), IdentityAlgorithm::Ed25519);
        assert_eq!(id.public_key_hex(), id2.public_key_hex());
        assert!(id.identity_wire().starts_with("ed25519:"));
    }

    #[test]
    fn parse_secret_key_hex_rejects_bad_length() {
        assert!(parse_secret_key_hex("ab").is_err());
    }

    #[test]
    fn parse_secret_hex_rejects_oversized_input() {
        let huge = "ab".repeat(MAX_SECRET_IMPORT_HEX_CHARS);
        assert!(matches!(
            parse_secret_key_hex(&huge),
            Err(KeystoreError::Invalid("secret key hex too long"))
        ));
    }

    #[test]
    fn from_json_str_rejects_truncated_json() {
        let (ks, _) = create_keystore_v1("pw", None).unwrap();
        let mut json = ks.to_json_string().unwrap();
        json.truncate(json.len() / 2);
        assert!(KeystoreV1::from_json_str(&json).is_err());
    }

    #[test]
    fn from_json_str_rejects_oversized_blob() {
        let huge = "x".repeat(MAX_KEYSTORE_JSON_BYTES + 1);
        assert!(matches!(
            KeystoreV1::from_json_str(&huge),
            Err(KeystoreError::Invalid("keystore JSON exceeds size limit"))
        ));
    }

    #[test]
    fn public_key_hex_is_canonical_identity() {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        let pk = id.public_key_hex();
        assert!(crate::public_key_util::same_contact_pk(&pk, &pk));
    }

    #[test]
    fn unlock_rejects_extreme_kdf_before_argon2() {
        let (mut ks, _) = create_keystore_v1("pw", None).unwrap();
        ks.kdf.m_cost_kib = u32::MAX;
        assert!(matches!(
            unlock_keystore_v1("pw", &ks),
            Err(KeystoreError::Invalid("kdf m_cost out of range"))
        ));
    }

    #[test]
    fn unlock_rejects_oversized_identity_ciphertext() {
        let (mut ks, _) = create_keystore_v1("pw", None).unwrap();
        ks.identity_ciphertext = vec![0u8; MAX_IDENTITY_CIPHERTEXT_LEN + 1];
        assert!(matches!(
            unlock_keystore_v1("pw", &ks),
            Err(KeystoreError::Invalid("identity ciphertext length out of range"))
        ));
    }

    #[test]
    fn unlock_rejects_invalid_stored_public_key() {
        let (mut ks, _) = create_keystore_v1("pw", None).unwrap();
        ks.identity_public_key = vec![0x04; 20];
        assert!(matches!(
            unlock_keystore_v1("pw", &ks),
            Err(KeystoreError::InvalidMsg(_))
        ));
    }

    #[test]
    fn from_json_str_rejects_oversized_kdf_salt_before_kdf() {
        let (mut ks, _) = create_keystore_v1("pw", None).unwrap();
        ks.kdf.salt = vec![0u8; MAX_KDF_SALT_LEN + 1];
        let json = serde_json::to_string(&ks).unwrap();
        assert!(matches!(
            KeystoreV1::from_json_str(&json),
            Err(KeystoreError::Invalid("salt length out of range"))
        ));
    }

    #[test]
    fn validate_fields_rejects_bad_format() {
        let (mut ks, _) = create_keystore_v1("pw", None).unwrap();
        ks.format = "keystore_v99".to_string();
        assert!(matches!(
            ks.validate_fields(),
            Err(KeystoreError::Invalid("unknown format"))
        ));
    }
}
