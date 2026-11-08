//! Coord bridge client for WAN call byte relay.

use crate::coord::CoordHttpClient;
use crate::p2p::native_log;

#[derive(Clone, Debug)]
pub struct BridgeRequestResult {
    pub bridge_id: String,
    pub token: String,
    pub connect_url: String,
}

/// Match coord `handle_bridge_socket` query limits.
pub(crate) const MAX_BRIDGE_CONNECT_ID_LEN: usize = 64;
pub(crate) const MAX_BRIDGE_CONNECT_TOKEN_LEN: usize = 128;
const MAX_BRIDGE_CONNECT_URL_LEN: usize = 2048;

pub(crate) fn validate_bridge_id(id: &str) -> Result<(), String> {
    let t = id.trim();
    if t.is_empty() || t.len() > MAX_BRIDGE_CONNECT_ID_LEN {
        return Err("bridge_id invalid".into());
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bridge_id invalid".into());
    }
    Ok(())
}

pub(crate) fn validate_bridge_token(token: &str) -> Result<(), String> {
    let t = token.trim();
    if t.is_empty() || t.len() > MAX_BRIDGE_CONNECT_TOKEN_LEN {
        return Err("token invalid".into());
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("token invalid".into());
    }
    Ok(())
}

pub(crate) fn validate_bridge_connect_url(url: &str) -> Result<(), String> {
    let t = url.trim();
    if t.is_empty() || t.len() > MAX_BRIDGE_CONNECT_URL_LEN {
        return Err("connect_url invalid".into());
    }
    if !(t.starts_with("wss://") || t.starts_with("ws://")) {
        return Err("connect_url must be ws(s)".into());
    }
    Ok(())
}

pub fn bridge_request(
    client: &CoordHttpClient,
    ident: &crate::DecryptedIdentity,
    peer_identity_wire: &str,
    call_id: &str,
) -> Result<BridgeRequestResult, String> {
    let caller = crate::identity::normalize_identity_wire(&ident.identity_wire())?;
    let ch_url = format!("{}/v1/bridge/challenge", client.base_url());
    let ch: serde_json::Value = client.post_json(
        &ch_url,
        &serde_json::json!({ "caller_identity_wire": caller }),
    )?;
    let nonce_hex = ch["nonce_hex"].as_str().ok_or("missing nonce_hex")?;
    let nonce = parse_bridge_nonce32(nonce_hex)?;
    let peer = crate::identity::normalize_identity_wire(peer_identity_wire)?;
    if caller.eq_ignore_ascii_case(&peer) {
        return Err("bridge caller and peer must differ".into());
    }
    let call_id = call_id.trim();
    if call_id.is_empty() || call_id.len() > 128 {
        return Err("call_id invalid".into());
    }
    let msg = bridge_request_bytes(&nonce, &caller, &peer, call_id);
    let sig = sign_bridge_request(ident, &msg)?;
    let url = format!("{}/v1/bridge/request", client.base_url());
    let resp: serde_json::Value = client.post_json(
        &url,
        &serde_json::json!({
            "caller_identity_wire": caller,
            // Same normalization as the signed challenge bytes (coord re-normalizes too).
            "peer_identity_wire": peer,
            "call_id": call_id,
            "nonce_hex": nonce_hex,
            "signature_hex": hex::encode(sig),
        }),
    )?;
    native_log::info(
        "bridge",
        format!(
            "bridge request ok bridge_id={}",
            resp["bridge_id"].as_str().unwrap_or("?")
        ),
    );
    let bridge_id = resp["bridge_id"].as_str().ok_or("missing bridge_id")?;
    let token = resp["token"].as_str().ok_or("missing token")?;
    let connect_url = resp["connect_url"].as_str().ok_or("missing connect_url")?;
    validate_bridge_id(bridge_id)?;
    validate_bridge_token(token)?;
    validate_bridge_connect_url(connect_url)?;
    Ok(BridgeRequestResult {
        bridge_id: bridge_id.to_string(),
        token: token.to_string(),
        connect_url: connect_url.to_string(),
    })
}

fn parse_bridge_nonce32(hex_s: &str) -> Result<[u8; 32], String> {
    let t = hex_s.trim();
    if t.len() != 64 {
        return Err("nonce must be 32 bytes hex".into());
    }
    let bytes = hex::decode(t).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "nonce must be 32 bytes hex".to_string())?;
    Ok(arr)
}

fn bridge_request_bytes(nonce: &[u8; 32], caller: &str, peer: &str, call_id: &str) -> Vec<u8> {
    format!(
        "ghalbol:bridge:request:v1\n{}\n{}\n{}\n{}",
        hex::encode(nonce),
        caller.trim().to_ascii_lowercase(),
        peer.trim().to_ascii_lowercase(),
        call_id.trim()
    )
    .into_bytes()
}

#[cfg(test)]
pub(crate) fn bridge_request_bytes_for_test(
    nonce: &[u8; 32],
    caller: &str,
    peer: &str,
    call_id: &str,
) -> Result<Vec<u8>, String> {
    let caller = crate::identity::normalize_identity_wire(caller)?;
    let peer = crate::identity::normalize_identity_wire(peer)?;
    Ok(bridge_request_bytes(&nonce, &caller, &peer, call_id))
}

fn sign_bridge_request(ident: &crate::DecryptedIdentity, msg: &[u8]) -> Result<Vec<u8>, String> {
    use crate::identity::IdentityAlgorithm;
    use sha2::{Digest, Sha256};
    match ident.algorithm() {
        IdentityAlgorithm::Secp256k1 => {
            let hash = Sha256::digest(msg);
            let digest = secp256k1::Message::from_digest(hash.into());
            let sig = secp256k1::Secp256k1::new().sign_ecdsa(digest, ident.secp256k1_secret());
            Ok(sig.serialize_der().to_vec())
        }
        IdentityAlgorithm::Ed25519 | IdentityAlgorithm::EcdsaP256 => ident.sign_message(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use sha2::{Digest, Sha256};

    #[test]
    fn parse_bridge_nonce32_rejects_wrong_length() {
        assert!(parse_bridge_nonce32("ab").is_err());
        assert!(parse_bridge_nonce32(&"a".repeat(128)).is_err());
        assert!(parse_bridge_nonce32(&"g".repeat(64)).is_err());
        let ok = parse_bridge_nonce32(&"ab".repeat(32)).unwrap();
        assert_eq!(ok.len(), 32);
    }

    #[test]
    fn validate_bridge_credentials_match_coord_connect() {
        let id64 = "a".repeat(64);
        assert!(validate_bridge_id(&id64).is_ok());
        assert!(validate_bridge_id(&format!("{id64}x")).is_err());
        assert!(validate_bridge_id("not-hex").is_err());

        let tok64 = "b".repeat(64);
        assert!(validate_bridge_token(&tok64).is_ok());
        assert!(validate_bridge_token(&"c".repeat(128)).is_ok());
        assert!(validate_bridge_token(&"d".repeat(129)).is_err());
        assert!(validate_bridge_token("zz").is_err());

        assert!(validate_bridge_connect_url("wss://coord/v1/bridge/connect").is_ok());
        assert!(validate_bridge_connect_url("ftp://x").is_err());
    }

    #[test]
    fn bridge_request_bytes_match_coord_normalization() {
        let secp = Secp256k1::new();
        let sk = secp256k1::SecretKey::from_byte_array([11u8; 32]).expect("sk");
        let bare = hex::encode(sk.public_key(&secp).serialize());
        let callee_prefixed = format!("secp256k1:{bare}");
        let nonce = [9u8; 32];
        let call_id = "call-x";
        let from_bare =
            bridge_request_bytes_for_test(&nonce, &bare, &callee_prefixed, call_id).unwrap();
        let from_upper = bridge_request_bytes_for_test(
            &nonce,
            &bare.to_uppercase(),
            &callee_prefixed,
            call_id,
        )
        .unwrap();
        assert_eq!(from_bare, from_upper);
        let expected = format!(
            "ghalbol:bridge:request:v1\n{}\n{}\n{}\n{}",
            hex::encode(nonce),
            bare,
            bare,
            call_id
        );
        assert_eq!(from_bare, expected.as_bytes());
        let hash = Sha256::digest(&from_bare);
        let digest = secp256k1::Message::from_digest(hash.into());
        assert!(secp
            .verify_ecdsa(
                digest,
                &secp.sign_ecdsa(digest, &sk),
                &sk.public_key(&secp)
            )
            .is_ok());
    }
}
