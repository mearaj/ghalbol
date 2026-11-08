//! Delivery envelope validation (opaque E2E blob).

use crate::auth::verify_signature;
use crate::error::{DeliveryError, Result};
use crate::identity::normalize_identity_wire;
use serde_json::Value;

pub const DELIVERY_MSG_SHARE: &str = "ghalbol_delivery_msg_v1";
pub const DELIVERY_MSG_FORMAT_VERSION: u64 = 1;
/// Match client sealed-blob cap after hex decode.
const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 256;
pub const MAX_MESSAGE_ID_BYTES: usize = 128;
/// Reject envelopes with client timestamps far outside server wall clock.
const MAX_CREATED_AT_CLOCK_SKEW_MS: i64 = 10 * 60 * 1000;
/// Serialized envelope JSON cap (stored blob size).
pub const MAX_ENVELOPE_JSON_BYTES: usize = 9 * 1024 * 1024;

fn map_wire_id_err(e: DeliveryError) -> DeliveryError {
    match e {
        DeliveryError::BadRequest(msg) => DeliveryError::InvalidEnvelope(msg),
        other => other,
    }
}

fn expect_envelope_str<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str> {
    match value {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(DeliveryError::InvalidEnvelope(format!(
            "invalid {field}"
        ))),
        None => Err(DeliveryError::InvalidEnvelope(format!("missing {field}"))),
    }
}

pub fn parse_wire_message_id(raw: &str) -> Result<String> {
    let message_id = raw.trim();
    if message_id.is_empty()
        || message_id.len() > MAX_MESSAGE_ID_BYTES
        || message_id.chars().any(|c| c.is_control())
    {
        return Err(DeliveryError::BadRequest("invalid message_id".into()));
    }
    Ok(message_id.to_string())
}

pub fn envelope_sign_bytes(
    message_id: &str,
    sender_wire: &str,
    recipient_wire: &str,
    created_at_ms: i64,
    ciphertext_hex: &str,
) -> Vec<u8> {
    let body = serde_json::json!({
        "ciphertext_hex": ciphertext_hex,
        "created_at_ms": created_at_ms,
        "message_id": message_id,
        "recipient_wire": recipient_wire.trim().to_ascii_lowercase(),
        "sender_wire": sender_wire.trim().to_ascii_lowercase(),
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

pub fn validate_envelope(
    envelope: &Value,
    session_sender_wire: &str,
) -> Result<ValidatedEnvelope> {
    if !envelope.is_object() {
        return Err(DeliveryError::InvalidEnvelope(
            "envelope must be a JSON object".into(),
        ));
    }
    let raw_blob = serde_json::to_string(envelope)
        .map_err(|e| DeliveryError::InvalidEnvelope(format!("envelope json: {e}")))?;
    if raw_blob.len() > MAX_ENVELOPE_JSON_BYTES {
        return Err(DeliveryError::InvalidEnvelope("envelope too large".into()));
    }

    let share = envelope
        .get("ghalbol.share")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DeliveryError::InvalidEnvelope("missing ghalbol.share".into()))?;
    if share != DELIVERY_MSG_SHARE {
        return Err(DeliveryError::InvalidEnvelope(format!(
            "unknown ghalbol.share: {share}"
        )));
    }
    let fv = envelope
        .get("format_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DeliveryError::InvalidEnvelope("missing format_version".into()))?;
    if fv != DELIVERY_MSG_FORMAT_VERSION {
        return Err(DeliveryError::InvalidEnvelope(format!(
            "unsupported format_version {fv}"
        )));
    }
    let message_id =
        parse_wire_message_id(expect_envelope_str(envelope.get("message_id"), "message_id")?)
            .map_err(map_wire_id_err)?;
    let sender_wire = expect_envelope_str(envelope.get("sender_wire"), "sender_wire")?;
    let sender_norm = normalize_identity_wire(sender_wire)?;
    let session_norm = normalize_identity_wire(session_sender_wire)?;
    if sender_norm != session_norm {
        return Err(DeliveryError::Forbidden(
            "envelope sender does not match session".into(),
        ));
    }
    let recipient_wire = expect_envelope_str(envelope.get("recipient_wire"), "recipient_wire")?;
    let recipient_norm = normalize_identity_wire(recipient_wire)?;
    let created_at_ms = envelope
        .get("created_at_ms")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| DeliveryError::InvalidEnvelope("missing created_at_ms".into()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if created_at_ms < 0 {
        return Err(DeliveryError::InvalidEnvelope(
            "created_at_ms invalid".into(),
        ));
    }
    if created_at_ms > now.saturating_add(MAX_CREATED_AT_CLOCK_SKEW_MS) {
        return Err(DeliveryError::InvalidEnvelope(
            "created_at_ms too far in future".into(),
        ));
    }
    let ciphertext_hex =
        expect_envelope_str(envelope.get("ciphertext_hex"), "ciphertext_hex")?;
    let ciphertext_hex = ciphertext_hex.trim();
    if ciphertext_hex.is_empty() {
        return Err(DeliveryError::InvalidEnvelope("empty ciphertext".into()));
    }
    if ciphertext_hex.len() % 2 != 0 || !ciphertext_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DeliveryError::InvalidEnvelope(
            "ciphertext hex invalid".into(),
        ));
    }
    if ciphertext_hex.len() / 2 > MAX_CIPHERTEXT_BYTES {
        return Err(DeliveryError::InvalidEnvelope("ciphertext too large".into()));
    }
    let signature_hex = expect_envelope_str(envelope.get("signature_hex"), "signature_hex")?;
    let sig_hex = signature_hex.trim();
    if sig_hex.is_empty()
        || sig_hex.len() > MAX_SIGNATURE_BYTES * 2
        || sig_hex.len() % 2 != 0
        || !sig_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(DeliveryError::InvalidEnvelope(
            "signature length out of range".into(),
        ));
    }
    let sig = hex::decode(sig_hex)
        .map_err(|e| DeliveryError::InvalidEnvelope(format!("signature hex: {e}")))?;
    if sig.len() > MAX_SIGNATURE_BYTES {
        return Err(DeliveryError::InvalidEnvelope(
            "signature length out of range".into(),
        ));
    }
    let sign_bytes = envelope_sign_bytes(
        &message_id,
        &sender_norm,
        &recipient_norm,
        created_at_ms,
        ciphertext_hex,
    );
    verify_signature(&sender_norm, &sign_bytes, &sig)
        .map_err(|e| DeliveryError::InvalidEnvelope(e.to_string()))?;
    let canonical = serde_json::json!({
        "ghalbol.share": DELIVERY_MSG_SHARE,
        "format_version": DELIVERY_MSG_FORMAT_VERSION,
        "message_id": message_id,
        "sender_wire": sender_norm,
        "recipient_wire": recipient_norm,
        "created_at_ms": created_at_ms,
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": sig_hex,
    });
    let envelope_blob = serde_json::to_string(&canonical).map_err(|e| {
        DeliveryError::InvalidEnvelope(format!("envelope json: {e}"))
    })?;
    if envelope_blob.len() > MAX_ENVELOPE_JSON_BYTES {
        return Err(DeliveryError::InvalidEnvelope("envelope too large".into()));
    }
    let size_bytes = envelope_blob.len() as i64;
    Ok(ValidatedEnvelope {
        message_id,
        sender_wire: sender_norm,
        recipient_wire: recipient_norm,
        envelope_blob,
        size_bytes,
    })
}

#[derive(Clone, Debug)]
pub struct ValidatedEnvelope {
    pub message_id: String,
    pub sender_wire: String,
    pub recipient_wire: String,
    pub envelope_blob: String,
    pub size_bytes: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::Digest;

    fn test_wire(seed: u8) -> String {
        let sk = secp256k1::SecretKey::from_byte_array([seed; 32]).expect("key");
        let secp = secp256k1::Secp256k1::new();
        hex::encode(sk.public_key(&secp).serialize())
    }

    fn signed_envelope(sender_seed: u8, recipient_seed: u8, message_id: &str, ct: &str) -> Value {
        let sender = test_wire(sender_seed);
        let recipient = test_wire(recipient_seed);
        let created_at_ms = 1i64;
        let ciphertext_hex = hex::encode(ct.as_bytes());
        let sign_bytes =
            envelope_sign_bytes(message_id, &sender, &recipient, created_at_ms, &ciphertext_hex);
        let sk = secp256k1::SecretKey::from_byte_array([sender_seed; 32]).expect("key");
        let secp = secp256k1::Secp256k1::new();
        let digest = secp256k1::Message::from_digest(sha2::Sha256::digest(&sign_bytes).into());
        let sig = secp.sign_ecdsa(digest, &sk);
        json!({
            "ghalbol.share": DELIVERY_MSG_SHARE,
            "format_version": DELIVERY_MSG_FORMAT_VERSION,
            "message_id": message_id,
            "sender_wire": sender,
            "recipient_wire": recipient,
            "created_at_ms": created_at_ms,
            "ciphertext_hex": ciphertext_hex,
            "signature_hex": hex::encode(sig.serialize_der()),
        })
    }

    #[test]
    fn rejects_oversized_ciphertext_hex_before_verify() {
        let sender = test_wire(7);
        let recipient = test_wire(8);
        let huge = "ab".repeat(MAX_CIPHERTEXT_BYTES + 1);
        let env = json!({
            "ghalbol.share": DELIVERY_MSG_SHARE,
            "format_version": DELIVERY_MSG_FORMAT_VERSION,
            "message_id": "m1",
            "sender_wire": sender,
            "recipient_wire": recipient,
            "created_at_ms": 1,
            "ciphertext_hex": huge,
            "signature_hex": "00",
        });
        let err = validate_envelope(&env, &sender).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn validate_accepts_well_signed_envelope() {
        let sender = test_wire(11);
        let env = signed_envelope(11, 12, "mid-ok", "cipher");
        let validated = validate_envelope(&env, &sender).unwrap();
        assert_eq!(validated.message_id, "mid-ok");
        assert!(validated.size_bytes > 0);
    }

    #[test]
    fn rejects_malformed_and_adversarial_fields() {
        let sender = test_wire(20);
        let recipient = test_wire(21);
        let base = signed_envelope(20, 21, "mid", "ct");

        let mut bad_hex = base.clone();
        bad_hex["ciphertext_hex"] = json!("not-hex!!");
        assert!(validate_envelope(&bad_hex, &sender).is_err());

        let mut ctrl_id = base.clone();
        ctrl_id["message_id"] = json!("bad\u{0001}id");
        assert!(validate_envelope(&ctrl_id, &sender).is_err());

        let mut long_id = base.clone();
        long_id["message_id"] = json!("x".repeat(MAX_MESSAGE_ID_BYTES + 1));
        assert!(validate_envelope(&long_id, &sender).is_err());

        let mut wrong_share = base.clone();
        wrong_share["ghalbol.share"] = json!("wrong_share");
        assert!(validate_envelope(&wrong_share, &sender).is_err());

        let wrong_session = base.clone();
        assert!(validate_envelope(&wrong_session, &recipient).is_err());

        let mut tampered = base;
        tampered["message_id"] = json!("other-id");
        assert!(validate_envelope(&tampered, &sender).is_err());
    }

    #[test]
    fn rejects_oversized_signature_hex_without_crypto() {
        let sender = test_wire(22);
        let mut env = signed_envelope(22, 23, "mid", "ct");
        env["signature_hex"] = json!("ab".repeat(MAX_SIGNATURE_BYTES + 4));
        let err = validate_envelope(&env, &sender).unwrap_err();
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn rejects_created_at_ms_too_far_in_future() {
        let sender = test_wire(30);
        let mut env = signed_envelope(30, 31, "mid", "ct");
        env["created_at_ms"] = json!(9_999_999_999_999_999i64);
        let err = validate_envelope(&env, &sender).unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn parse_wire_message_id_rejects_control_and_length() {
        assert!(parse_wire_message_id("ok-id").is_ok());
        assert!(parse_wire_message_id(&"x".repeat(MAX_MESSAGE_ID_BYTES + 1)).is_err());
        assert!(parse_wire_message_id("bad\u{0001}").is_err());
    }

    #[test]
    fn rejects_non_object_and_nested_scalar_fields() {
        let sender = test_wire(40);
        assert!(validate_envelope(&json!([]), &sender).is_err());
        assert!(validate_envelope(&json!(null), &sender).is_err());
        assert!(validate_envelope(&json!("string"), &sender).is_err());

        let mut nested_id = signed_envelope(40, 41, "mid", "ct");
        nested_id["message_id"] = json!({ "inner": "not-a-wire-id" });
        let err = validate_envelope(&nested_id, &sender).unwrap_err();
        assert!(err.to_string().contains("message_id"));

        let mut nested_recipient = signed_envelope(40, 41, "mid", "ct");
        nested_recipient["recipient_wire"] = json!([test_wire(41)]);
        assert!(validate_envelope(&nested_recipient, &sender).is_err());
    }

    #[test]
    fn rejects_oversized_envelope_json_before_crypto() {
        let sender = test_wire(41);
        let mut env = signed_envelope(41, 42, "mid", "ct");
        let pad = "x".repeat(MAX_ENVELOPE_JSON_BYTES);
        env["padding"] = json!(pad);
        let err = validate_envelope(&env, &sender).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn strips_unsigned_fields_from_stored_envelope_blob() {
        let sender = test_wire(50);
        let mut env = signed_envelope(50, 51, "mid-strip", "ct");
        env["unsigned_extra"] = json!("must not persist");
        let validated = validate_envelope(&env, &sender).unwrap();
        assert!(!validated.envelope_blob.contains("unsigned_extra"));
        let parsed: Value = serde_json::from_str(&validated.envelope_blob).unwrap();
        assert!(parsed.get("unsigned_extra").is_none());
        assert_eq!(parsed["message_id"], "mid-strip");
    }

    #[test]
    fn corrupt_envelope_fails_even_when_upload_op_sig_would_verify() {
        use crate::auth::{upload_challenge_bytes, verify_signature};

        let sender_seed = 44u8;
        let sender = test_wire(sender_seed);
        let recipient = test_wire(45);
        let message_id = "combo-mid";
        let mut env = signed_envelope(sender_seed, 45, message_id, "ct");
        env["signature_hex"] = json!("00");

        assert!(validate_envelope(&env, &sender).is_err());

        let op_nonce = [9u8; 32];
        let upload_msg = upload_challenge_bytes(&op_nonce, message_id, &recipient);
        let sign_bytes = envelope_sign_bytes(
            message_id,
            &sender,
            &recipient,
            env["created_at_ms"].as_i64().unwrap(),
            env["ciphertext_hex"].as_str().unwrap(),
        );
        assert_ne!(upload_msg, sign_bytes);

        let sk = secp256k1::SecretKey::from_byte_array([sender_seed; 32]).expect("key");
        let secp = secp256k1::Secp256k1::new();
        let digest =
            secp256k1::Message::from_digest(sha2::Sha256::digest(&upload_msg).into());
        let upload_sig = secp.sign_ecdsa(digest, &sk).serialize_der();

        verify_signature(&sender, &upload_msg, &upload_sig).unwrap();
        assert!(validate_envelope(&env, &sender).is_err());
    }
}
