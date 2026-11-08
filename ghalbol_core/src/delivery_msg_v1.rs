//! Signed delivery envelope + identity-sealed inner text.

use serde_json::{Value, json};

use crate::delivery_auth::{sign_delivery_challenge, verify_delivery_signature};
use crate::identity::Identity;
use crate::keystore_v1::DecryptedIdentity;
use crate::offline_seal_v1::{open_sealed_for_identity, seal_to_identity_public};
use crate::public_key_util::normalize_contact_identity_wire;

pub const DELIVERY_MSG_SHARE: &str = "ghalbol_delivery_msg_v1";
pub const DELIVERY_MSG_FORMAT_VERSION: u64 = 1;

/// Sealed mailbox blob after hex decode (voice/attachment inner caps apply).
const MAX_DELIVERY_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DELIVERY_SIGNATURE_BYTES: usize = 256;
/// Match `ghalbol_delivery::envelope::MAX_MESSAGE_ID_BYTES`.
const MAX_DELIVERY_MESSAGE_ID_BYTES: usize = 128;

fn validate_delivery_message_id(message_id: &str) -> Result<(), String> {
    let t = message_id.trim();
    if t.is_empty() || t.len() > MAX_DELIVERY_MESSAGE_ID_BYTES || t.chars().any(|c| c.is_control()) {
        return Err("message_id invalid".into());
    }
    Ok(())
}

pub fn envelope_sign_bytes(
    message_id: &str,
    sender_wire: &str,
    recipient_wire: &str,
    created_at_ms: i64,
    ciphertext_hex: &str,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "ciphertext_hex": ciphertext_hex,
        "created_at_ms": created_at_ms,
        "message_id": message_id,
        "recipient_wire": recipient_wire.trim().to_ascii_lowercase(),
        "sender_wire": sender_wire.trim().to_ascii_lowercase(),
    });
    serde_json::to_vec(&body).map_err(|e| format!("envelope sign json: {e}"))
}

pub fn build_text_envelope(
    ident: &DecryptedIdentity,
    message_id: &str,
    recipient_wire: &str,
    text: &str,
    created_at_ms: i64,
) -> Result<Value, String> {
    validate_delivery_message_id(message_id)?;
    let sender_wire = ident.identity_wire();
    let recipient_norm = normalize_contact_identity_wire(recipient_wire)?;
    let recipient_id = Identity::parse(&recipient_norm)?;
    let inner = json!({ "text": text }).to_string();
    let sealed = seal_to_identity_public(
        recipient_id.algorithm,
        &recipient_id.public_key,
        inner.as_bytes(),
    )?;
    let ciphertext_hex = hex::encode(&sealed);
    let sign_bytes = envelope_sign_bytes(
        message_id,
        &sender_wire,
        &recipient_norm,
        created_at_ms,
        &ciphertext_hex,
    )?;
    let signature = sign_delivery_challenge(ident, &sign_bytes)?;
    Ok(json!({
        "ghalbol.share": DELIVERY_MSG_SHARE,
        "format_version": DELIVERY_MSG_FORMAT_VERSION,
        "message_id": message_id,
        "sender_wire": sender_wire,
        "recipient_wire": recipient_norm,
        "created_at_ms": created_at_ms,
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": hex::encode(signature),
    }))
}

pub fn build_voice_envelope(
    ident: &DecryptedIdentity,
    message_id: &str,
    recipient_wire: &str,
    duration_ms: u32,
    opus_blob: &[u8],
    created_at_ms: i64,
) -> Result<Value, String> {
    validate_delivery_message_id(message_id)?;
    let sender_wire = ident.identity_wire();
    let recipient_norm = normalize_contact_identity_wire(recipient_wire)?;
    let recipient_id = Identity::parse(&recipient_norm)?;
    let inner = crate::voice_msg_v1::build_voice_inner(duration_ms, opus_blob)?;
    let inner_bytes = inner.to_json_bytes()?;
    let sealed = seal_to_identity_public(
        recipient_id.algorithm,
        &recipient_id.public_key,
        &inner_bytes,
    )?;
    let ciphertext_hex = hex::encode(&sealed);
    let sign_bytes = envelope_sign_bytes(
        message_id,
        &sender_wire,
        &recipient_norm,
        created_at_ms,
        &ciphertext_hex,
    )?;
    let signature = sign_delivery_challenge(ident, &sign_bytes)?;
    Ok(json!({
        "ghalbol.share": DELIVERY_MSG_SHARE,
        "format_version": DELIVERY_MSG_FORMAT_VERSION,
        "message_id": message_id,
        "sender_wire": sender_wire,
        "recipient_wire": recipient_norm,
        "created_at_ms": created_at_ms,
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": hex::encode(signature),
    }))
}

pub fn build_attachment_envelope(
    ident: &DecryptedIdentity,
    message_id: &str,
    recipient_wire: &str,
    inner: &crate::attach_v1::AttachmentInner,
    created_at_ms: i64,
) -> Result<Value, String> {
    validate_delivery_message_id(message_id)?;
    let sender_wire = ident.identity_wire();
    let recipient_norm = normalize_contact_identity_wire(recipient_wire)?;
    let recipient_id = Identity::parse(&recipient_norm)?;
    let inner_bytes = inner.to_json_bytes()?;
    let sealed = seal_to_identity_public(
        recipient_id.algorithm,
        &recipient_id.public_key,
        &inner_bytes,
    )?;
    let ciphertext_hex = hex::encode(&sealed);
    let sign_bytes = envelope_sign_bytes(
        message_id,
        &sender_wire,
        &recipient_norm,
        created_at_ms,
        &ciphertext_hex,
    )?;
    let signature = sign_delivery_challenge(ident, &sign_bytes)?;
    Ok(json!({
        "ghalbol.share": DELIVERY_MSG_SHARE,
        "format_version": DELIVERY_MSG_FORMAT_VERSION,
        "message_id": message_id,
        "sender_wire": sender_wire,
        "recipient_wire": recipient_norm,
        "created_at_ms": created_at_ms,
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": hex::encode(signature),
    }))
}

/// Control upload: availability status (no chat bubble; short TTL on the mailbox).
pub fn build_availability_envelope(
    ident: &DecryptedIdentity,
    message_id: &str,
    recipient_wire: &str,
    status: &str,
    updated_at_ms: i64,
    created_at_ms: i64,
) -> Result<Value, String> {
    validate_delivery_message_id(message_id)?;
    let sender_wire = ident.identity_wire();
    let recipient_norm = normalize_contact_identity_wire(recipient_wire)?;
    let recipient_id = Identity::parse(&recipient_norm)?;
    let inner = json!({
        "kind": "availability_status",
        "status": status,
        "updated_at_ms": updated_at_ms,
    })
    .to_string();
    let sealed = seal_to_identity_public(
        recipient_id.algorithm,
        &recipient_id.public_key,
        inner.as_bytes(),
    )?;
    let ciphertext_hex = hex::encode(&sealed);
    let sign_bytes = envelope_sign_bytes(
        message_id,
        &sender_wire,
        &recipient_norm,
        created_at_ms,
        &ciphertext_hex,
    )?;
    let signature = sign_delivery_challenge(ident, &sign_bytes)?;
    Ok(json!({
        "ghalbol.share": DELIVERY_MSG_SHARE,
        "format_version": DELIVERY_MSG_FORMAT_VERSION,
        "message_id": message_id,
        "sender_wire": sender_wire,
        "recipient_wire": recipient_norm,
        "created_at_ms": created_at_ms,
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": hex::encode(signature),
    }))
}

pub fn open_text_from_envelope(
    ident: &DecryptedIdentity,
    envelope: &Value,
) -> Result<(String, String, String), String> {
    verify_delivery_envelope(envelope)?;
    let sender_wire = envelope
        .get("sender_wire")
        .and_then(|v| v.as_str())
        .ok_or("missing sender_wire")?
        .to_string();
    let message_id = envelope
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or("missing message_id")?
        .to_string();
    let ciphertext_hex = envelope
        .get("ciphertext_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing ciphertext_hex")?;
    let sealed = decode_delivery_ciphertext_hex(ciphertext_hex)?;
    let plain = open_sealed_for_identity(ident, &sealed)?;
    let inner: Value = serde_json::from_slice(&plain).map_err(|e| format!("inner json: {e}"))?;
    let text = inner
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or("inner text missing")?
        .to_string();
    Ok((message_id, sender_wire, text))
}

pub fn open_voice_from_envelope(
    ident: &DecryptedIdentity,
    envelope: &Value,
) -> Result<(String, String, u32, Vec<u8>), String> {
    let (message_id, sender_wire, plain) = open_plain_from_envelope(ident, envelope)?;
    let inner = crate::voice_msg_v1::VoiceInner::from_json_bytes(&plain)?;
    Ok((
        message_id,
        sender_wire,
        inner.duration_ms,
        inner.opus_bytes()?,
    ))
}

#[derive(Debug)]
pub enum DeliveryOpenedMessage {
    Text {
        message_id: String,
        sender_wire: String,
        text: String,
    },
    Voice {
        message_id: String,
        sender_wire: String,
        duration_ms: u32,
        opus_blob: Vec<u8>,
    },
    /// Full E2E mailbox attachment (file bytes in sealed inner).
    Attachment {
        message_id: String,
        sender_wire: String,
        inner: crate::attach_v1::AttachmentInner,
    },
    /// Control: peer availability text — not a chat bubble.
    AvailabilityStatus {
        message_id: String,
        sender_wire: String,
        status: String,
        updated_at_ms: i64,
    },
}

pub fn open_message_from_envelope(
    ident: &DecryptedIdentity,
    envelope: &Value,
) -> Result<DeliveryOpenedMessage, String> {
    let (message_id, sender_wire, plain) = open_plain_from_envelope(ident, envelope)?;
    let inner: Value = serde_json::from_slice(&plain).map_err(|e| format!("inner json: {e}"))?;
    if inner.get("voice_msg_version").is_some() || inner.get("audio_b64").is_some() {
        let voice = crate::voice_msg_v1::VoiceInner::from_json_bytes(&plain)?;
        return Ok(DeliveryOpenedMessage::Voice {
            message_id,
            sender_wire,
            duration_ms: voice.duration_ms,
            opus_blob: voice.opus_bytes()?,
        });
    }
    if crate::attach_v1::AttachmentInner::is_mailbox_payload(&inner)
        || (inner.get("attachment_version").is_some() && inner.get("file_b64").is_some())
    {
        let attach = crate::attach_v1::AttachmentInner::from_json_bytes(&plain)?;
        return Ok(DeliveryOpenedMessage::Attachment {
            message_id,
            sender_wire,
            inner: attach,
        });
    }
    let kind = inner
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if kind == "availability_status"
        || (inner.get("status").is_some()
            && inner.get("updated_at_ms").is_some()
            && inner.get("text").is_none())
    {
        let status = inner
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let updated_at_ms = inner
            .get("updated_at_ms")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        return Ok(DeliveryOpenedMessage::AvailabilityStatus {
            message_id,
            sender_wire,
            status,
            updated_at_ms,
        });
    }
    let text = inner
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or("inner text missing")?
        .to_string();
    Ok(DeliveryOpenedMessage::Text {
        message_id,
        sender_wire,
        text,
    })
}

fn open_plain_from_envelope(
    ident: &DecryptedIdentity,
    envelope: &Value,
) -> Result<(String, String, Vec<u8>), String> {
    verify_delivery_envelope(envelope)?;
    let sender_wire = envelope
        .get("sender_wire")
        .and_then(|v| v.as_str())
        .ok_or("missing sender_wire")?
        .to_string();
    let message_id = envelope
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or("missing message_id")?
        .to_string();
    let ciphertext_hex = envelope
        .get("ciphertext_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing ciphertext_hex")?;
    let sealed = decode_delivery_ciphertext_hex(ciphertext_hex)?;
    let plain = open_sealed_for_identity(ident, &sealed)?;
    Ok((message_id, sender_wire, plain))
}

pub fn verify_delivery_envelope(envelope: &Value) -> Result<(), String> {
    let share = envelope
        .get("ghalbol.share")
        .and_then(|v| v.as_str())
        .ok_or("missing ghalbol.share")?;
    if share.len() > 128 {
        return Err("ghalbol.share too long".into());
    }
    if share != DELIVERY_MSG_SHARE {
        return Err(format!("unknown share: {share}"));
    }
    let format_version = envelope
        .get("format_version")
        .and_then(|v| v.as_u64())
        .ok_or("missing format_version")?;
    if format_version != DELIVERY_MSG_FORMAT_VERSION {
        return Err(format!("unsupported format_version {format_version}"));
    }
    let message_id = envelope
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or("missing message_id")?;
    validate_delivery_message_id(message_id)?;
    let sender_wire = envelope
        .get("sender_wire")
        .and_then(|v| v.as_str())
        .ok_or("missing sender_wire")?;
    let recipient_wire = envelope
        .get("recipient_wire")
        .and_then(|v| v.as_str())
        .ok_or("missing recipient_wire")?;
    let created_at_ms = envelope
        .get("created_at_ms")
        .and_then(|v| v.as_i64())
        .ok_or("missing created_at_ms")?;
    let ciphertext_hex = envelope
        .get("ciphertext_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing ciphertext_hex")?;
    let signature_hex = envelope
        .get("signature_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing signature_hex")?;
    let sig = hex::decode(signature_hex.trim()).map_err(|e| format!("signature hex: {e}"))?;
    if sig.is_empty() || sig.len() > MAX_DELIVERY_SIGNATURE_BYTES {
        return Err("signature length out of range".to_string());
    }
    decode_delivery_ciphertext_hex(ciphertext_hex)?;
    let sign_bytes = envelope_sign_bytes(
        message_id,
        sender_wire,
        recipient_wire,
        created_at_ms,
        ciphertext_hex,
    )?;
    verify_delivery_signature(sender_wire, &sign_bytes, &sig)
}

fn decode_delivery_ciphertext_hex(ciphertext_hex: &str) -> Result<Vec<u8>, String> {
    if ciphertext_hex.trim().is_empty() {
        return Err("empty ciphertext".to_string());
    }
    let sealed = hex::decode(ciphertext_hex.trim()).map_err(|e| format!("ciphertext hex: {e}"))?;
    if sealed.len() > MAX_DELIVERY_CIPHERTEXT_BYTES {
        return Err("ciphertext too large".to_string());
    }
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_secp256k1() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let env = build_text_envelope(&a, "msg-1", &b.identity_wire(), "hello", 1_000).unwrap();
        verify_delivery_envelope(&env).unwrap();
        let (_id, _from, text) = open_text_from_envelope(&b, &env).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn roundtrip_availability_status() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let env = build_availability_envelope(
            &a,
            "avail-1",
            &b.identity_wire(),
            "Busy",
            2_000,
            1_000,
        )
        .unwrap();
        match open_message_from_envelope(&b, &env).unwrap() {
            DeliveryOpenedMessage::AvailabilityStatus {
                status,
                updated_at_ms,
                ..
            } => {
                assert_eq!(status, "Busy");
                assert_eq!(updated_at_ms, 2_000);
            }
            other => panic!("expected AvailabilityStatus, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_ed25519_mailbox_text() {
        let (_ks_a, a) = crate::create_keystore_v1_with_algorithm(
            "pw",
            crate::IdentityAlgorithm::Ed25519,
            None,
        )
        .unwrap();
        let (_ks_b, b) = crate::create_keystore_v1_with_algorithm(
            "pw2",
            crate::IdentityAlgorithm::Ed25519,
            None,
        )
        .unwrap();
        let env = build_text_envelope(&a, "msg-ed", &b.identity_wire(), "ed hello", 1_000).unwrap();
        let (_id, _from, text) = open_text_from_envelope(&b, &env).unwrap();
        assert_eq!(text, "ed hello");
    }

    #[test]
    fn roundtrip_ecdsa_p256_mailbox_text() {
        let (_ks_a, a) = crate::create_keystore_v1_with_algorithm(
            "pw",
            crate::IdentityAlgorithm::EcdsaP256,
            None,
        )
        .unwrap();
        let (_ks_b, b) = crate::create_keystore_v1_with_algorithm(
            "pw2",
            crate::IdentityAlgorithm::EcdsaP256,
            None,
        )
        .unwrap();
        let env =
            build_text_envelope(&a, "msg-p256", &b.identity_wire(), "p256 hello", 1_000).unwrap();
        let (_id, _from, text) = open_text_from_envelope(&b, &env).unwrap();
        assert_eq!(text, "p256 hello");
    }

    #[test]
    fn cross_algo_secp_sender_to_ed_recipient() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1_with_algorithm(
            "pw2",
            crate::IdentityAlgorithm::Ed25519,
            None,
        )
        .unwrap();
        let env = build_text_envelope(&a, "msg-x", &b.identity_wire(), "cross", 1_000).unwrap();
        let (_id, _from, text) = open_text_from_envelope(&b, &env).unwrap();
        assert_eq!(text, "cross");
    }

    #[test]
    fn verify_rejects_wrong_format_version() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let mut env = build_text_envelope(&a, "msg-bad-fv", &b.identity_wire(), "x", 1).unwrap();
        env.as_object_mut()
            .unwrap()
            .insert("format_version".to_string(), json!(99_u64));
        assert!(verify_delivery_envelope(&env).is_err());
    }

    #[test]
    fn verify_rejects_oversized_ciphertext_hex() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let mut env =
            build_text_envelope(&a, "msg-big", &b.identity_wire(), "x", 1).unwrap();
        let huge = hex::encode(vec![0u8; MAX_DELIVERY_CIPHERTEXT_BYTES + 1]);
        env.as_object_mut()
            .unwrap()
            .insert("ciphertext_hex".to_string(), json!(huge));
        assert!(verify_delivery_envelope(&env).is_err());
    }

    #[test]
    fn verify_rejects_empty_ciphertext_and_bad_signature_hex() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let mut env = build_text_envelope(&a, "msg-empty-ct", &b.identity_wire(), "x", 1).unwrap();
        env.as_object_mut()
            .unwrap()
            .insert("ciphertext_hex".to_string(), json!(""));
        assert!(verify_delivery_envelope(&env).is_err());

        let mut env2 =
            build_text_envelope(&a, "msg-bad-sig", &b.identity_wire(), "x", 1).unwrap();
        env2.as_object_mut()
            .unwrap()
            .insert("signature_hex".to_string(), json!("zz"));
        assert!(verify_delivery_envelope(&env2).is_err());
    }

    #[test]
    fn verify_rejects_tampered_message_id_after_sign() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let mut env =
            build_text_envelope(&a, "msg-tamper", &b.identity_wire(), "hi", 1).unwrap();
        env.as_object_mut()
            .unwrap()
            .insert("message_id".to_string(), json!("msg-other"));
        assert!(verify_delivery_envelope(&env).is_err());
    }

    #[test]
    fn build_and_verify_reject_oversized_or_control_message_id() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let huge = "m".repeat(MAX_DELIVERY_MESSAGE_ID_BYTES + 1);
        assert!(build_text_envelope(&a, &huge, &b.identity_wire(), "x", 1).is_err());
        assert!(build_text_envelope(&a, "bad\nid", &b.identity_wire(), "x", 1).is_err());
        let mut env = build_text_envelope(&a, "msg-ok", &b.identity_wire(), "x", 1).unwrap();
        env.as_object_mut()
            .unwrap()
            .insert("message_id".to_string(), json!(huge));
        assert!(verify_delivery_envelope(&env).is_err());
    }

    #[test]
    fn verify_rejects_unknown_ghalbol_share() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let mut env = build_text_envelope(&a, "msg-share", &b.identity_wire(), "x", 1).unwrap();
        env.as_object_mut()
            .unwrap()
            .insert("ghalbol.share".to_string(), json!("legacy_share_v0"));
        assert!(verify_delivery_envelope(&env).is_err());
    }

    /// Soft latency guard — catches accidental regressions on build → verify → open.
    /// Bound is deliberately loose for slow CI hosts.
    #[test]
    fn text_envelope_seal_verify_open_stays_under_soft_latency_budget() {
        let (_ks_a, a) = crate::create_keystore_v1("pw", None).unwrap();
        let (_ks_b, b) = crate::create_keystore_v1("pw2", None).unwrap();
        let start = std::time::Instant::now();
        for i in 0..40 {
            let env = build_text_envelope(
                &a,
                &format!("msg-perf-{i}"),
                &b.identity_wire(),
                "perf",
                1_000 + i,
            )
            .unwrap();
            verify_delivery_envelope(&env).unwrap();
            let (_id, _from, text) = open_text_from_envelope(&b, &env).unwrap();
            assert_eq!(text, "perf");
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(8),
            "40× delivery text build/verify/open took {elapsed:?} (budget 8s)"
        );
    }
}
