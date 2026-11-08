//! Text, voice, and attachment send / fetch paths.

use std::time::Duration;

use crate::connect::new_msg_id_for_ffi;
use crate::contacts_v1::is_valid_public_key_hex;
use crate::dm_event_handler::active_app_namespace;
use crate::p2p::{OutboundCmd, native_log};
use crate::session_runtime::unlocked_identity_clone;
use serde_json::Value;

use super::helpers::{json_err, json_ok, now_ms};
use super::lifecycle::p2p_mx;

fn existing_outbound_created_at_ms(recipient: &str, message_id: &str) -> Option<i64> {
    if let Some(ns) = active_app_namespace() {
        if let Ok(rows) =
            crate::dm_transcript_store::load_merged(&ns, &[recipient.to_string()], None)
        {
            for row in rows {
                if row.outgoing && row.message_id.as_deref() == Some(message_id) {
                    return row.created_at_ms;
                }
            }
        }
    }
    None
}

fn append_outbound_voice_transcript(
    recipient: &str,
    message_id: &str,
    duration_ms: u32,
    opus_blob: &[u8],
) -> Option<String> {
    let Some(ns) = active_app_namespace() else {
        return None;
    };
    let conv_key = recipient.trim().to_string();
    if !is_valid_public_key_hex(&conv_key) {
        return None;
    }
    let created_at_ms =
        existing_outbound_created_at_ms(&conv_key, message_id).unwrap_or_else(now_ms);
    let preview = crate::voice_msg_v1::voice_preview(duration_ms);
    let audio_path = match crate::voice_msg_v1::write_voice_audio_file(&ns, message_id, opus_blob) {
        Ok(p) => Some(p),
        Err(e) => {
            native_log::warn(
                "outbound",
                format!("voice audio persist failed msg_id={message_id}: {e}"),
            );
            None
        }
    };
    let line = crate::dm_transcript_store::StoredChatLine {
        local_id: message_id.to_string(),
        text: preview.clone(),
        outgoing: true,
        from: None,
        message_id: Some(message_id.to_string()),
        delivery: "pending".to_string(),
        created_at_ms: Some(created_at_ms),
        received_at_ms: None,
        read_ack_sent: false,
        msg_kind: "voice".to_string(),
        duration_ms: Some(duration_ms),
        audio_path: audio_path.clone(),
        file_name: None,
        mime_type: Some("audio/opus".to_string()),
        size_bytes: Some(opus_blob.len() as u64),
        local_path: audio_path.clone(),
    };
    let _ = crate::dm_transcript_store::append_if_new(&ns, &conv_key, line);
    let _ = crate::contacts_v1::record_thread_message_preview(
        &ns,
        &conv_key,
        &preview,
        false,
        Some(now_ms()),
    );
    audio_path
}

fn append_outbound_attachment_transcript(
    recipient: &str,
    message_id: &str,
    file_name: &str,
    mime_type: &str,
    size_bytes: u64,
    local_path: &str,
    preview: &str,
) {
    let Some(ns) = active_app_namespace() else {
        return;
    };
    let conv_key = recipient.trim().to_string();
    if !is_valid_public_key_hex(&conv_key) {
        return;
    }
    let created_at_ms =
        existing_outbound_created_at_ms(&conv_key, message_id).unwrap_or_else(now_ms);
    let line = crate::dm_transcript_store::StoredChatLine {
        local_id: message_id.to_string(),
        text: preview.to_string(),
        outgoing: true,
        from: None,
        message_id: Some(message_id.to_string()),
        delivery: "pending".to_string(),
        created_at_ms: Some(created_at_ms),
        received_at_ms: None,
        read_ack_sent: false,
        msg_kind: "attachment_offer".to_string(),
        duration_ms: None,
        audio_path: None,
        file_name: Some(file_name.to_string()),
        mime_type: Some(mime_type.to_string()),
        size_bytes: Some(size_bytes),
        local_path: Some(local_path.to_string()),
    };
    let _ = crate::dm_transcript_store::append_if_new(&ns, &conv_key, line);
    let _ = crate::contacts_v1::record_thread_message_preview(
        &ns,
        &conv_key,
        preview,
        false,
        Some(created_at_ms),
    );
}

fn enqueue_send_text_dm(
    message_id: String,
    recipient: String,
    text: String,
    wait_for_wire: bool,
) -> Value {
    let recipient_trim = recipient.trim().to_lowercase();
    if let Ok(ident) = unlocked_identity_clone() {
        let my_pk = ident.public_key_hex().trim().to_lowercase();
        if recipient_trim == my_pk {
            native_log::warn(
                "outbound",
                format!("send_text rejected: recipient is own identity msg_id={message_id}"),
            );
            return json_err("cannot send DM to your own identity (scan the other device's QR)");
        }
    }
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    // Preserve existing timestamp if Makepad already saved the message to transcript.
    // This ensures timestamps are immutable - once set, never changed.
    let created_at_ms =
        existing_outbound_created_at_ms(&recipient_trim, &message_id).unwrap_or_else(now_ms);
    if wait_for_wire {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if out_tx
            .send(OutboundCmd::SendText {
                recipient_public_key_hex: recipient,
                text,
                message_id: message_id.clone(),
                created_at_ms,
                done: Some(done_tx),
            })
            .is_err()
        {
            return json_err("p2p send failed (node stopped?)");
        }
        return match done_rx.recv_timeout(Duration::from_secs(8)) {
            Ok(Ok(())) => json_ok(serde_json::json!({ "ok": true, "message_id": message_id })),
            Ok(Err(e)) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": message_id,
                "queued": true,
                "detail": e,
            })),
            Err(_) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": message_id,
                "queued": true,
                "detail": "send pending (outbox will retry)",
            })),
        };
    }
    let recipient_log = recipient.trim();
    let pk_short = if recipient_log.len() >= 16 {
        format!(
            "{}…{}",
            &recipient_log[..8],
            &recipient_log[recipient_log.len() - 8..]
        )
    } else {
        recipient_log.to_string()
    };
    native_log::info(
        "outbound",
        format!(
            "enqueue send_text msg_id={message_id} recipient_pk={pk_short} text_len={}",
            text.len()
        ),
    );
    if out_tx
        .send(OutboundCmd::SendText {
            recipient_public_key_hex: recipient,
            text,
            message_id: message_id.clone(),
            created_at_ms,
            done: None,
        })
        .is_err()
    {
        native_log::warn(
            "outbound",
            format!("send_text failed: node stopped? msg_id={message_id}"),
        );
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "message_id": message_id,
        "queued": true,
    }))
}

fn enqueue_send_voice_dm(
    message_id: String,
    recipient: String,
    duration_ms: u32,
    opus_blob: Vec<u8>,
    wait_for_wire: bool,
) -> Value {
    let recipient_trim = recipient.trim().to_lowercase();
    if let Ok(ident) = unlocked_identity_clone() {
        let my_pk = ident.public_key_hex().trim().to_lowercase();
        if recipient_trim == my_pk {
            native_log::warn(
                "outbound",
                format!("send_voice rejected: recipient is own identity msg_id={message_id}"),
            );
            return json_err("cannot send DM to your own identity (scan the other device's QR)");
        }
    }
    let _ = append_outbound_voice_transcript(&recipient_trim, &message_id, duration_ms, &opus_blob);
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    let created_at_ms =
        existing_outbound_created_at_ms(&recipient_trim, &message_id).unwrap_or_else(now_ms);
    let send_cmd = OutboundCmd::SendVoice {
        recipient_public_key_hex: recipient,
        message_id: message_id.clone(),
        created_at_ms,
        duration_ms,
        opus_blob,
        done: None,
    };
    if wait_for_wire {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let OutboundCmd::SendVoice {
            recipient_public_key_hex,
            message_id: mid,
            created_at_ms,
            duration_ms,
            opus_blob,
            ..
        } = send_cmd
        else {
            unreachable!();
        };
        if out_tx
            .send(OutboundCmd::SendVoice {
                recipient_public_key_hex,
                message_id: mid.clone(),
                created_at_ms,
                duration_ms,
                opus_blob,
                done: Some(done_tx),
            })
            .is_err()
        {
            return json_err("p2p send failed (node stopped?)");
        }
        return match done_rx.recv_timeout(Duration::from_secs(8)) {
            Ok(Ok(())) => json_ok(serde_json::json!({ "ok": true, "message_id": mid })),
            Ok(Err(e)) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": mid,
                "queued": true,
                "detail": e,
            })),
            Err(_) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": mid,
                "queued": true,
                "detail": "send pending (outbox will retry)",
            })),
        };
    }
    native_log::info(
        "outbound",
        format!(
            "enqueue send_voice msg_id={message_id} duration_ms={duration_ms} opus_len={}",
            match &send_cmd {
                OutboundCmd::SendVoice { opus_blob, .. } => opus_blob.len(),
                _ => 0,
            }
        ),
    );
    if out_tx.send(send_cmd).is_err() {
        native_log::warn(
            "outbound",
            format!("send_voice failed: node stopped? msg_id={message_id}"),
        );
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "message_id": message_id,
        "queued": true,
    }))
}

fn enqueue_send_attachment_offer(
    message_id: String,
    recipient: String,
    preview_text: String,
    offer_json: Value,
    wait_for_wire: bool,
) -> Value {
    let recipient_trim = recipient.trim().to_lowercase();
    if let Ok(ident) = unlocked_identity_clone() {
        let my_pk = ident.public_key_hex().trim().to_lowercase();
        if recipient_trim == my_pk {
            return json_err("cannot send DM to your own identity (scan the other device's QR)");
        }
    }
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    let created_at_ms =
        existing_outbound_created_at_ms(&recipient_trim, &message_id).unwrap_or_else(now_ms);
    let done = if wait_for_wire {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        if out_tx
            .send(OutboundCmd::SendAttachmentOffer {
                recipient_public_key_hex: recipient,
                message_id: message_id.clone(),
                created_at_ms,
                preview_text,
                offer_json,
                done: Some(done_tx),
            })
            .is_err()
        {
            return json_err("p2p send failed (node stopped?)");
        }
        return match done_rx.recv_timeout(Duration::from_secs(8)) {
            Ok(Ok(())) => json_ok(serde_json::json!({ "ok": true, "message_id": message_id })),
            Ok(Err(e)) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": message_id,
                "queued": true,
                "detail": e,
            })),
            Err(_) => json_ok(serde_json::json!({
                "ok": true,
                "message_id": message_id,
                "queued": true,
                "detail": "send pending (outbox will retry)",
            })),
        };
    } else {
        None
    };
    if out_tx
        .send(OutboundCmd::SendAttachmentOffer {
            recipient_public_key_hex: recipient,
            message_id: message_id.clone(),
            created_at_ms,
            preview_text,
            offer_json,
            done,
        })
        .is_err()
    {
        return json_err("p2p send failed (node stopped?)");
    }
    json_ok(serde_json::json!({
        "ok": true,
        "message_id": message_id,
        "queued": true,
    }))
}

fn maybe_mirror_voice_on_lan_fast_path(
    message_id: &str,
    recipient: &str,
    duration_ms: u32,
    opus_blob: &[u8],
) {
    if !crate::text_transport::lan_fast_path_enabled() {
        return;
    }
    if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
        return;
    }
    let _ = enqueue_send_voice_dm(
        message_id.to_string(),
        recipient.to_string(),
        duration_ms,
        opus_blob.to_vec(),
        false,
    );
}

fn maybe_mirror_text_on_lan_fast_path(message_id: &str, recipient: &str, text: &str) {
    if !crate::text_transport::lan_fast_path_enabled() {
        return;
    }
    if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
        return;
    }
    let _ = enqueue_send_text_dm(
        message_id.to_string(),
        recipient.to_string(),
        text.to_string(),
        false,
    );
}

pub fn p2p_send_text_dm(recipient: &str, text: &str) -> Value {
    let message_id = new_msg_id_for_ffi();
    if crate::text_transport::delivery_primary_text() {
        let result = crate::delivery_runtime::delivery_send_text_dm(recipient, text, &message_id);
        maybe_mirror_text_on_lan_fast_path(&message_id, recipient, text);
        return result;
    }
    if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
        return json_err(
            "GHALBOL_DELIVERY_URL not set — WAN text requires delivery server; peer not on LAN",
        );
    }
    enqueue_send_text_dm(message_id, recipient.to_string(), text.to_string(), false)
}

pub fn p2p_send_voice_dm(recipient: &str, duration_ms: u32, opus_blob: Vec<u8>) -> Value {
    let message_id = new_msg_id_for_ffi();
    if crate::text_transport::delivery_primary_text() {
        let result = crate::delivery_runtime::delivery_send_voice_dm(
            recipient,
            duration_ms,
            opus_blob.clone(),
            &message_id,
        );
        maybe_mirror_voice_on_lan_fast_path(&message_id, recipient, duration_ms, &opus_blob);
        return result;
    }
    if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
        return json_err(
            "GHALBOL_DELIVERY_URL not set — WAN text requires delivery server; peer not on LAN",
        );
    }
    enqueue_send_voice_dm(
        message_id,
        recipient.to_string(),
        duration_ms,
        opus_blob,
        false,
    )
}

pub fn p2p_send_attachment(recipient: &str, config: &Value) -> Value {
    let Some(ns) = active_app_namespace() else {
        return json_err("app namespace not set");
    };
    let file_path = match config
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(str::trim)
    {
        Some(s) if !s.is_empty() => s,
        _ => return json_err("file_path required"),
    };
    let file_name = config
        .get("file_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::path::Path::new(file_path)
                .file_name()
                .and_then(|s| s.to_str())
        })
        .unwrap_or("file");
    let mime_type = config
        .get("mime_type")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream");
    let message_id = new_msg_id_for_ffi();
    let recipient = recipient.trim();

    // Prefer mailbox path (delivery / LAN DM) — same E2E rail as voice.
    match crate::attach_v1::pack_attachment_for_mailbox(
        std::path::Path::new(file_path),
        file_name,
        mime_type,
    ) {
        Ok(inner) => {
            let preview = crate::attach_v1::attachment_preview(&inner.file_name);
            append_outbound_attachment_transcript(
                recipient,
                &message_id,
                &inner.file_name,
                &inner.mime_type,
                inner.size_plaintext,
                file_path,
                &preview,
            );
            let offer_json = match inner.to_json_value() {
                Ok(v) => v,
                Err(e) => return json_err(e),
            };
            if crate::text_transport::delivery_primary_text() {
                let result = crate::delivery_runtime::delivery_send_attachment(
                    recipient,
                    inner,
                    &message_id,
                );
                maybe_mirror_attachment_on_lan_fast_path(
                    &message_id,
                    recipient,
                    &preview,
                    offer_json,
                );
                return result;
            }
            if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
                return json_err(
                    "GHALBOL_DELIVERY_URL not set and peer not on LAN — cannot send attachment",
                );
            }
            return enqueue_send_attachment_offer(
                message_id,
                recipient.to_string(),
                preview,
                offer_json,
                false,
            );
        }
        Err(mailbox_err) => {
            // Oversized for mailbox: LAN mux only (never WAN/coord).
            if crate::text_transport::delivery_primary_text()
                && !crate::p2p::contact_has_lan_p2p_text_path(recipient)
            {
                return json_err(mailbox_err);
            }
            if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
                return json_err(format!(
                    "{mailbox_err}; peer not on LAN for large-file transfer"
                ));
            }
            let staged = match crate::attach_v1::stage_file_for_offer(
                &ns,
                recipient,
                &message_id,
                std::path::Path::new(file_path),
                file_name,
                mime_type,
            ) {
                Ok(s) => s,
                Err(e) => return json_err(e),
            };
            append_outbound_attachment_transcript(
                recipient,
                &message_id,
                &staged.file_name,
                &staged.mime_type,
                staged.size_plaintext,
                file_path,
                &staged.preview,
            );
            let blob_id = staged.blob_id.clone();
            let mut result = enqueue_send_attachment_offer(
                message_id,
                recipient.to_string(),
                staged.preview,
                staged.offer_json,
                false,
            );
            if let Some(obj) = result.as_object_mut() {
                obj.insert("blob_id".to_string(), serde_json::json!(blob_id));
                obj.insert("lan_mux".to_string(), serde_json::json!(true));
            }
            result
        }
    }
}

fn maybe_mirror_attachment_on_lan_fast_path(
    message_id: &str,
    recipient: &str,
    preview: &str,
    offer_json: Value,
) {
    if !crate::text_transport::lan_fast_path_enabled() {
        return;
    }
    if !crate::p2p::contact_has_lan_p2p_text_path(recipient) {
        return;
    }
    let _ = enqueue_send_attachment_offer(
        message_id.to_string(),
        recipient.to_string(),
        preview.to_string(),
        offer_json,
        false,
    );
}

/// How long `p2p_attachment_fetch` waits for a start-up verdict before reporting
/// the transfer as in progress.
const ATTACHMENT_FETCH_START_GRACE: Duration = Duration::from_millis(1500);

pub fn p2p_attachment_fetch(config: &Value) -> Value {
    let peer = match config
        .get("peer_public_key_hex")
        .or_else(|| config.get("sender_public_key_hex"))
        .and_then(|v| v.as_str())
        .map(str::trim)
    {
        Some(s) if !s.is_empty() => s,
        _ => return json_err("peer_public_key_hex required"),
    };
    let offer_id = match config
        .get("offer_id")
        .or_else(|| config.get("message_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
    {
        Some(s) if !s.is_empty() => s,
        _ => return json_err("offer_id required"),
    };
    let save_path = config
        .get("save_path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let out_tx = {
        let g = match p2p_mx().lock() {
            Ok(g) => g,
            Err(_) => return json_err("p2p mutex poisoned"),
        };
        let Some(h) = g.as_ref() else {
            return json_err("p2p not running");
        };
        h.out_tx.clone()
    };
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    if out_tx
        .send(OutboundCmd::FetchAttachment {
            peer_public_key_hex: peer.to_string(),
            offer_id: offer_id.to_string(),
            save_path,
            done: done_tx,
        })
        .is_err()
    {
        return json_err("p2p fetch failed (node stopped?)");
    }
    match done_rx.recv_timeout(ATTACHMENT_FETCH_START_GRACE) {
        Ok(Ok(local_path)) => json_ok(serde_json::json!({
            "ok": true,
            "offer_id": offer_id,
            "local_path": local_path,
        })),
        Ok(Err(e)) => json_err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            json_err("attachment fetch aborted")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => json_ok(serde_json::json!({
            "ok": true,
            "offer_id": offer_id,
            "downloading": true,
        })),
    }
}

