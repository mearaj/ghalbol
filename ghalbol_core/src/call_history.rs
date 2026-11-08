//! Local call-history lines in the chat transcript (optional GHALBOL_VOICE_V1 follow-up).

use crate::dm_transcript_store::StoredChatLine;
use crate::p2p::call_active::ActiveCallSnapshot;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn format_duration(ms: i64) -> String {
    let secs = (ms / 1000).max(0) as u32;
    let m = secs / 60;
    let s = secs % 60;
    format!("{m}:{s:02}")
}

fn summary_text(kind: &str, reason: &str, elapsed: i64) -> String {
    match reason {
        "missed" | "rejected" | "remote_reject" => format!("Missed {kind}"),
        "remote_hangup" if elapsed < 2_000 => format!("Missed {kind}"),
        _ if elapsed < 2_000 => format!("{kind} · cancelled"),
        _ => format!("{kind} · {}", format_duration(elapsed)),
    }
}

fn call_event_outgoing(reason: &str, elapsed: i64) -> bool {
    match reason {
        "missed" | "rejected" | "remote_reject" => false,
        "remote_hangup" if elapsed < 2_000 => false,
        _ => true,
    }
}

/// Append a local-only call summary to the peer transcript (no wire send).
pub fn record_call_ended(snap: &ActiveCallSnapshot, reason: &str) {
    let Some(ns) = crate::dm_event_handler::active_app_namespace() else {
        return;
    };
    let peer = snap.peer_public_key_hex.trim();
    if peer.is_empty() {
        return;
    }
    let now = now_ms();
    let elapsed = if snap.started_at_ms > 0 {
        now.saturating_sub(snap.started_at_ms)
    } else {
        0
    };
    let kind = if snap.video_active || snap.camera_on || snap.remote_video_on {
        "Video call"
    } else {
        "Voice call"
    };
    let text = summary_text(kind, reason, elapsed);
    // Missed / rejected rings render as inbound; connected/cancelled hangups as outbound.
    let outgoing = call_event_outgoing(reason, elapsed);
    let line = StoredChatLine {
        local_id: format!("call-{}-{}", snap.call_id, now),
        text,
        outgoing,
        from: if outgoing {
            None
        } else {
            Some(peer.to_string())
        },
        message_id: Some(format!("call-{}", snap.call_id)),
        delivery: "read".into(),
        created_at_ms: Some(now),
        received_at_ms: if outgoing { None } else { Some(now) },
        read_ack_sent: true,
        msg_kind: "call_event".into(),
        duration_ms: Some(elapsed.max(0) as u32),
        audio_path: None,
        file_name: None,
        mime_type: None,
        size_bytes: None,
        local_path: None,
    };
    let _ = crate::dm_transcript_store::append_if_new(&ns, peer, line);
}

/// Snapshot-based record when ending from UI / remote hangup.
pub fn record_from_active(reason: &str) {
    if let Some(snap) = crate::p2p::call_active::snapshot() {
        record_call_ended(&snap, reason);
    }
}

/// Record a ring that never reached active media (Decline, miss, or remote reject).
pub fn record_ring_outcome(call_id: &str, peer_public_key_hex: &str, video: bool, reason: &str) {
    let call_id = call_id.trim();
    let peer = peer_public_key_hex.trim();
    // Match call_state / media ceilings — refuse pathological ids before transcript write.
    if call_id.is_empty() || call_id.len() > 128 || peer.is_empty() || peer.len() > 192 {
        return;
    }
    let snap = ActiveCallSnapshot {
        call_id: call_id.to_string(),
        peer_public_key_hex: peer.to_string(),
        voice_active: false,
        video_active: video,
        camera_on: false,
        remote_video_on: false,
        started_at_ms: now_ms(),
    };
    record_call_ended(&snap, reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missed_and_reject_reasons_label_as_missed() {
        assert_eq!(summary_text("Voice call", "missed", 0), "Missed Voice call");
        assert_eq!(
            summary_text("Voice call", "rejected", 500),
            "Missed Voice call"
        );
        assert_eq!(
            summary_text("Video call", "remote_reject", 1_000),
            "Missed Video call"
        );
    }

    #[test]
    fn short_remote_hangup_counts_as_missed() {
        assert_eq!(
            summary_text("Voice call", "remote_hangup", 1_500),
            "Missed Voice call"
        );
    }

    #[test]
    fn connected_call_shows_duration() {
        assert_eq!(
            summary_text("Voice call", "ui_hangup", 65_000),
            "Voice call · 1:05"
        );
    }

    #[test]
    fn short_local_cancel_label() {
        assert_eq!(
            summary_text("Voice call", "ui_hangup", 800),
            "Voice call · cancelled"
        );
    }

    #[test]
    fn missed_reasons_are_inbound() {
        assert!(!call_event_outgoing("missed", 0));
        assert!(!call_event_outgoing("rejected", 500));
        assert!(!call_event_outgoing("remote_reject", 1_000));
        assert!(!call_event_outgoing("remote_hangup", 1_500));
        assert!(call_event_outgoing("remote_hangup", 5_000));
        assert!(call_event_outgoing("ui_hangup", 800));
    }

    #[test]
    fn record_ring_outcome_ignores_pathological_ids() {
        // Must not panic or attempt a transcript write with absurd keys.
        record_ring_outcome(&"c".repeat(200), &"aa".repeat(33), false, "missed");
        record_ring_outcome("ok-call", &"p".repeat(300), true, "missed");
        record_ring_outcome("", &"aa".repeat(33), false, "missed");
    }
}
