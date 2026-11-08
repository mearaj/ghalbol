//! In-memory voice-call state (one active call per remote pubkey).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::call_sig_v1::CallSigKind;

/// Match Makepad `CallController._maxLiveInviteAgeMs` — invites and ringing UI must not outlive this.
pub const MAX_LIVE_CALL_INVITE_AGE_MS: i64 = 45_000;
/// Match transport/call_media call_id ceiling — reject before HashMap insert.
const MAX_CALL_ID_CHARS: usize = 128;
/// Bound concurrent peer call rows under invite storms.
const MAX_PEER_CALL_ROWS: usize = 256;

fn validate_call_id(call_id: &str) -> Result<(), String> {
    let t = call_id.trim();
    if t.is_empty() || t.len() > MAX_CALL_ID_CHARS {
        return Err("call_id invalid".into());
    }
    Ok(())
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn call_invite_is_live(created_at_ms: i64, now_ms: i64) -> bool {
    if created_at_ms <= 0 {
        return false;
    }
    let age = now_ms.saturating_sub(created_at_ms);
    age >= 0 && age <= MAX_LIVE_CALL_INVITE_AGE_MS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallPhase {
    Idle,
    OutgoingRinging,
    IncomingRinging,
    Connected,
}

#[derive(Clone, Debug)]
struct PeerCall {
    call_id: String,
    phase: CallPhase,
    video_enabled: bool,
    /// When [phase] last changed — used to expire stuck ringing after hangup loss.
    phase_at_ms: i64,
}

fn store() -> &'static Mutex<HashMap<String, PeerCall>> {
    static S: OnceLock<Mutex<HashMap<String, PeerCall>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn clear_all_calls() {
    if let Ok(mut g) = store().lock() {
        g.clear();
    }
}

/// Active `(peer_pk_hex, call_id)` pairs for privacy teardown when the UI session ends.
pub fn store_for_teardown() -> Result<Vec<(String, String)>, ()> {
    let Ok(g) = store().lock() else {
        return Err(());
    };
    Ok(g.iter()
        .map(|(pk, c)| (pk.clone(), c.call_id.clone()))
        .collect())
}

/// One ring dropped by [expire_stale_ringing] (peer wire, call id, was inbound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredRing {
    pub peer_public_key_hex: String,
    pub call_id: String,
    pub incoming: bool,
    pub video_enabled: bool,
}

/// Drop [CallPhase::IncomingRinging] / [CallPhase::OutgoingRinging] older than [MAX_LIVE_CALL_INVITE_AGE_MS].
/// Returns each expired ring so callers can record missed / cancelled history.
pub fn expire_stale_ringing(now_ms: i64) -> Vec<ExpiredRing> {
    let Ok(mut g) = store().lock() else {
        return Vec::new();
    };
    let mut expired = Vec::new();
    g.retain(|pk, c| {
        let ringing = matches!(
            c.phase,
            CallPhase::IncomingRinging | CallPhase::OutgoingRinging
        );
        if !ringing || now_ms.saturating_sub(c.phase_at_ms) <= MAX_LIVE_CALL_INVITE_AGE_MS {
            return true;
        }
        expired.push(ExpiredRing {
            peer_public_key_hex: pk.clone(),
            call_id: c.call_id.clone(),
            incoming: c.phase == CallPhase::IncomingRinging,
            video_enabled: c.video_enabled,
        });
        false
    });
    expired
}

/// Whether the live call for `peer` was started as video (invite / connected).
pub fn peer_call_video_enabled(peer_pk_hex: &str) -> bool {
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    store()
        .lock()
        .ok()
        .and_then(|g| g.get(&key).map(|c| c.video_enabled))
        .unwrap_or(false)
}

pub fn clear_peer(peer_pk_hex: &str) {
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    if let Ok(mut g) = store().lock() {
        g.remove(&key);
    }
}

pub fn peer_call_phase(peer_pk_hex: &str) -> CallPhase {
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    store()
        .lock()
        .ok()
        .and_then(|g| g.get(&key).map(|c| c.phase))
        .unwrap_or(CallPhase::Idle)
}

/// First inbound ring waiting for the user (for UI restore when the app was killed).
/// Callers that care about TTL must run [expire_stale_ringing] first so history can be recorded.
pub fn first_incoming_ringing() -> Option<(String, String)> {
    let Ok(g) = store().lock() else {
        return None;
    };
    for (pk, call) in g.iter() {
        if call.phase == CallPhase::IncomingRinging {
            return Some((pk.clone(), call.call_id.clone()));
        }
    }
    None
}

/// First outbound ring (caller waiting for peer accept) — never show Accept here.
pub fn first_outgoing_ringing() -> Option<(String, String)> {
    let Ok(g) = store().lock() else {
        return None;
    };
    for (pk, call) in g.iter() {
        if call.phase == CallPhase::OutgoingRinging {
            return Some((pk.clone(), call.call_id.clone()));
        }
    }
    None
}

/// Age of the current inbound ring, for UI stale checks.
pub fn incoming_ring_age_ms(now_ms: i64) -> Option<i64> {
    let Ok(g) = store().lock() else {
        return None;
    };
    for call in g.values() {
        if call.phase == CallPhase::IncomingRinging {
            return Some(now_ms.saturating_sub(call.phase_at_ms));
        }
    }
    None
}

#[cfg(test)]
pub fn phase_for_peer(peer_pk_hex: &str) -> CallPhase {
    snapshot_for_peer(peer_pk_hex).phase
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSnapshot {
    pub phase: CallPhase,
    pub call_id: Option<String>,
    pub video_enabled: bool,
}

#[cfg(test)]
pub fn snapshot_for_peer(peer_pk_hex: &str) -> CallSnapshot {
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    store()
        .lock()
        .ok()
        .and_then(|g| g.get(&key).cloned())
        .map(|c| CallSnapshot {
            phase: c.phase,
            call_id: Some(c.call_id),
            video_enabled: c.video_enabled,
        })
        .unwrap_or(CallSnapshot {
            phase: CallPhase::Idle,
            call_id: None,
            video_enabled: false,
        })
}

fn fresh_call(call_id: String, phase: CallPhase, video_enabled: bool) -> PeerCall {
    PeerCall {
        call_id,
        phase,
        video_enabled,
        phase_at_ms: now_ms(),
    }
}

/// True when invite/accept payload advertises audio+video (or video-only).
pub fn invite_payload_wants_video(payload: &serde_json::Value) -> bool {
    matches!(
        payload
            .get("media")
            .and_then(|v| v.as_str())
            .map(str::trim),
        Some("audio_video" | "video")
    )
}

/// Apply an **outbound** signal before enqueueing to the network.
/// `invite_video` is honored for [CallSigKind::Invite] only.
pub fn apply_outbound_ex(
    peer_pk_hex: &str,
    call_id: &str,
    kind: CallSigKind,
    invite_video: bool,
) -> Result<(), String> {
    validate_call_id(call_id)?;
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    let mut g = store().lock().map_err(|_| "call state lock".to_string())?;
    let cur = g.get(&key).cloned();
    match kind {
        CallSigKind::Invite => {
            match cur {
                None => {
                    if g.len() >= MAX_PEER_CALL_ROWS {
                        return Err("too many active calls".into());
                    }
                    g.insert(
                        key,
                        fresh_call(
                            call_id.to_string(),
                            CallPhase::OutgoingRinging,
                            invite_video,
                        ),
                    );
                }
                // Idempotent: host applies before enqueue; the outbound worker applies again.
                Some(c)
                    if c.phase == CallPhase::OutgoingRinging && c.call_id == call_id =>
                {
                    if invite_video && !c.video_enabled {
                        g.insert(
                            key,
                            PeerCall {
                                video_enabled: true,
                                ..c
                            },
                        );
                    }
                }
                Some(_) => {
                    return Err("call already active with this contact".to_string());
                }
            }
        }
        CallSigKind::Accept => {
            let Some(c) = cur else {
                return Err("no call to accept".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            match c.phase {
                CallPhase::IncomingRinging => {
                    g.insert(
                        key,
                        fresh_call(call_id.to_string(), CallPhase::Connected, c.video_enabled),
                    );
                }
                CallPhase::Connected => {}
                _ => return Err("call not in incoming_ringing".to_string()),
            }
        }
        CallSigKind::Reject | CallSigKind::Hangup => {
            g.remove(&key);
        }
        CallSigKind::VideoOn => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            if c.phase != CallPhase::Connected {
                return Err("video_on only when connected".to_string());
            }
            g.insert(
                key,
                fresh_call(call_id.to_string(), CallPhase::Connected, true),
            );
        }
        CallSigKind::VideoOff => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            g.insert(
                key,
                PeerCall {
                    call_id: call_id.to_string(),
                    phase: c.phase,
                    video_enabled: false,
                    phase_at_ms: c.phase_at_ms,
                },
            );
        }
        CallSigKind::SdpOffer | CallSigKind::SdpAnswer | CallSigKind::Ice => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
        }
        CallSigKind::KeyRequest => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            if c.phase != CallPhase::Connected {
                return Err("key_request only when connected".to_string());
            }
        }
    }
    Ok(())
}

/// Apply an **inbound** signal after cryptographic verify.
/// `invite_video` is honored for [CallSigKind::Invite] only.
pub fn apply_inbound_ex(
    peer_pk_hex: &str,
    call_id: &str,
    kind: CallSigKind,
    invite_video: bool,
) -> Result<(), String> {
    validate_call_id(call_id)?;
    let key = peer_pk_hex.trim().to_ascii_lowercase();
    let mut g = store().lock().map_err(|_| "call state lock".to_string())?;
    let cur = g.get(&key).cloned();
    match kind {
        CallSigKind::Invite => {
            match cur {
                None => {
                    if g.len() >= MAX_PEER_CALL_ROWS {
                        return Err("too many active calls".into());
                    }
                    g.insert(
                        key,
                        fresh_call(
                            call_id.to_string(),
                            CallPhase::IncomingRinging,
                            invite_video,
                        ),
                    );
                }
                Some(c) if c.phase == CallPhase::OutgoingRinging => {
                    // Glare: both sides tapped Call — lower call_id is the canonical call.
                    if call_id < c.call_id.as_str() {
                        g.insert(
                            key,
                            fresh_call(
                                call_id.to_string(),
                                CallPhase::IncomingRinging,
                                invite_video,
                            ),
                        );
                    } else {
                        return Err("busy".to_string());
                    }
                }
                Some(_) => return Err("busy".to_string()),
            }
        }
        CallSigKind::Accept => {
            let Some(c) = cur else {
                return Err("no outgoing call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            match c.phase {
                CallPhase::OutgoingRinging => {
                    g.insert(
                        key,
                        fresh_call(call_id.to_string(), CallPhase::Connected, c.video_enabled),
                    );
                }
                CallPhase::Connected => {}
                _ => return Err("accept on unexpected phase".to_string()),
            }
        }
        CallSigKind::Reject | CallSigKind::Hangup => {
            g.remove(&key);
        }
        CallSigKind::VideoOn => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            g.insert(
                key,
                PeerCall {
                    call_id: call_id.to_string(),
                    phase: c.phase,
                    video_enabled: true,
                    phase_at_ms: c.phase_at_ms,
                },
            );
        }
        CallSigKind::VideoOff => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            g.insert(
                key,
                PeerCall {
                    call_id: call_id.to_string(),
                    phase: c.phase,
                    video_enabled: false,
                    phase_at_ms: c.phase_at_ms,
                },
            );
        }
        CallSigKind::SdpOffer | CallSigKind::SdpAnswer | CallSigKind::Ice => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
        }
        CallSigKind::KeyRequest => {
            let Some(c) = cur else {
                return Err("no active call".to_string());
            };
            if c.call_id != call_id {
                return Err("call_id mismatch".to_string());
            }
            // No phase change — peer asked us to emit a video keyframe.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_sig_v1::CallSigKind;
    use std::sync::{Mutex, OnceLock};

    fn lock_call_state_tests() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn glare_simultaneous_outbound_invites() {
        let _lock = lock_call_state_tests();
        // Each test must use a unique key because `call_state` is global process state and
        // lib tests run concurrently.
        const PK: &str = "0305b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_outbound_ex(PK, "call-bbb", CallSigKind::Invite, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::OutgoingRinging);
        apply_inbound_ex(PK, "call-aaa", CallSigKind::Invite, false).unwrap();
        let snap = snapshot_for_peer(PK);
        assert_eq!(snap.phase, CallPhase::IncomingRinging);
        assert_eq!(snap.call_id.as_deref(), Some("call-aaa"));

        clear_all_calls();
        apply_outbound_ex(PK, "call-aaa", CallSigKind::Invite, false).unwrap();
        assert!(apply_inbound_ex(PK, "call-bbb", CallSigKind::Invite, false).is_err());
        assert_eq!(phase_for_peer(PK), CallPhase::OutgoingRinging);
        assert_eq!(snapshot_for_peer(PK).call_id.as_deref(), Some("call-aaa"));
    }

    #[test]
    fn expire_stale_ringing_clears_old_inbound() {
        let _lock = lock_call_state_tests();
        const PK: &str = "03f1b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        let t0 = now_ms();
        apply_inbound_ex(PK, "call-stale", CallSigKind::Invite, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::IncomingRinging);
        let expired = expire_stale_ringing(t0 + MAX_LIVE_CALL_INVITE_AGE_MS + 1_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].call_id, "call-stale");
        assert!(expired[0].incoming);
        assert!(!expired[0].video_enabled);
        assert_eq!(phase_for_peer(PK), CallPhase::Idle);
        assert!(first_incoming_ringing().is_none());
    }

    #[test]
    fn expire_stale_video_invite_preserves_video_flag() {
        let _lock = lock_call_state_tests();
        const PK: &str = "03a1b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        let t0 = now_ms();
        apply_inbound_ex(PK, "call-vid", CallSigKind::Invite, true).unwrap();
        assert!(peer_call_video_enabled(PK));
        let expired = expire_stale_ringing(t0 + MAX_LIVE_CALL_INVITE_AGE_MS + 1_000);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].video_enabled);
    }

    #[test]
    fn invite_payload_wants_video_parses_media() {
        assert!(invite_payload_wants_video(&serde_json::json!({
            "media": "audio_video"
        })));
        assert!(invite_payload_wants_video(&serde_json::json!({ "media": "video" })));
        assert!(!invite_payload_wants_video(&serde_json::json!({ "media": "audio" })));
        assert!(!invite_payload_wants_video(&serde_json::json!({})));
    }

    #[test]
    fn duplicate_outbound_invite_same_call_id_is_idempotent() {
        let _lock = lock_call_state_tests();
        const PK: &str = "0365b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_outbound_ex(PK, "call-dup", CallSigKind::Invite, false).unwrap();
        apply_outbound_ex(PK, "call-dup", CallSigKind::Invite, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::OutgoingRinging);
    }

    #[test]
    fn accept_rejects_wrong_call_id_while_ringing() {
        let _lock = lock_call_state_tests();
        const PK: &str = "0395b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_inbound_ex(PK, "call-real", CallSigKind::Invite, false).unwrap();
        assert!(apply_outbound_ex(PK, "call-other", CallSigKind::Accept, false).is_err());
        assert_eq!(phase_for_peer(PK), CallPhase::IncomingRinging);
    }

    #[test]
    fn hangup_on_idle_is_harmless() {
        let _lock = lock_call_state_tests();
        const PK: &str = "0375b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_outbound_ex(PK, "gone", CallSigKind::Hangup, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::Idle);
    }

    #[test]
    fn duplicate_outbound_accept_is_idempotent_when_connected() {
        let _lock = lock_call_state_tests();
        const PK: &str = "0385b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_inbound_ex(PK, "call-acc", CallSigKind::Invite, false).unwrap();
        apply_outbound_ex(PK, "call-acc", CallSigKind::Accept, false).unwrap();
        apply_outbound_ex(PK, "call-acc", CallSigKind::Accept, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::Connected);
    }

    #[test]
    fn inbound_accept_rejects_while_incoming_ringing() {
        let _lock = lock_call_state_tests();
        const PK: &str = "0399b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_inbound_ex(PK, "call-in", CallSigKind::Invite, false).unwrap();
        assert!(apply_inbound_ex(PK, "call-in", CallSigKind::Accept, false).is_err());
        assert_eq!(phase_for_peer(PK), CallPhase::IncomingRinging);
    }

    #[test]
    fn duplicate_inbound_accept_idempotent_on_outgoing_ringing() {
        let _lock = lock_call_state_tests();
        const PK: &str = "03a9b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        apply_outbound_ex(PK, "call-out", CallSigKind::Invite, false).unwrap();
        apply_inbound_ex(PK, "call-out", CallSigKind::Accept, false).unwrap();
        apply_inbound_ex(PK, "call-out", CallSigKind::Accept, false).unwrap();
        assert_eq!(phase_for_peer(PK), CallPhase::Connected);
    }

    #[test]
    fn reject_oversized_or_empty_call_id() {
        let _lock = lock_call_state_tests();
        const PK: &str = "03b9b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784";
        clear_all_calls();
        let huge = "c".repeat(MAX_CALL_ID_CHARS + 1);
        assert!(apply_outbound_ex(PK, &huge, CallSigKind::Invite, false).is_err());
        assert!(apply_inbound_ex(PK, "", CallSigKind::Invite, false).is_err());
        assert_eq!(phase_for_peer(PK), CallPhase::Idle);
    }
}
