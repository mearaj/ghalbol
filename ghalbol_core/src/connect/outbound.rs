//! Process outbound commands for the connect worker.

use std::sync::Arc;

use super::bridge_ws::{bridge_request_for_call, connect_bridge_session};
use super::chat_room_session::begin_chat_room_session;
use super::frames::{
    build_pending_outbound_frame, fetch_attachment_for_peer, send_availability_status_to_peer,
    send_frame_to_peer, start_call_media_for_peer, start_call_video_for_peer,
};
use super::outbox_acks::{
    flush_pending_call_signals, handle_run_read_ack_catchup, handle_send_ack_cmd,
};
use super::peer_session::{dial_peer_tcp, prune_closed_writers, writer_open_for_peer};
use super::prelude::*;
use super::session::chrono_now_ms;
use super::types::{
    GossipChatEvent, OutboundCmd, PendingCallSignal, PendingOutbound,
    session_peer_from_identity_wire,
};
use super::ui_session::{emit_call_media, on_local_call_signal_sent};
use super::worker::ConnectWorkerState;

pub(crate) async fn process_outbound_cmds(
    worker: Arc<ConnectWorkerState>,
    events_tx: &Option<std::sync::mpsc::Sender<GossipChatEvent>>,
    outbound_rx: &std::sync::mpsc::Receiver<OutboundCmd>,
    max: usize,
) {
    for _ in 0..max {
        let Ok(cmd) = outbound_rx.try_recv() else {
            break;
        };
        process_one(Arc::clone(&worker), events_tx, cmd).await;
    }
}

async fn process_one(
    worker: Arc<ConnectWorkerState>,
    events_tx: &Option<std::sync::mpsc::Sender<GossipChatEvent>>,
    cmd: OutboundCmd,
) {
    let session = Arc::clone(&worker.session);
    let writers = Arc::clone(&worker.registry.writers);
    match cmd {
        OutboundCmd::RegisterDmPeer { public_key_hex } => {
            session.register_dm_peer_key(&public_key_hex);
        }
        OutboundCmd::SetForegroundPeer {
            identity_wire,
            generation: _,
        } => {
            let peer = identity_wire
                .as_deref()
                .and_then(|w| session_peer_from_identity_wire(w).ok());
            if let Some(ref p) = peer {
                begin_chat_room_session(session.as_ref(), p);
            }
            session.set_foreground_peer(peer.clone());
            if let Some(ref pk) = peer {
                crate::coord_runtime::note_peer_lookup_intent(pk);
            }
        }
        OutboundCmd::RunReadAckCatchup { identity_wire } => {
            handle_run_read_ack_catchup(Arc::clone(&session), writers, identity_wire).await;
        }
        OutboundCmd::SendText {
            recipient_public_key_hex,
            text,
            message_id,
            created_at_ms,
            done,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&recipient_public_key_hex) else {
                let _ = done.map(|tx| tx.send(Err("invalid recipient".into())));
                return;
            };
            session.register_dm_peer_key(&recipient_public_key_hex);
            let now = chrono_now_ms();
            let pending = PendingOutbound {
                message_id: message_id.clone(),
                peer: peer.clone(),
                recipient_public_key_hex: recipient_public_key_hex.clone(),
                text: text.clone(),
                msg_kind: "text".to_string(),
                attachment_offer: None,
                voice_opus: None,
                duration_ms: None,
                created_at_ms,
                last_send_ms: 0,
                first_on_wire_ms: 0,
                on_wire: false,
            };
            session.track_outbound(pending.clone());
            if writer_open_for_peer(&writers, &peer) {
                match build_pending_outbound_frame(session.as_ref(), &pending) {
                    Ok(frame) => {
                        if send_frame_to_peer(&peer, frame, &writers).await.is_ok() {
                            session.mark_outbox_sent(&message_id, now);
                            if let Some(tx) = events_tx {
                                let _ = tx.send(GossipChatEvent::OutboundSent {
                                    message_id: message_id.clone(),
                                });
                            }
                            let _ = done.map(|tx| tx.send(Ok(())));
                            return;
                        }
                    }
                    Err(e) => {
                        native_log::debug("outbound", format!("send_text deferred: {e}"));
                    }
                }
            }
            let _ = done.map(|tx| tx.send(Err("peer stream not ready".into())));
        }
        OutboundCmd::SendVoice {
            recipient_public_key_hex,
            message_id,
            created_at_ms,
            duration_ms,
            opus_blob,
            done,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&recipient_public_key_hex) else {
                let _ = done.map(|tx| tx.send(Err("invalid recipient".into())));
                return;
            };
            session.register_dm_peer_key(&recipient_public_key_hex);
            let now = chrono_now_ms();
            let pending = PendingOutbound {
                message_id: message_id.clone(),
                peer: peer.clone(),
                recipient_public_key_hex: recipient_public_key_hex.clone(),
                text: crate::voice_msg_v1::voice_preview(duration_ms),
                msg_kind: "voice".to_string(),
                attachment_offer: None,
                voice_opus: Some(opus_blob),
                duration_ms: Some(duration_ms),
                created_at_ms,
                last_send_ms: 0,
                first_on_wire_ms: 0,
                on_wire: false,
            };
            session.track_outbound(pending.clone());
            if writer_open_for_peer(&writers, &peer) {
                match build_pending_outbound_frame(session.as_ref(), &pending) {
                    Ok(frame) => {
                        if send_frame_to_peer(&peer, frame, &writers).await.is_ok() {
                            session.mark_outbox_sent(&message_id, now);
                            if let Some(tx) = events_tx {
                                let _ = tx.send(GossipChatEvent::OutboundSent {
                                    message_id: message_id.clone(),
                                });
                            }
                            let _ = done.map(|tx| tx.send(Ok(())));
                            return;
                        }
                    }
                    Err(e) => {
                        native_log::debug("outbound", format!("send_voice deferred: {e}"));
                    }
                }
            }
            let _ = done.map(|tx| tx.send(Err("peer stream not ready".into())));
        }
        OutboundCmd::SendAttachmentOffer {
            recipient_public_key_hex,
            message_id,
            created_at_ms,
            preview_text,
            offer_json,
            done,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&recipient_public_key_hex) else {
                let _ = done.map(|tx| tx.send(Err("invalid recipient".into())));
                return;
            };
            session.register_dm_peer_key(&recipient_public_key_hex);
            let now = chrono_now_ms();
            let pending = PendingOutbound {
                message_id: message_id.clone(),
                peer: peer.clone(),
                recipient_public_key_hex: recipient_public_key_hex.clone(),
                text: preview_text,
                msg_kind: "attachment_offer".to_string(),
                attachment_offer: Some(offer_json),
                voice_opus: None,
                duration_ms: None,
                created_at_ms,
                last_send_ms: 0,
                first_on_wire_ms: 0,
                on_wire: false,
            };
            session.track_outbound(pending.clone());
            if writer_open_for_peer(&writers, &peer) {
                match build_pending_outbound_frame(session.as_ref(), &pending) {
                    Ok(frame) => {
                        if send_frame_to_peer(&peer, frame, &writers).await.is_ok() {
                            session.mark_outbox_sent(&message_id, now);
                            if let Some(tx) = events_tx {
                                let _ = tx.send(GossipChatEvent::OutboundSent {
                                    message_id: message_id.clone(),
                                });
                            }
                            let _ = done.map(|tx| tx.send(Ok(())));
                            return;
                        }
                    }
                    Err(e) => {
                        native_log::debug("outbound", format!("send_attachment deferred: {e}"));
                    }
                }
            }
            let _ = done.map(|tx| tx.send(Err("peer stream not ready".into())));
        }
        OutboundCmd::SendAvailabilityStatus {
            recipient_public_key_hex,
            status,
            updated_at_ms,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&recipient_public_key_hex) else {
                native_log::warn("outbound", "availability_status dropped: invalid recipient");
                return;
            };
            session.register_dm_peer_key(&recipient_public_key_hex);
            if !writer_open_for_peer(&writers, &peer) {
                native_log::debug(
                    "outbound",
                    format!("availability_status deferred: no writer {peer}"),
                );
                return;
            }
            if let Err(e) = send_availability_status_to_peer(
                session.as_ref(),
                &writers,
                &peer,
                status.as_deref(),
                updated_at_ms,
            )
            .await
            {
                native_log::debug("outbound", format!("availability_status send failed: {e}"));
            }
        }
        OutboundCmd::FetchAttachment {
            peer_public_key_hex,
            offer_id,
            save_path,
            done,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&peer_public_key_hex) else {
                let _ = done.send(Err("invalid peer".into()));
                return;
            };
            if let Err(e) = fetch_attachment_for_peer(
                Arc::clone(&session),
                Arc::clone(&writers),
                peer,
                offer_id,
                save_path,
                done,
            )
            .await
            {
                native_log::warn("attach", format!("fetch_attachment failed: {e}"));
            }
        }
        OutboundCmd::CancelAttachment { blob_id } => {
            let _ = crate::attach_v1::cancel_serve(&blob_id);
        }
        OutboundCmd::SendAck {
            recipient_public_key_hex,
            ref_id,
            ack_kind,
        } => {
            handle_send_ack_cmd(
                Arc::clone(&session),
                writers,
                recipient_public_key_hex,
                ref_id,
                ack_kind,
            )
            .await;
        }
        OutboundCmd::SendCallSignal {
            recipient_public_key_hex,
            call_id,
            signal_kind,
            payload,
            signal_id,
        } => {
            let Ok(peer) = session_peer_from_identity_wire(&recipient_public_key_hex) else {
                native_log::warn(
                    "call",
                    format!("call signal dropped — bad peer wire call_id={call_id}"),
                );
                return;
            };
            let recipient_hex = recipient_public_key_hex.clone();
            if let Err(e) = call_state::apply_outbound(&recipient_hex, &call_id, signal_kind) {
                native_log::warn("call", format!("outbound signal rejected: {e}"));
                return;
            }
            on_local_call_signal_sent(&call_id, signal_kind);
            session.enqueue_pending_call_signal(PendingCallSignal {
                call_id: call_id.clone(),
                signal_id,
                signal_kind,
                payload,
                peer: peer.clone(),
                recipient_public_key_hex,
                created_at_ms: chrono_now_ms(),
            });
            prune_closed_writers(&writers);
            let lan_up = writer_open_for_peer(&writers, &peer);
            native_log::info(
                "call",
                format!(
                    "call signal enqueue kind={} call_id={call_id} peer={} lan_writer={lan_up}",
                    signal_kind.wire_name(),
                    &peer[..peer.len().min(16)],
                ),
            );
            // `CallSignalSent` only after a real wire write (LAN flush or post-bridge ready).
            if lan_up {
                flush_pending_call_signals(
                    Arc::clone(&session),
                    Arc::clone(&writers),
                    vec![peer.clone()],
                    events_tx.clone(),
                )
                .await;
            }
            // Docs (GHALBOL_CONNECT_V1): WAN call bridge when no live LAN writer.
            let need_bridge = !lan_up
                && matches!(
                    signal_kind,
                    crate::call_sig_v1::CallSigKind::Invite
                        | crate::call_sig_v1::CallSigKind::Accept
                        | crate::call_sig_v1::CallSigKind::Hangup
                        | crate::call_sig_v1::CallSigKind::Reject
                        | crate::call_sig_v1::CallSigKind::VideoOn
                        | crate::call_sig_v1::CallSigKind::VideoOff
                        | crate::call_sig_v1::CallSigKind::KeyRequest
                );
            if need_bridge {
                if !crate::coord_runtime::coord_is_configured() {
                    native_log::warn(
                        "call",
                        format!(
                            "call signal queued but no LAN session and coord not configured call_id={call_id}"
                        ),
                    );
                } else {
                    let reg = Arc::clone(&worker.registry);
                    let sess = Arc::clone(&session);
                    let id = worker.identity.clone();
                    let ev = worker.events_tx.clone();
                    let pw = peer.clone();
                    let peer_hex = recipient_hex.clone();
                    let cid = call_id.clone();
                    let writers_flush = Arc::clone(&writers);
                    let events_flush = events_tx.clone();
                    native_log::info(
                        "connect",
                        format!("wan call path: public TCP dial then bridge call_id={cid}"),
                    );
                    tokio::spawn(async move {
                        // Call intent beats 404 backoff (TRANSPORT.md scale invariant).
                        crate::coord_runtime::clear_coord_lookup_backoff_for_pk(&peer_hex);

                        // Prefer public TCP when the peer registered dialable endpoints.
                        match crate::coord_runtime::lookup_dial_addrs_for_public_key_async(
                            &peer_hex,
                        )
                        .await
                        {
                            Ok(addrs) if !addrs.is_empty() => {
                                for addr in addrs.into_iter().take(3) {
                                    if writer_open_for_peer(&reg.writers, &pw) {
                                        break;
                                    }
                                    native_log::info(
                                        "connect",
                                        format!(
                                            "wan public TCP dial {}:{} peer={}",
                                            addr.host,
                                            addr.port,
                                            &pw[..pw.len().min(16)]
                                        ),
                                    );
                                    let reg_d = Arc::clone(&reg);
                                    let sess_d = Arc::clone(&sess);
                                    let id_d = id.clone();
                                    let ev_d = ev.clone();
                                    let pw_d = pw.clone();
                                    tokio::spawn(dial_peer_tcp(
                                        reg_d,
                                        sess_d,
                                        id_d,
                                        ev_d,
                                        pw_d,
                                        addr.host,
                                        addr.port,
                                    ));
                                    for _ in 0..30 {
                                        if writer_open_for_peer(&reg.writers, &pw) {
                                            break;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(100))
                                            .await;
                                    }
                                    if writer_open_for_peer(&reg.writers, &pw) {
                                        break;
                                    }
                                }
                            }
                            Ok(_) => {
                                native_log::debug(
                                    "connect",
                                    "coord lookup ok but no dialable public TCP; bridge next",
                                );
                            }
                            Err(e) => {
                                native_log::debug(
                                    "connect",
                                    format!("coord public TCP lookup: {e}; bridge next"),
                                );
                            }
                        }

                        if writer_open_for_peer(&reg.writers, &pw) {
                            flush_pending_call_signals(
                                Arc::clone(&sess),
                                writers_flush,
                                vec![pw.clone()],
                                events_flush,
                            )
                            .await;
                            native_log::info(
                                "connect",
                                format!("wan public TCP up for call_id={cid}; skip bridge"),
                            );
                            return;
                        }

                        native_log::info(
                            "bridge",
                            format!("wan call bridge requesting call_id={cid}"),
                        );
                        let peer_hex_b = peer_hex.clone();
                        let cid_b = cid.clone();
                        let bridge = match tokio::task::spawn_blocking(move || {
                            bridge_request_for_call(&peer_hex_b, &cid_b)
                        })
                        .await
                        {
                            Ok(Ok(b)) => b,
                            Ok(Err(e)) => {
                                native_log::warn(
                                    "bridge",
                                    format!("wan call bridge request failed: {e}"),
                                );
                                return;
                            }
                            Err(e) => {
                                native_log::warn(
                                    "bridge",
                                    format!("wan call bridge request task: {e}"),
                                );
                                return;
                            }
                        };
                        if let Err(e) = connect_bridge_session(
                            reg, sess, id, ev, pw, bridge, true, // caller = Noise initiator
                        )
                        .await
                        {
                            native_log::warn("bridge", format!("wan call bridge failed: {e}"));
                        }
                    });
                }
            }
        }
        OutboundCmd::CallMediaStart {
            call_id,
            peer_public_key_hex,
        } => {
            if let Err(e) = start_call_media_for_peer(
                Arc::clone(&session),
                writers,
                call_id.clone(),
                peer_public_key_hex,
                events_tx.clone(),
            )
            .await
            {
                native_log::warn("call_media", format!("start failed call_id={call_id}: {e}"));
            }
        }
        OutboundCmd::CallMediaStop { call_id } => {
            let stopped = session.call_media_stop(&call_id);
            if stopped {
                if let Some(pk) = crate::p2p::call_active::snapshot().map(|s| s.peer_public_key_hex)
                {
                    emit_call_media(events_tx, &call_id, &pk, "voice_stopped", None);
                }
            }
            #[cfg(target_os = "android")]
            crate::call_media::reset_voice_audio_mode_flag();
        }
        OutboundCmd::CallMediaSetMicMuted { call_id, muted } => {
            session.call_media_set_mic_muted(&call_id, muted);
        }
        OutboundCmd::CallMediaSetSpeaker {
            call_id,
            speaker_on,
        } => {
            #[cfg(not(target_os = "android"))]
            let _ = crate::call_media::set_speakerphone(speaker_on);
            #[cfg(target_os = "android")]
            let _ = crate::call_media::set_speakerphone(speaker_on);
            let _ = call_id;
        }
        OutboundCmd::CallVideoStart {
            call_id,
            peer_public_key_hex,
            camera_enabled,
        } => {
            if let Err(e) = start_call_video_for_peer(
                Arc::clone(&session),
                writers,
                call_id.clone(),
                peer_public_key_hex,
                camera_enabled,
                events_tx.clone(),
            )
            .await
            {
                native_log::warn("call_video", format!("start failed call_id={call_id}: {e}"));
            }
        }
        OutboundCmd::CallVideoStop { call_id } => {
            session.call_video_stop(&call_id);
            let peer_pk = crate::p2p::call_active::snapshot().map(|s| s.peer_public_key_hex);
            crate::p2p::call_active::on_video_stop(&call_id);
            if let Some(pk) = peer_pk {
                let _ = crate::p2p_runtime::p2p_call_signal(&serde_json::json!({
                    "recipient_public_key_hex": pk,
                    "call_id": call_id,
                    "signal": "video_off",
                    "payload": {},
                }));
                emit_call_media(events_tx, &call_id, &pk, "video_stopped", None);
            }
        }
        OutboundCmd::CallVideoSetCameraEnabled { call_id, enabled } => {
            session.call_video_set_camera_off(&call_id, !enabled);
            crate::p2p::call_active::set_camera_on(&call_id, enabled);
            if let Some(pk) = crate::p2p::call_active::snapshot().map(|s| s.peer_public_key_hex) {
                if enabled {
                    let _ = crate::p2p_runtime::p2p_call_signal(&serde_json::json!({
                        "recipient_public_key_hex": pk,
                        "call_id": call_id,
                        "signal": "video_on",
                        "payload": {
                            "w": crate::call_video::CAP_WIDTH,
                            "h": crate::call_video::CAP_HEIGHT,
                            "fps": 30,
                            "codec": "h264",
                        },
                    }));
                } else {
                    let _ = crate::p2p_runtime::p2p_call_signal(&serde_json::json!({
                        "recipient_public_key_hex": pk,
                        "call_id": call_id,
                        "signal": "video_off",
                        "payload": {},
                    }));
                }
            }
        }
    }
}
