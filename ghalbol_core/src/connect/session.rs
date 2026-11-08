//! Slim session state for native connect (identity-wire keyed).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, RwLock};

use super::types::{
    DmPeer, PendingCallSignal, PendingDeliveryAck, PendingOutbound, PendingReadAck,
    SEEN_INBOUND_MAX, SessionPeer, session_peer_from_identity_wire,
};

/// Same KDF as [`SessionState`] local DM transport secret — peer pk is deterministic
/// from their identity wire (hello still exchanged for confirmation / future ephemerals).
pub(crate) fn dm_transport_sk_for_identity_wire(identity_wire: &str) -> x25519_dalek::StaticSecret {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ghalbol_connect_v1/dm_transport_sk");
    h.update(identity_wire.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    x25519_dalek::StaticSecret::from(digest)
}

pub(crate) fn dm_transport_pk_for_identity_wire(identity_wire: &str) -> [u8; 32] {
    let sk = dm_transport_sk_for_identity_wire(identity_wire);
    *x25519_dalek::PublicKey::from(&sk).as_bytes()
}

/// Cap in-memory P2P outbox so a long offline window cannot unbounded-grow RAM.
const MAX_PENDING_OUTBOX: usize = 2_048;
/// Cap queued call signals while the peer is offline for a long ring/retry window.
const MAX_PENDING_CALL_SIGNALS: usize = 64;
/// Bound in-memory ack dedupe sets (permanent id strings only).
const MAX_ACK_DEDUPE_SET: usize = 8_192;
/// One live call is normal; refuse adversarial register storms of unique call_ids.
const MAX_CALL_MEDIA_ENTRIES: usize = 8;

pub(crate) struct SessionState {
    pub(crate) identity: crate::DecryptedIdentity,
    peers: RwLock<HashMap<SessionPeer, DmPeer>>,
    connected: RwLock<HashSet<SessionPeer>>,
    stream_ready: RwLock<HashSet<SessionPeer>>,
    chat_ready_emitted: RwLock<HashSet<SessionPeer>>,
    identified_emitted: RwLock<HashSet<SessionPeer>>,
    outbox: RwLock<HashMap<String, PendingOutbound>>,
    outbound_ack_pending_poll: RwLock<HashSet<String>>,
    seen_inbound_ids: RwLock<HashMap<String, i64>>,
    pending_read_acks: RwLock<VecDeque<PendingReadAck>>,
    pending_delivery_acks: RwLock<VecDeque<PendingDeliveryAck>>,
    pending_call_signals: RwLock<VecDeque<PendingCallSignal>>,
    read_ack_confirmed: RwLock<HashSet<String>>,
    delivery_ack_sent: RwLock<HashSet<String>>,
    /// Serialize concurrent wire sends for the same inbound id (upkeep + in-room path).
    read_ack_wire_in_flight: RwLock<HashSet<String>>,
    /// Throttle failed delivery-ack upkeep retries (same interval as outbox resend).
    delivery_ack_upkeep_attempt_ms: RwLock<HashMap<String, i64>>,
    foreground_peer: RwLock<Option<SessionPeer>>,
    pub(crate) app_namespace: Option<String>,
    dm_transport_local_sk: x25519_dalek::StaticSecret,
    dm_peer_transport_pks: RwLock<HashMap<String, [u8; 32]>>,
    dm_transport_hello_sent: RwLock<HashSet<String>>,
    call_media: Mutex<HashMap<String, CallMediaEntry>>,
    call_video: Mutex<HashMap<String, CallVideoEntry>>,
    peers_on_local_lan: RwLock<HashSet<SessionPeer>>,
}

struct CallMediaEntry {
    peer: SessionPeer,
    controls: crate::call_media::MediaControls,
    wire_in_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

struct CallVideoEntry {
    peer: SessionPeer,
    controls: crate::call_video::VideoControls,
    wire_in_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl SessionState {
    pub fn new(
        identity: crate::DecryptedIdentity,
        dm_peers: &[DmPeer],
        app_namespace: Option<String>,
    ) -> Result<Self, String> {
        let sk = dm_transport_sk_for_identity_wire(&identity.identity_wire());
        let mut peers = HashMap::new();
        for p in dm_peers {
            if let Ok(w) = session_peer_from_identity_wire(&p.identity_wire) {
                peers.insert(w.clone(), DmPeer { identity_wire: w });
            }
        }
        Ok(Self {
            identity,
            peers: RwLock::new(peers),
            connected: RwLock::new(HashSet::new()),
            stream_ready: RwLock::new(HashSet::new()),
            chat_ready_emitted: RwLock::new(HashSet::new()),
            identified_emitted: RwLock::new(HashSet::new()),
            outbox: RwLock::new(HashMap::new()),
            outbound_ack_pending_poll: RwLock::new(HashSet::new()),
            seen_inbound_ids: RwLock::new(HashMap::new()),
            pending_read_acks: RwLock::new(VecDeque::new()),
            pending_delivery_acks: RwLock::new(VecDeque::new()),
            pending_call_signals: RwLock::new(VecDeque::new()),
            read_ack_confirmed: RwLock::new(HashSet::new()),
            delivery_ack_sent: RwLock::new(HashSet::new()),
            read_ack_wire_in_flight: RwLock::new(HashSet::new()),
            delivery_ack_upkeep_attempt_ms: RwLock::new(HashMap::new()),
            foreground_peer: RwLock::new(None),
            app_namespace,
            dm_transport_local_sk: sk,
            dm_peer_transport_pks: RwLock::new(HashMap::new()),
            dm_transport_hello_sent: RwLock::new(HashSet::new()),
            call_media: Mutex::new(HashMap::new()),
            call_video: Mutex::new(HashMap::new()),
            peers_on_local_lan: RwLock::new(HashSet::new()),
        })
    }

    pub fn register_dm_peer_key(&self, public_key_hex: &str) {
        if let Ok(w) = session_peer_from_identity_wire(public_key_hex) {
            if let Ok(mut g) = self.peers.write() {
                g.entry(w.clone()).or_insert(DmPeer { identity_wire: w });
            }
        }
    }

    pub fn resolve_send_peer(&self, pk: &str) -> Option<SessionPeer> {
        session_peer_from_identity_wire(pk).ok()
    }

    pub fn set_peer_connected(&self, peer: &SessionPeer, up: bool) {
        if let Ok(mut g) = self.connected.write() {
            if up {
                g.insert(peer.clone());
            } else {
                g.remove(peer);
            }
        }
    }

    pub fn set_stream_ready(&self, peer: &SessionPeer, ready: bool) {
        if let Ok(mut g) = self.stream_ready.write() {
            if ready {
                g.insert(peer.clone());
            } else {
                g.remove(peer);
            }
        }
    }

    pub fn set_peer_on_local_lan(&self, peer: &SessionPeer, on: bool) {
        if let Ok(mut g) = self.peers_on_local_lan.write() {
            if on {
                g.insert(peer.clone());
            } else {
                g.remove(peer);
            }
        }
    }

    pub fn set_foreground_peer(&self, peer: Option<SessionPeer>) {
        if let Ok(mut g) = self.foreground_peer.write() {
            *g = peer;
        }
    }

    pub fn foreground_peer(&self) -> Option<SessionPeer> {
        self.foreground_peer.read().ok().and_then(|g| g.clone())
    }

    pub fn list_dm_peer_wires(&self) -> Vec<SessionPeer> {
        self.peers
            .read()
            .ok()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn peers_with_pending_outbox(&self) -> Vec<SessionPeer> {
        self.outbox
            .read()
            .ok()
            .map(|g| {
                let mut out = Vec::new();
                for row in g.values() {
                    if !out.iter().any(|p: &SessionPeer| p == &row.peer) {
                        out.push(row.peer.clone());
                    }
                }
                out
            })
            .unwrap_or_default()
    }

    pub fn track_outbound(&self, row: PendingOutbound) {
        crate::coord_runtime::note_peer_lookup_intent(&row.peer);
        if let Ok(mut g) = self.outbox.write() {
            if !g.contains_key(&row.message_id) && g.len() >= MAX_PENDING_OUTBOX {
                // Drop oldest-by-created_at so a long offline window cannot unbounded-grow RAM.
                if let Some(oldest_id) = g
                    .values()
                    .min_by_key(|r| r.created_at_ms)
                    .map(|r| r.message_id.clone())
                {
                    g.remove(&oldest_id);
                }
            }
            g.insert(row.message_id.clone(), row);
        }
    }

    pub fn pending_outbox_for_peer(&self, peer: &SessionPeer) -> Vec<PendingOutbound> {
        self.outbox
            .read()
            .ok()
            .map(|g| g.values().filter(|r| &r.peer == peer).cloned().collect())
            .unwrap_or_default()
    }

    pub fn enqueue_pending_call_signal(&self, sig: PendingCallSignal) {
        if let Ok(mut g) = self.pending_call_signals.write() {
            // Bound memory if the peer is offline for a long ring/retry window.
            while g.len() >= MAX_PENDING_CALL_SIGNALS {
                g.pop_front();
            }
            g.push_back(sig);
        }
    }

    pub fn call_media_stop(&self, call_id: &str) -> bool {
        self.call_media
            .lock()
            .ok()
            .map(|mut g| g.remove(call_id).is_some())
            .unwrap_or(false)
    }

    pub fn call_video_stop(&self, call_id: &str) -> bool {
        self.call_video
            .lock()
            .ok()
            .map(|mut g| g.remove(call_id).is_some())
            .unwrap_or(false)
    }

    pub fn call_media_set_mic_muted(&self, call_id: &str, muted: bool) -> bool {
        self.call_media
            .lock()
            .ok()
            .and_then(|g| {
                g.get(call_id).map(|e| {
                    e.controls.set_mic_muted(muted);
                    true
                })
            })
            .unwrap_or(false)
    }

    pub fn call_video_set_camera_off(&self, call_id: &str, off: bool) -> bool {
        self.call_video
            .lock()
            .ok()
            .and_then(|g| {
                g.get(call_id).map(|e| {
                    e.controls.set_camera_off(off);
                    true
                })
            })
            .unwrap_or(false)
    }

    /// Apply peer `video_on` encode cap (min of both sides).
    pub fn call_video_set_remote_max_edge(&self, call_id: &str, max_edge: u32) -> bool {
        self.call_video
            .lock()
            .ok()
            .and_then(|g| {
                g.get(call_id).map(|e| {
                    e.controls.set_remote_max_edge(max_edge);
                    true
                })
            })
            .unwrap_or(false)
    }

    /// True when this call's camera is currently off (receive-only or muted).
    pub fn call_video_camera_is_off(&self, call_id: &str) -> bool {
        self.call_video
            .lock()
            .ok()
            .and_then(|g| g.get(call_id).map(|e| e.controls.camera_off.load(Ordering::Relaxed)))
            .unwrap_or(true)
    }

    /// Peer sent `key_request` — force the next local encoded frame to be an IDR.
    pub fn call_video_force_keyframe(&self, call_id: &str) -> bool {
        self.call_video
            .lock()
            .ok()
            .and_then(|g| {
                g.get(call_id).map(|e| {
                    e.controls.force_keyframe.store(true, Ordering::Relaxed);
                    true
                })
            })
            .unwrap_or(false)
    }

    pub fn call_media_active(&self, call_id: &str) -> bool {
        self.call_media
            .lock()
            .ok()
            .is_some_and(|g| g.contains_key(call_id))
    }

    pub fn dm_local_transport_sk(&self) -> &x25519_dalek::StaticSecret {
        &self.dm_transport_local_sk
    }

    pub fn store_peer_transport_pk(&self, peer_identity_wire: &str, pk: [u8; 32]) {
        if let Ok(wire) = session_peer_from_identity_wire(peer_identity_wire) {
            if let Ok(mut g) = self.dm_peer_transport_pks.write() {
                g.insert(wire, pk);
            }
        }
    }

    /// Peer X25519 transport public key for sealing.
    ///
    /// Prefers a key learned from `TransportKemHello`. Falls back to the same
    /// identity-wire KDF used for the local transport secret — hello can be
    /// one-sided on a fresh bridge (initiator never sees responder hello) and
    /// call invites must not sit deferred forever.
    pub fn peer_transport_pk(&self, peer_identity_wire: &str) -> Option<[u8; 32]> {
        let wire = session_peer_from_identity_wire(peer_identity_wire).ok()?;
        if let Some(pk) = self
            .dm_peer_transport_pks
            .read()
            .ok()
            .and_then(|g| g.get(&wire).copied())
        {
            return Some(pk);
        }
        Some(dm_transport_pk_for_identity_wire(&wire))
    }

    pub(crate) fn clear_transport_kem_for_peer(&self, peer: &SessionPeer) {
        if let Ok(mut g) = self.dm_peer_transport_pks.write() {
            g.remove(peer);
        }
        if let Ok(mut g) = self.dm_transport_hello_sent.write() {
            g.remove(peer);
        }
        super::transport_kem::clear_peer_transport_pk(peer);
    }

    pub fn mark_seen_inbound(&self, id: &str, now_ms: i64) -> bool {
        if let Ok(mut g) = self.seen_inbound_ids.write() {
            if g.contains_key(id) {
                return false;
            }
            g.insert(id.to_string(), now_ms);
            if g.len() > SEEN_INBOUND_MAX {
                if let Some((old, _)) = g
                    .iter()
                    .min_by_key(|(_, t)| *t)
                    .map(|(k, v)| (k.clone(), *v))
                {
                    g.remove(&old);
                }
            }
            return true;
        }
        false
    }

    pub fn emit_chat_ready_once(&self, peer: &SessionPeer) -> bool {
        self.chat_ready_emitted
            .write()
            .ok()
            .is_some_and(|mut g| g.insert(peer.clone()))
    }

    pub fn emit_identified_once(&self, peer: &SessionPeer) -> bool {
        self.identified_emitted
            .write()
            .ok()
            .is_some_and(|mut g| g.insert(peer.clone()))
    }

    pub(crate) fn transport_hello_already_sent(&self, peer: &SessionPeer) -> bool {
        self.dm_transport_hello_sent
            .read()
            .ok()
            .is_some_and(|g| g.contains(peer))
    }

    pub(crate) fn mark_transport_hello_sent(&self, peer: &SessionPeer) {
        if let Ok(mut g) = self.dm_transport_hello_sent.write() {
            g.insert(peer.clone());
        }
    }

    pub(crate) fn finalize_outbound_ack(&self, message_id: &str) {
        let id = message_id.trim();
        if id.is_empty() {
            return;
        }
        if let Ok(mut g) = self.outbox.write() {
            g.remove(id);
        }
        if let Ok(mut g) = self.outbound_ack_pending_poll.write() {
            g.insert(id.to_string());
        }
    }

    pub(crate) fn mark_outbox_sent(&self, message_id: &str, now_ms: i64) -> bool {
        let Ok(mut g) = self.outbox.write() else {
            return false;
        };
        if let Some(p) = g.get_mut(message_id) {
            let first = !p.on_wire;
            p.on_wire = true;
            if first {
                p.first_on_wire_ms = now_ms;
            }
            p.last_send_ms = now_ms;
            return first;
        }
        false
    }

    pub(crate) fn mark_outbox_send_failed(&self, message_id: &str, now_ms: i64) {
        if let Ok(mut g) = self.outbox.write() {
            if let Some(p) = g.get_mut(message_id) {
                p.on_wire = false;
                p.first_on_wire_ms = 0;
                p.last_send_ms = now_ms;
            }
        }
    }

    pub(crate) fn outbox_due_for_resend(&self, now_ms: i64) -> Vec<PendingOutbound> {
        self.outbox
            .read()
            .ok()
            .map(|g| {
                g.values()
                    .filter(|p| {
                        !p.on_wire
                            || now_ms.saturating_sub(p.last_send_ms)
                                >= super::types::OUTBOX_RESEND_INTERVAL_MS
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn is_delivery_ack_sent(&self, inbound_id: &str) -> bool {
        self.delivery_ack_sent
            .read()
            .ok()
            .is_some_and(|g| g.contains(inbound_id))
    }

    pub(crate) fn mark_delivery_ack_sent(&self, inbound_id: &str) {
        if let Ok(mut g) = self.delivery_ack_sent.write() {
            if g.len() >= MAX_ACK_DEDUPE_SET && !g.contains(inbound_id) {
                if let Some(old) = g.iter().next().cloned() {
                    g.remove(&old);
                }
            }
            g.insert(inbound_id.to_string());
        }
        self.clear_delivery_ack_upkeep_attempt(inbound_id);
    }

    pub(crate) fn clear_delivery_ack_sent(&self, inbound_id: &str) {
        if let Ok(mut g) = self.delivery_ack_sent.write() {
            g.remove(inbound_id);
        }
    }

    pub(crate) fn enqueue_delivery_ack(
        &self,
        peer: &SessionPeer,
        inbound_id: &str,
        recipient_signing: &str,
        received_at_ms: i64,
    ) {
        let id = inbound_id.trim().to_string();
        if id.is_empty() {
            return;
        }
        if let Ok(mut q) = self.pending_delivery_acks.write() {
            if q.iter().any(|p| p.inbound_id == id) {
                return;
            }
            if q.len() >= 512 {
                q.pop_front();
            }
            q.push_back(PendingDeliveryAck {
                peer: peer.clone(),
                inbound_id: id,
                recipient_public_key_hex: recipient_signing.trim().to_string(),
                received_at_ms,
            });
        }
    }

    pub(crate) fn dequeue_delivery_ack(&self, inbound_id: &str) {
        if let Ok(mut q) = self.pending_delivery_acks.write() {
            q.retain(|p| p.inbound_id != inbound_id);
        }
    }

    pub(crate) fn delivery_acks_due_for_upkeep(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Vec<PendingDeliveryAck> {
        let attempts = self
            .delivery_ack_upkeep_attempt_ms
            .read()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default();
        self.pending_delivery_acks
            .read()
            .ok()
            .map(|q| {
                q.iter()
                    .filter(|p| {
                        attempts
                            .get(&p.inbound_id)
                            .map(|t| {
                                now_ms.saturating_sub(*t)
                                    >= super::types::OUTBOX_RESEND_INTERVAL_MS
                            })
                            .unwrap_or(true)
                    })
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn note_delivery_ack_upkeep_attempt(&self, inbound_id: &str, now_ms: i64) {
        let id = inbound_id.trim();
        if id.is_empty() {
            return;
        }
        if let Ok(mut g) = self.delivery_ack_upkeep_attempt_ms.write() {
            if g.len() >= MAX_ACK_DEDUPE_SET && !g.contains_key(id) {
                if let Some(old) = g.keys().next().cloned() {
                    g.remove(&old);
                }
            }
            g.insert(id.to_string(), now_ms);
        }
    }

    pub(crate) fn clear_delivery_ack_upkeep_attempt(&self, inbound_id: &str) {
        let id = inbound_id.trim();
        if id.is_empty() {
            return;
        }
        if let Ok(mut g) = self.delivery_ack_upkeep_attempt_ms.write() {
            g.remove(id);
        }
    }

    pub(crate) fn has_pending_read_ack(&self, inbound_id: &str) -> bool {
        self.pending_read_acks
            .read()
            .ok()
            .is_some_and(|q| q.iter().any(|p| p.inbound_id == inbound_id))
    }

    pub(crate) fn is_read_ack_confirmed(&self, inbound_id: &str) -> bool {
        self.read_ack_confirmed
            .read()
            .ok()
            .is_some_and(|g| g.contains(inbound_id))
    }

    pub(crate) fn mark_read_ack_confirmed(&self, inbound_id: &str) {
        if let Ok(mut g) = self.read_ack_confirmed.write() {
            if g.len() >= MAX_ACK_DEDUPE_SET && !g.contains(inbound_id) {
                if let Some(old) = g.iter().next().cloned() {
                    g.remove(&old);
                }
            }
            g.insert(inbound_id.to_string());
        }
        self.release_read_ack_wire_claim(inbound_id);
        if let Ok(mut q) = self.pending_read_acks.write() {
            q.retain(|p| p.inbound_id != inbound_id);
        }
    }

    pub(crate) fn try_claim_read_ack_wire_send(
        &self,
        peer: &SessionPeer,
        inbound_id: &str,
    ) -> bool {
        let id = inbound_id.trim();
        if id.is_empty() {
            return false;
        }
        if self.is_read_ack_confirmed(id) {
            return false;
        }
        if let Ok(g) = self.read_ack_wire_in_flight.read() {
            if g.contains(id) {
                return false;
            }
        }
        let Ok(mut inflight) = self.read_ack_wire_in_flight.write() else {
            return false;
        };
        if inflight.len() >= MAX_ACK_DEDUPE_SET && !inflight.contains(id) {
            if let Some(old) = inflight.iter().next().cloned() {
                inflight.remove(&old);
            }
        }
        if !inflight.insert(id.to_string()) {
            return false;
        }
        let Ok(mut q) = self.pending_read_acks.write() else {
            inflight.remove(id);
            return false;
        };
        if !q.iter().any(|p| p.inbound_id == id) {
            if q.len() >= 512 {
                q.pop_front();
            }
            q.push_back(PendingReadAck {
                peer: peer.clone(),
                inbound_id: id.to_string(),
                recipient_public_key_hex: peer.clone(),
                last_send_ms: 0,
            });
        }
        true
    }

    pub(crate) fn release_read_ack_wire_claim(&self, inbound_id: &str) {
        let id = inbound_id.trim();
        if id.is_empty() {
            return;
        }
        if let Ok(mut g) = self.read_ack_wire_in_flight.write() {
            g.remove(id);
        }
    }

    pub(crate) fn mark_read_ack_wire_sent(&self, inbound_id: &str) {
        self.release_read_ack_wire_claim(inbound_id);
        if let Ok(mut q) = self.pending_read_acks.write() {
            let now = chrono_now_ms();
            for item in q.iter_mut() {
                if item.inbound_id == inbound_id {
                    item.last_send_ms = now;
                }
            }
        }
    }

    pub(crate) fn enqueue_read_ack_backlog(&self, peer: &SessionPeer, inbound_id: &str) -> bool {
        let id = inbound_id.trim().to_string();
        if id.is_empty() {
            return false;
        }
        if let Ok(mut s) = self.read_ack_confirmed.write() {
            s.remove(&id);
        }
        let Ok(mut q) = self.pending_read_acks.write() else {
            return false;
        };
        if q.iter().any(|p| p.inbound_id == id) {
            return false;
        }
        if q.len() >= 512 {
            q.pop_front();
        }
        q.push_back(PendingReadAck {
            peer: peer.clone(),
            inbound_id: id,
            recipient_public_key_hex: peer.clone(),
            last_send_ms: 0,
        });
        true
    }

    pub(crate) fn has_pending_read_acks_for(&self, peer: &SessionPeer) -> bool {
        self.pending_read_acks
            .read()
            .ok()
            .is_some_and(|q| q.iter().any(|p| &p.peer == peer))
    }

    pub(crate) fn pending_read_ack_len(&self) -> usize {
        self.pending_read_acks
            .read()
            .ok()
            .map(|q| q.len())
            .unwrap_or(0)
    }

    pub(crate) fn read_acks_due_for_upkeep(&self, now_ms: i64, limit: usize) -> Vec<PendingReadAck> {
        self.pending_read_acks
            .read()
            .ok()
            .map(|q| {
                q.iter()
                    .filter(|p| {
                        p.last_send_ms == 0
                            || now_ms.saturating_sub(p.last_send_ms)
                                >= super::types::OUTBOX_RESEND_INTERVAL_MS
                    })
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn drain_pending_call_signals(&self, limit: usize) -> Vec<PendingCallSignal> {
        self.pending_call_signals
            .write()
            .ok()
            .map(|mut q| {
                let n = limit.min(q.len());
                q.drain(0..n).collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn requeue_pending_call_signal_front(&self, item: PendingCallSignal) {
        if let Ok(mut q) = self.pending_call_signals.write() {
            while q.len() >= MAX_PENDING_CALL_SIGNALS {
                q.pop_back();
            }
            q.push_front(item);
        }
    }

    pub(crate) fn call_media_register(
        &self,
        call_id: String,
        peer: SessionPeer,
        controls: crate::call_media::MediaControls,
        wire_in_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        if let Ok(mut m) = self.call_media.lock() {
            if !m.contains_key(&call_id) && m.len() >= MAX_CALL_MEDIA_ENTRIES {
                // Evict an arbitrary stale entry so a real call can still register.
                if let Some(old) = m.keys().next().cloned() {
                    m.remove(&old);
                }
            }
            m.insert(
                call_id,
                CallMediaEntry {
                    peer,
                    controls,
                    wire_in_tx,
                },
            );
        }
    }

    pub(crate) fn call_media_wire_in_any(
        &self,
        peer: &SessionPeer,
    ) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        self.call_media.lock().ok().and_then(|g| {
            g.values()
                .find(|e| &e.peer == peer)
                .map(|e| e.wire_in_tx.clone())
        })
    }

    pub(crate) fn call_video_register(
        &self,
        call_id: String,
        peer: SessionPeer,
        controls: crate::call_video::VideoControls,
        wire_in_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) {
        if let Ok(mut m) = self.call_video.lock() {
            if !m.contains_key(&call_id) && m.len() >= MAX_CALL_MEDIA_ENTRIES {
                if let Some(old) = m.keys().next().cloned() {
                    m.remove(&old);
                }
            }
            m.insert(
                call_id,
                CallVideoEntry {
                    peer,
                    controls,
                    wire_in_tx,
                },
            );
        }
    }

    pub(crate) fn call_video_active(&self, call_id: &str) -> bool {
        self.call_video
            .lock()
            .ok()
            .is_some_and(|g| g.contains_key(call_id))
    }

    pub(crate) fn call_video_wire_in_any(
        &self,
        peer: &SessionPeer,
    ) -> Option<tokio::sync::mpsc::Sender<Vec<u8>>> {
        self.call_video.lock().ok().and_then(|g| {
            g.values()
                .find(|e| &e.peer == peer)
                .map(|e| e.wire_in_tx.clone())
        })
    }
}

pub(crate) fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::call_sig_v1::CallSigKind;
    use crate::create_keystore_v1;
    use serde_json::json;

    fn test_session() -> SessionState {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        SessionState::new(id, &[], None).unwrap()
    }

    fn outbound(id: &str, created_at_ms: i64) -> PendingOutbound {
        PendingOutbound {
            message_id: id.to_string(),
            peer: "aa".repeat(32),
            recipient_public_key_hex: "aa".repeat(32),
            text: "x".into(),
            msg_kind: "text".into(),
            attachment_offer: None,
            voice_opus: None,
            duration_ms: None,
            created_at_ms,
            last_send_ms: 0,
            first_on_wire_ms: 0,
            on_wire: false,
        }
    }

    #[test]
    fn outbox_evicts_oldest_when_full() {
        let s = test_session();
        for i in 0..MAX_PENDING_OUTBOX {
            s.track_outbound(outbound(&format!("m{i}"), i as i64));
        }
        assert_eq!(s.outbox.read().unwrap().len(), MAX_PENDING_OUTBOX);
        s.track_outbound(outbound("newest", 9_999_999));
        let g = s.outbox.read().unwrap();
        assert_eq!(g.len(), MAX_PENDING_OUTBOX);
        assert!(!g.contains_key("m0"));
        assert!(g.contains_key("newest"));
    }

    #[test]
    fn pending_call_signals_drop_oldest_when_full() {
        let s = test_session();
        for i in 0..(MAX_PENDING_CALL_SIGNALS + 3) {
            s.enqueue_pending_call_signal(PendingCallSignal {
                call_id: format!("c{i}"),
                signal_id: format!("s{i}"),
                signal_kind: CallSigKind::Invite,
                payload: json!({}),
                peer: "bb".repeat(32),
                recipient_public_key_hex: "bb".repeat(32),
                created_at_ms: i as i64,
            });
        }
        let g = s.pending_call_signals.read().unwrap();
        assert_eq!(g.len(), MAX_PENDING_CALL_SIGNALS);
        assert_eq!(g.front().unwrap().call_id, "c3");
    }

    #[test]
    fn read_acks_due_respects_resend_interval() {
        let s = test_session();
        let peer = "cc".repeat(32);
        assert!(s.enqueue_read_ack_backlog(&peer, "msg-1"));
        // Pin last_send_ms so the due check is not racing the wall clock.
        if let Ok(mut q) = s.pending_read_acks.write() {
            q[0].last_send_ms = 1_000;
        }
        assert!(s.read_acks_due_for_upkeep(1_000, 8).is_empty());
        assert_eq!(
            s.read_acks_due_for_upkeep(
                1_000 + crate::connect::types::OUTBOX_RESEND_INTERVAL_MS,
                8
            )
            .len(),
            1
        );
    }

    #[test]
    fn read_ack_wire_claim_blocks_concurrent_send() {
        let s = test_session();
        let peer = "dd".repeat(32);
        assert!(s.try_claim_read_ack_wire_send(&peer, "msg-x"));
        assert!(!s.try_claim_read_ack_wire_send(&peer, "msg-x"));
        s.release_read_ack_wire_claim("msg-x");
        assert!(s.try_claim_read_ack_wire_send(&peer, "msg-x"));
        s.mark_read_ack_wire_sent("msg-x");
        assert!(s.try_claim_read_ack_wire_send(&peer, "msg-x"));
    }

    #[test]
    fn delivery_ack_upkeep_respects_resend_interval() {
        let s = test_session();
        let peer = "ee".repeat(32);
        s.enqueue_delivery_ack(&peer, "in-1", &peer, 100);
        let t0 = 50_000i64;
        assert_eq!(s.delivery_acks_due_for_upkeep(t0, 8).len(), 1);
        s.note_delivery_ack_upkeep_attempt("in-1", t0);
        assert!(s.delivery_acks_due_for_upkeep(t0, 8).is_empty());
        assert_eq!(
            s.delivery_acks_due_for_upkeep(
                t0 + crate::connect::types::OUTBOX_RESEND_INTERVAL_MS,
                8,
            )
            .len(),
            1
        );
    }

    #[test]
    fn seen_inbound_ids_bounded_under_flood() {
        let s = test_session();
        for i in 0..(SEEN_INBOUND_MAX + 500) {
            s.mark_seen_inbound(&format!("id-{i}"), i as i64);
        }
        assert!(s.seen_inbound_ids.read().unwrap().len() <= SEEN_INBOUND_MAX);
    }

    #[test]
    fn delivery_ack_upkeep_attempt_map_bounded() {
        let s = test_session();
        for i in 0..(MAX_ACK_DEDUPE_SET + 200) {
            s.note_delivery_ack_upkeep_attempt(&format!("up-{i}"), i as i64);
        }
        assert!(s
            .delivery_ack_upkeep_attempt_ms
            .read()
            .unwrap()
            .len()
            <= MAX_ACK_DEDUPE_SET);
    }

    #[test]
    fn requeue_call_signal_respects_cap() {
        let s = test_session();
        for i in 0..MAX_PENDING_CALL_SIGNALS {
            s.enqueue_pending_call_signal(PendingCallSignal {
                call_id: format!("c{i}"),
                signal_id: format!("s{i}"),
                signal_kind: CallSigKind::Invite,
                payload: json!({}),
                peer: "bb".repeat(32),
                recipient_public_key_hex: "bb".repeat(32),
                created_at_ms: i as i64,
            });
        }
        s.requeue_pending_call_signal_front(PendingCallSignal {
            call_id: "retry".into(),
            signal_id: "rs".into(),
            signal_kind: CallSigKind::Hangup,
            payload: json!({}),
            peer: "bb".repeat(32),
            recipient_public_key_hex: "bb".repeat(32),
            created_at_ms: 99,
        });
        let g = s.pending_call_signals.read().unwrap();
        assert_eq!(g.len(), MAX_PENDING_CALL_SIGNALS);
        assert_eq!(g.front().unwrap().call_id, "retry");
    }
}
