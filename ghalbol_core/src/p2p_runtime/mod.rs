//! In-process native DM worker. The Makepad app calls this through `ghalbol_core::host`.

mod calls;
mod helpers;
mod lifecycle;
mod poll;
mod send;
mod ui_session;

pub use calls::{
    p2p_call_media, p2p_call_signal, p2p_call_status, p2p_call_video, p2p_force_end_active_call,
};
pub use lifecycle::{p2p_register_dm_peer, p2p_start, p2p_stop};
pub use poll::{enqueue_delivery_gossip_event, p2p_poll_event, p2p_transcript_load_merged};
pub use send::{
    p2p_attachment_fetch, p2p_send_attachment, p2p_send_text_dm, p2p_send_voice_dm,
};
pub use ui_session::{
    p2p_get_availability_status, p2p_set_availability_status, p2p_sync_ui_session,
};
