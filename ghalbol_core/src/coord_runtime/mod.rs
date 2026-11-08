//! Process-wide coordination server URL, registration, and heartbeat loop.

mod config;
mod lookup;
mod lookup_schedule;
mod presence;
mod recovery;
mod register;
mod state;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use config::{
    coord_base_urls, coord_http_degraded, coord_insecure_tls, coord_is_configured,
    coord_is_registered, coord_link_recently_ok, coord_note_relay_reservation,
    coord_set_base_url_json, coord_set_base_urls_json, coord_urls_from_json_value,
    fetch_all_ghalbol_relays, invalidate_cached_ghalbol_relay, parse_coord_urls,
    purge_legacy_relay_cache_files, set_coord_base_url, set_coord_base_urls,
    wan_discovery_via_coord_only,
};
pub use lookup::{
    coord_lookup_peer_json, lookup_bootstrap_multiaddrs, lookup_dial_addrs_for_public_key,
    lookup_dial_addrs_for_public_key_async, lookup_dial_multiaddrs_for_public_key,
    lookup_dial_multiaddrs_for_public_key_async,
};
pub use lookup_schedule::{
    note_peer_disconnect_urgent, note_peer_lookup_intent, peers_for_lookup_tick,
    LOOKUP_BACKGROUND_CAP,
};
pub use presence::{
    coord_note_relay_circuit_ready, ensure_coord_presence_polling, schedule_coord_presence_after_relay,
    schedule_register_presence_force, stop_coord_presence, try_restore_relay_presence_from_coord,
};
pub use recovery::{
    clear_coord_lookup_backoff_for_pk, coord_invalidate_presence_on_network_change,
    mark_coord_relay_hop_lost, note_remote_peer_circuit_stale, sync_coord_lookup_peer_not_found,
};
pub use register::{
    coord_register_now_json, coord_register_tick, on_listen_dm_addr,
    rebuild_coord_endpoints_from_listen, schedule_register_presence, sync_published_listen_addrs,
};
pub use state::{coord_note_relay_bootstrap_addrs, coord_set_local_peer_id};
