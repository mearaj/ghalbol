#[cfg(test)]
mod tests {
    use super::super::config::{
        coord_http_degraded, coord_lookup_err_means_http_reachable, note_coord_transport_ok,
        parse_coord_urls, resolve_coord_insecure_tls,
    };
    use super::super::recovery::{
        clear_coord_lookup_backoff_for_pk, coord_invalidate_presence_on_network_change,
        coord_recovery_throttled, note_coord_recovery_attempt, relay_presence_reschedule_min_ms,
        sync_coord_lookup_peer_not_found,
    };
    use super::super::state::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn coord_http_degraded_false_after_recent_ok_even_unregistered() {
        COORD_REGISTERED.store(false, Ordering::Relaxed);
        COORD_CONSEC_FAILS.store(0, Ordering::Relaxed);
        note_coord_transport_ok();
        assert!(!coord_http_degraded());
    }

    #[test]
    fn coord_lookup_404_counts_as_http_reachable() {
        assert!(coord_lookup_err_means_http_reachable(
            "HTTP 404 peer_not_on_server"
        ));
        assert!(!coord_lookup_err_means_http_reachable(
            "error sending request for url"
        ));
    }

    #[test]
    fn https_coord_urls_force_secure_tls() {
        let https = vec!["https://coord.ghalbol.com".to_string()];
        assert!(!resolve_coord_insecure_tls(&https, true));
        assert!(!resolve_coord_insecure_tls(&https, false));
        let http_dev = vec!["http://127.0.0.1:8765".to_string()];
        assert!(resolve_coord_insecure_tls(&http_dev, true));
        assert!(!resolve_coord_insecure_tls(&http_dev, false));
    }

    #[test]
    fn coord_recovery_throttle_blocks_rapid_retries() {
        COORD_RECOVERY_LAST_MS.store(0, Ordering::Relaxed);
        let t0 = 1_000_000u64;
        assert!(!coord_recovery_throttled(t0));
        note_coord_recovery_attempt(t0);
        assert!(coord_recovery_throttled(t0 + 1_000));
        assert!(!coord_recovery_throttled(t0 + COORD_RECOVERY_MIN_MS));
    }

    #[test]
    fn relay_presence_reschedule_stricter_when_registered() {
        COORD_REGISTERED.store(true, Ordering::Relaxed);
        assert_eq!(
            relay_presence_reschedule_min_ms(),
            RELAY_PRESENCE_RESCHEDULE_REGISTERED_MS
        );
        COORD_REGISTERED.store(false, Ordering::Relaxed);
        assert_eq!(
            relay_presence_reschedule_min_ms(),
            RELAY_PRESENCE_RESCHEDULE_MIN_MS
        );
    }

    #[test]
    fn parse_coord_urls_splits_and_normalizes() {
        let urls = parse_coord_urls("https://a.example , http://b.example:8765\nhttps://c.example");
        assert!(urls.iter().any(|u| u.contains("a.example")));
        assert!(urls.iter().any(|u| u.contains("b.example")));
        assert!(urls.len() >= 2);
    }

    #[test]
    fn parse_coord_urls_empty_input() {
        assert!(parse_coord_urls("").is_empty());
        assert!(parse_coord_urls("   ").is_empty());
    }

    #[test]
    fn network_handover_invalidate_clears_lookup_backoff() {
        let secret =
            crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
                .expect("secret");
        let pk_bytes = crate::identity::public_key_from_secret(
            crate::identity::IdentityAlgorithm::Secp256k1,
            &secret,
        )
        .expect("pk");
        let pk = hex::encode(pk_bytes);
        sync_coord_lookup_peer_not_found(&pk, 2_000, 1_000_000);
        assert!(
            lookup_backoff_map()
                .lock()
                .map(|m| m.contains_key(&pk))
                .unwrap_or(false)
        );
        coord_invalidate_presence_on_network_change();
        assert!(
            lookup_backoff_map()
                .lock()
                .map(|m| !m.contains_key(&pk))
                .unwrap_or(false)
        );
        clear_coord_lookup_backoff_for_pk(&pk);
    }
}
