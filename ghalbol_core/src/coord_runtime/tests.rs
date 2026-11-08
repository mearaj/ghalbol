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
    use super::super::presence::peer_record_has_coord_presence;
    use super::super::register::{
        drain_coord_register_pending, filter_coord_record_tcp_for_dial, should_throttle_register,
    };
    use super::super::state::{insert_lookup_backoff, MAX_LOOKUP_BACKOFF_ENTRIES};
    use crate::coord::CoordPeerRecord;
    use crate::coord::CoordEndpoint;
    use super::super::state::{lookup_backoff_map, CoordLookupBackoff, *};
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
    fn parse_coord_urls_drops_non_http_and_oversized() {
        assert!(parse_coord_urls("ftp://evil.example").is_empty());
        assert!(parse_coord_urls("not-a-url").is_empty());
        let huge = format!("https://x/{}", "a".repeat(3_000));
        assert!(parse_coord_urls(&huge).is_empty());
        assert_eq!(
            parse_coord_urls("https://ok.example,ftp://no").len(),
            1
        );
    }

    #[test]
    fn filter_dial_tcp_drops_bootstrap_and_link_local() {
        crate::coord_runtime::coord_note_relay_bootstrap_addrs(&["203.0.113.10:4001".to_string()]);
        let eps = vec![
            CoordEndpoint {
                scheme: "tcp".into(),
                host: "203.0.113.10".into(),
                port: 4001,
            },
            CoordEndpoint {
                scheme: "tcp".into(),
                host: "169.254.1.1".into(),
                port: 8766,
            },
            CoordEndpoint {
                scheme: "tcp".into(),
                host: "203.0.113.50".into(),
                port: 8766,
            },
        ];
        let out = filter_coord_record_tcp_for_dial(&eps);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].host, "203.0.113.50");
    }

    #[test]
    fn filter_dial_tcp_caps_count_and_rejects_huge_host() {
        let mut eps: Vec<CoordEndpoint> = (0..20)
            .map(|i| CoordEndpoint {
                scheme: "tcp".into(),
                host: format!("203.0.113.{}", i + 1),
                port: 8766,
            })
            .collect();
        eps.push(CoordEndpoint {
            scheme: "tcp".into(),
            host: "x".repeat(300),
            port: 8766,
        });
        let out = filter_coord_record_tcp_for_dial(&eps);
        assert!(out.len() <= 8);
        assert!(out.iter().all(|e| e.host.len() <= 253));
    }

    #[test]
    fn network_handover_clears_registered_on() {
        if let Ok(mut r) = coord_globals().registered_on.lock() {
            r.insert("https://coord.example.test".into());
        }
        coord_invalidate_presence_on_network_change();
        assert!(
            coord_globals()
                .registered_on
                .lock()
                .map(|r| r.is_empty())
                .unwrap_or(false)
        );
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

    #[test]
    fn pending_register_drain_requeues_while_worker_busy() {
        COORD_REG_PENDING.store(true, Ordering::Relaxed);
        COORD_REG_WORKER_BUSY.store(true, Ordering::Relaxed);
        assert!(drain_coord_register_pending());
        assert!(
            COORD_REG_PENDING.load(Ordering::Relaxed),
            "drain must call force register; busy worker re-queues pending"
        );
        COORD_REG_WORKER_BUSY.store(false, Ordering::Relaxed);
        COORD_REG_PENDING.store(false, Ordering::Relaxed);
    }

    #[test]
    fn sync_lookup_backoff_caps_map_growth() {
        let Ok(mut m) = lookup_backoff_map().lock() else {
            return;
        };
        m.clear();
        const TEST_CAP: usize = 32;
        for i in 0..TEST_CAP {
            insert_lookup_backoff(
                &mut m,
                format!("fill-{i:04x}"),
                CoordLookupBackoff {
                    next_allowed_ms: 9_000_000 + i as u64,
                    step_ms: 800,
                },
            );
        }
        for i in TEST_CAP..MAX_LOOKUP_BACKOFF_ENTRIES {
            m.insert(
                format!("fill-{i:04x}"),
                CoordLookupBackoff {
                    next_allowed_ms: 9_000_000 + i as u64,
                    step_ms: 800,
                },
            );
        }
        assert_eq!(m.len(), MAX_LOOKUP_BACKOFF_ENTRIES);
        drop(m);
        let secret =
            crate::identity::generate_secret(crate::identity::IdentityAlgorithm::Secp256k1)
                .expect("secret");
        let new_pk = hex::encode(
            crate::identity::public_key_from_secret(
                crate::identity::IdentityAlgorithm::Secp256k1,
                &secret,
            )
            .expect("pk"),
        );
        sync_coord_lookup_peer_not_found(&new_pk, 800, 1_000_000);
        let Ok(mut m2) = lookup_backoff_map().lock() else {
            return;
        };
        assert_eq!(m2.len(), MAX_LOOKUP_BACKOFF_ENTRIES);
        assert!(m2.contains_key(&new_pk));
        assert!(!m2.contains_key("fill-0000"));
        m2.clear();
    }

    #[test]
    fn coord_presence_rejects_link_local_tcp_only() {
        let record = CoordPeerRecord {
            public_key_hex: "ab".into(),
            endpoints: vec![CoordEndpoint {
                scheme: "tcp".into(),
                host: "169.254.1.2".into(),
                port: 8765,
            }],
            transport_capabilities: vec![],
            ipv6: None,
            ipv4: None,
            last_heartbeat_unix_ms: 0,
        };
        assert!(!peer_record_has_coord_presence(&record));
    }

    #[test]
    fn register_throttle_respects_registered_vs_retry_gaps() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        COORD_LAST_REG_ATTEMPT_MS.store(now, Ordering::Relaxed);
        COORD_REGISTERED.store(true, Ordering::Relaxed);
        assert!(should_throttle_register());
        COORD_REGISTERED.store(false, Ordering::Relaxed);
        // Unregistered uses the shorter retry gap — still throttled immediately after attempt.
        assert!(should_throttle_register());
        COORD_LAST_REG_ATTEMPT_MS.store(now.saturating_sub(MIN_REGISTER_RETRY_MS), Ordering::Relaxed);
        assert!(!should_throttle_register());
        COORD_REGISTERED.store(true, Ordering::Relaxed);
        COORD_LAST_REG_ATTEMPT_MS.store(
            now.saturating_sub(MIN_REGISTER_INTERVAL_MS),
            Ordering::Relaxed,
        );
        assert!(!should_throttle_register());
    }
}
