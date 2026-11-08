//! Scale-invariant coord peer lookup: urgent → priority → capped background (TRANSPORT.md).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::recovery::clear_coord_lookup_backoff_for_pk;

/// Background sweep cap per upkeep tick — urgent/priority are uncapped.
pub const LOOKUP_BACKGROUND_CAP: usize = 4;
/// Recent disconnect stays urgent this long.
const URGENT_WINDOW_MS: i64 = 60_000;
/// Bound urgent map under adversarial disconnect floods.
const MAX_URGENT_ENTRIES: usize = 4_096;
/// Background rotation queue — same order of magnitude as contact roster caps.
const MAX_BACKGROUND_LOOKUP_QUEUE: usize = 4_096;

fn trim_urgent_map(g: &mut HashMap<String, i64>, now: i64) {
    g.retain(|_, at| now.saturating_sub(*at) <= URGENT_WINDOW_MS);
    while g.len() > MAX_URGENT_ENTRIES {
        let Some(oldest) = g.iter().min_by_key(|(_, at)| *at).map(|(k, _)| k.clone()) else {
            break;
        };
        g.remove(&oldest);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn urgent_map() -> &'static Mutex<HashMap<String, i64>> {
    static M: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn background_cursor() -> &'static Mutex<VecDeque<String>> {
    static Q: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Call when a native session drops — peer becomes urgent for the next minute.
pub fn note_peer_disconnect_urgent(public_key_hex: &str) {
    let Ok(pk) = crate::public_key_util::normalize_contact_identity_wire(public_key_hex) else {
        return;
    };
    clear_coord_lookup_backoff_for_pk(&pk);
    let now = now_ms();
    if let Ok(mut g) = urgent_map().lock() {
        g.insert(pk, now);
        trim_urgent_map(&mut g, now);
    }
}

/// Intent beats backoff: open chat / queued outbound / call.
pub fn note_peer_lookup_intent(public_key_hex: &str) {
    let Ok(pk) = crate::public_key_util::normalize_contact_identity_wire(public_key_hex) else {
        return;
    };
    clear_coord_lookup_backoff_for_pk(&pk);
}

fn take_urgent(now: i64) -> Vec<String> {
    let Ok(mut g) = urgent_map().lock() else {
        return Vec::new();
    };
    g.retain(|_, at| now.saturating_sub(*at) <= URGENT_WINDOW_MS);
    g.keys().cloned().collect()
}

/// Build ordered lookup list for this tick: urgent, then priority, then ≤[`LOOKUP_BACKGROUND_CAP`].
pub fn peers_for_lookup_tick(
    urgent_extra: &[String],
    priority: &[String],
    all_contacts: &[String],
    already_connected: &[String],
) -> Vec<String> {
    let now = now_ms();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let connected: std::collections::HashSet<String> = already_connected
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .collect();

    let push = |pk: &str, out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>| {
        let t = pk.trim();
        if t.is_empty() {
            return;
        }
        let key = t.to_ascii_lowercase();
        if connected.contains(&key) || !seen.insert(key) {
            return;
        }
        out.push(t.to_string());
    };

    for pk in take_urgent(now) {
        push(&pk, &mut out, &mut seen);
    }
    for pk in urgent_extra {
        push(pk, &mut out, &mut seen);
    }
    // Priority uncapped.
    for pk in priority {
        push(pk, &mut out, &mut seen);
    }

    // Background: LRU-ish rotation over remaining contacts.
    let mut candidates: Vec<String> = all_contacts
        .iter()
        .filter(|p| {
            let k = p.trim().to_ascii_lowercase();
            !k.is_empty() && !connected.contains(&k) && !seen.contains(&k)
        })
        .cloned()
        .collect();
    candidates.sort();
    if let Ok(mut q) = background_cursor().lock() {
        // Rotate: prefer those not recently swept.
        if q.is_empty() {
            for c in &candidates {
                q.push_back(c.clone());
            }
        } else {
            for c in &candidates {
                if !q.iter().any(|x| x.eq_ignore_ascii_case(c)) {
                    q.push_back(c.clone());
                }
            }
            q.retain(|x| {
                candidates
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(x))
            });
        }
        while q.len() > MAX_BACKGROUND_LOOKUP_QUEUE {
            q.pop_front();
        }
        // Bound scans to queue length so skipped (priority/urgent/connected) peers do not
        // drain the rotation without filling the background cap — starvation on large rosters.
        let queue_len = q.len();
        let mut bg = 0usize;
        let mut scans = 0usize;
        while bg < LOOKUP_BACKGROUND_CAP && scans < queue_len {
            let Some(pk) = q.pop_front() else {
                break;
            };
            scans += 1;
            let key = pk.to_ascii_lowercase();
            if seen.contains(&key) || connected.contains(&key) {
                q.push_back(pk);
                continue;
            }
            push(&pk, &mut out, &mut seen);
            q.push_back(pk);
            bg += 1;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_lookup_schedule_globals() {
        if let Ok(mut g) = urgent_map().lock() {
            g.clear();
        }
        if let Ok(mut q) = background_cursor().lock() {
            q.clear();
        }
    }

    #[test]
    fn background_fills_cap_when_queue_front_matches_priority() {
        reset_lookup_schedule_globals();
        let all: Vec<String> = (0..12).map(|i| format!("{:064x}", i + 10)).collect();
        let priority = vec![all[0].clone(), all[1].clone()];
        let list = peers_for_lookup_tick(&[], &priority, &all, &[]);
        assert_eq!(list[0], all[0]);
        assert_eq!(list[1], all[1]);
        assert_eq!(list.len(), 2 + LOOKUP_BACKGROUND_CAP);
        for p in list.iter().skip(2) {
            assert_ne!(p, &all[0]);
            assert_ne!(p, &all[1]);
        }
    }

    #[test]
    fn urgent_map_hard_caps_under_flood() {
        reset_lookup_schedule_globals();
        // Insert directly — `note_peer_disconnect_urgent` rejects non-curve points before insert.
        {
            let Ok(mut g) = urgent_map().lock() else {
                return;
            };
            let now = now_ms();
            for i in 0..(MAX_URGENT_ENTRIES + 32) {
                g.insert(format!("peer-{i}"), now - 1_000);
            }
            trim_urgent_map(&mut g, now);
            assert_eq!(g.len(), MAX_URGENT_ENTRIES);
        }
        reset_lookup_schedule_globals();
    }

    #[test]
    fn urgent_map_evicts_oldest_not_arbitrary() {
        let now = 10_000_000i64;
        let mut g = HashMap::new();
        for i in 0..(MAX_URGENT_ENTRIES + 2) {
            g.insert(format!("peer-{i}"), now - 1_000 + i as i64);
        }
        trim_urgent_map(&mut g, now);
        assert_eq!(g.len(), MAX_URGENT_ENTRIES);
        assert!(!g.contains_key("peer-0"));
        assert!(!g.contains_key("peer-1"));
        assert!(g.contains_key(&format!("peer-{}", MAX_URGENT_ENTRIES + 1)));
    }

    #[test]
    fn background_queue_bounded_under_huge_roster() {
        reset_lookup_schedule_globals();
        let all: Vec<String> = (0..5000).map(|i| format!("{:064x}", i + 100)).collect();
        let _ = peers_for_lookup_tick(&[], &[], &all, &[]);
        let q_len = background_cursor()
            .lock()
            .map(|q| q.len())
            .unwrap_or(0);
        assert!(q_len <= MAX_BACKGROUND_LOOKUP_QUEUE);
        reset_lookup_schedule_globals();
    }

    #[test]
    fn priority_before_background_and_cap() {
        reset_lookup_schedule_globals();
        let all: Vec<String> = (0..20).map(|i| format!("{:064x}", i + 1)).collect();
        // Valid-looking hex lengths — use real-shaped fake keys of 66 chars for filter.
        // is_valid is not used in peers_for_lookup_tick itself.
        let priority = vec![all[0].clone()];
        let connected = vec![all[1].clone()];
        let list = peers_for_lookup_tick(&[], &priority, &all, &connected);
        assert_eq!(list.first().map(String::as_str), Some(all[0].as_str()));
        // 1 priority + up to LOOKUP_BACKGROUND_CAP background (excluding connected + priority)
        assert!(list.len() <= 1 + LOOKUP_BACKGROUND_CAP);
        assert!(!list.iter().any(|p| p == &all[1]));
    }
}
