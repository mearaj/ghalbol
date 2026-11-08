//! Scale-invariant coord peer lookup: urgent → priority → capped background (TRANSPORT.md).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::recovery::clear_coord_lookup_backoff_for_pk;

/// Background sweep cap per upkeep tick — urgent/priority are uncapped.
pub const LOOKUP_BACKGROUND_CAP: usize = 4;
/// Recent disconnect stays urgent this long.
const URGENT_WINDOW_MS: i64 = 60_000;

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
    let pk = public_key_hex.trim();
    if pk.is_empty() || !crate::contacts_v1::is_valid_public_key_hex(pk) {
        return;
    }
    clear_coord_lookup_backoff_for_pk(pk);
    if let Ok(mut g) = urgent_map().lock() {
        g.insert(pk.to_string(), now_ms());
    }
}

/// Intent beats backoff: open chat / queued outbound / call.
pub fn note_peer_lookup_intent(public_key_hex: &str) {
    let pk = public_key_hex.trim();
    if pk.is_empty() || !crate::contacts_v1::is_valid_public_key_hex(pk) {
        return;
    }
    clear_coord_lookup_backoff_for_pk(pk);
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
        let mut bg = 0usize;
        while bg < LOOKUP_BACKGROUND_CAP {
            let Some(pk) = q.pop_front() else {
                break;
            };
            if seen.contains(&pk.to_ascii_lowercase()) || connected.contains(&pk.to_ascii_lowercase())
            {
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

    #[test]
    fn priority_before_background_and_cap() {
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
