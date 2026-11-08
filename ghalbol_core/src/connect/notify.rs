use super::util::chrono_now_ms;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

static NETWORK_CHANGE_NOTIFY: AtomicBool = AtomicBool::new(false);
static RELAY_REFRESH_NOTIFY: AtomicBool = AtomicBool::new(false);
static DM_PRESENCE_WAKE_NOTIFY: AtomicBool = AtomicBool::new(false);
static LAST_PRESENCE_WAKE_NOTIFY_MS: AtomicI64 = AtomicI64::new(0);
static DROP_PENDING_CALL_INVITE: OnceLock<fn(&str)> = OnceLock::new();

pub fn set_drop_pending_call_invite_hook(f: fn(&str)) {
    let _ = DROP_PENDING_CALL_INVITE.set(f);
}

pub(crate) fn drop_pending_call_invite(call_id: &str) {
    if let Some(f) = DROP_PENDING_CALL_INVITE.get() {
        f(call_id);
    }
}

pub fn notify_network_change() {
    NETWORK_CHANGE_NOTIFY.store(true, Ordering::SeqCst);
}

pub fn notify_relay_refresh() {
    RELAY_REFRESH_NOTIFY.store(true, Ordering::SeqCst);
}

pub(crate) fn take_connect_upkeep_notify() -> bool {
    NETWORK_CHANGE_NOTIFY.swap(false, Ordering::SeqCst)
        | RELAY_REFRESH_NOTIFY.swap(false, Ordering::SeqCst)
        | DM_PRESENCE_WAKE_NOTIFY.swap(false, Ordering::SeqCst)
}

pub fn notify_dm_presence_wake() {
    let now = chrono_now_ms();
    loop {
        let last = LAST_PRESENCE_WAKE_NOTIFY_MS.load(Ordering::Relaxed);
        if last > 0 && now.saturating_sub(last) < 5_000 {
            return;
        }
        if LAST_PRESENCE_WAKE_NOTIFY_MS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            DM_PRESENCE_WAKE_NOTIFY.store(true, Ordering::SeqCst);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    static DROP_SEEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    #[test]
    fn presence_wake_throttle_coalesces_burst() {
        DM_PRESENCE_WAKE_NOTIFY.store(false, Ordering::SeqCst);
        LAST_PRESENCE_WAKE_NOTIFY_MS.store(0, Ordering::Relaxed);
        notify_dm_presence_wake();
        assert!(DM_PRESENCE_WAKE_NOTIFY.load(Ordering::SeqCst));
        DM_PRESENCE_WAKE_NOTIFY.store(false, Ordering::SeqCst);
        notify_dm_presence_wake();
        assert!(!DM_PRESENCE_WAKE_NOTIFY.load(Ordering::SeqCst));
    }

    #[test]
    fn take_connect_upkeep_merges_notify_flags() {
        NETWORK_CHANGE_NOTIFY.store(true, Ordering::SeqCst);
        RELAY_REFRESH_NOTIFY.store(false, Ordering::SeqCst);
        DM_PRESENCE_WAKE_NOTIFY.store(true, Ordering::SeqCst);
        assert!(take_connect_upkeep_notify());
        assert!(!NETWORK_CHANGE_NOTIFY.load(Ordering::SeqCst));
        assert!(!DM_PRESENCE_WAKE_NOTIFY.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_pending_call_invite_invokes_hook() {
        DROP_SEEN.store(0, Ordering::Relaxed);
        if DROP_PENDING_CALL_INVITE.get().is_none() {
            set_drop_pending_call_invite_hook(|_| {
                DROP_SEEN.fetch_add(1, Ordering::Relaxed);
            });
        }
        let before = DROP_SEEN.load(Ordering::Relaxed);
        drop_pending_call_invite("call-1");
        drop_pending_call_invite("call-2");
        assert_eq!(DROP_SEEN.load(Ordering::Relaxed), before + 2);
    }
}
