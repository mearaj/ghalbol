//! New-message notifications: one per chat, replaced by each newer message and removed when
//! that chat is opened. Fired from `dm_event_handler` only when inbound mail bumps unread
//! (new, not a poll replay, and not read in the open room). The body names what arrived —
//! message text never leaves the app UI.

/// What arrived, for the notification body.
#[derive(Clone, Copy)]
pub(crate) enum Arrived {
    Text,
    Voice,
    File,
}

impl Arrived {
    fn body(self) -> &'static str {
        match self {
            Arrived::Text => "New message",
            Arrived::Voice => "Voice message",
            Arrived::File => "File",
        }
    }
}

/// `sender_pk` sent something the user has not seen yet.
pub(crate) fn notify_inbound(sender_pk: &str, arrived: Arrived) {
    let pk = sender_pk.trim();
    if pk.is_empty() {
        return;
    }
    #[cfg(test)]
    test_tally_inbound(&pk);
    let title = crate::host::peer_display_name(pk);
    imp::show(pk, &title, arrived.body());
}

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
static TEST_INBOUND_NOTIFY: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

#[cfg(test)]
fn test_inbound_notify_mx() -> &'static Mutex<HashMap<String, u32>> {
    TEST_INBOUND_NOTIFY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
fn test_tally_inbound(pk: &str) {
    let key = pk.to_ascii_lowercase();
    if let Ok(mut g) = test_inbound_notify_mx().lock() {
        *g.entry(key).or_insert(0) += 1;
    }
}

#[cfg(test)]
pub(crate) fn test_inbound_notify_count(pk: &str) -> u32 {
    let key = pk.trim().to_ascii_lowercase();
    test_inbound_notify_mx()
        .lock()
        .ok()
        .and_then(|g| g.get(&key).copied())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn test_reset_inbound_notify_counts() {
    if let Ok(mut g) = test_inbound_notify_mx().lock() {
        g.clear();
    }
}

/// The chat with `peer_pk` is open: its notification is no longer news.
pub(crate) fn clear_for_peer(peer_pk: &str) {
    let pk = peer_pk.trim();
    if !pk.is_empty() {
        imp::clear(pk);
    }
}

/// Android `NotificationManager.notify` id for one chat (stable FNV-1a).
#[cfg(any(test, target_os = "android"))]
pub(crate) fn android_message_notification_id(pk: &str) -> i32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in pk.trim().to_ascii_lowercase().bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    72_000 + (h % 10_000) as i32
}

#[cfg(test)]
mod tests {
    use super::android_message_notification_id;

    #[test]
    fn android_message_id_is_case_insensitive_and_stable() {
        let pk = "0305B1B0D27745E0A38A7254EA100ABC38857B51DED2AC7EA88D3063FB8DA21784";
        let a = android_message_notification_id(pk);
        let b = android_message_notification_id(&pk.to_ascii_lowercase());
        assert_eq!(a, b);
        assert!((72_000..82_000).contains(&a));
        assert_ne!(
            android_message_notification_id(pk),
            android_message_notification_id(
                "0200000000000000000000000000000000000000000000000000000000000001"
            )
        );
    }
}

// Unit tests drive the inbound path: never pop real desktop banners from `cargo test`.
#[cfg(all(target_os = "linux", not(test)))]
mod imp {
    use std::collections::HashMap;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};

    use notify_rust::{Hint, Notification};

    /// One D-Bus show at a time — parallel spawns used to mint duplicate server ids per chat.
    fn show_serial() -> &'static Mutex<()> {
        static S: OnceLock<Mutex<()>> = OnceLock::new();
        S.get_or_init(|| Mutex::new(()))
    }

    /// Server notification id per chat, so a newer message replaces the banner.
    fn shown() -> &'static Mutex<HashMap<String, u32>> {
        static SHOWN: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
        SHOWN.get_or_init(|| Mutex::new(HashMap::new()))
    }

    const MAX_SHOWN_ENTRIES: usize = 512;

    fn key(pk: &str) -> String {
        pk.to_ascii_lowercase()
    }

    pub fn show(pk: &str, title: &str, body: &str) {
        let pk = key(pk);
        let title: String = title.chars().take(128).collect();
        // Defense in depth — notification servers reject / hang on multi-KiB bodies.
        let body: String = body.chars().take(256).collect();
        // D-Bus round trips stay off the poll (UI) thread.
        std::thread::spawn(move || {
            let _serial = show_serial().lock().ok();
            let app_id = crate::host::default_app_namespace();
            let replace = shown().lock().ok().and_then(|g| g.get(&pk).copied());
            let mut n = Notification::new();
            n.appname(&app_id)
                .summary(&title)
                .body(&body)
                .hint(Hint::DesktopEntry(app_id.clone()))
                .action("default", "Open Ghal Bol");
            if let Some(id) = replace {
                n.id(id);
            }
            let Ok(handle) = n.show() else {
                return;
            };
            if replace.is_some() {
                // Same server id: the first banner's waiter still answers its click.
                return;
            }
            let id = handle.id();
            if let Ok(mut g) = shown().lock() {
                while g.len() >= MAX_SHOWN_ENTRIES {
                    if let Some(old) = g.keys().next().cloned() {
                        g.remove(&old);
                    } else {
                        break;
                    }
                }
                g.insert(pk.clone(), id);
            }
            handle.wait_for_action(move |action| {
                if action == "default" {
                    crate::linux_desktop_launch::wake_desktop_app(&app_id, || {});
                }
                if let Ok(mut g) = shown().lock() {
                    if g.get(&pk) == Some(&id) {
                        g.remove(&pk);
                    }
                }
            });
        });
    }

    pub fn clear(pk: &str) {
        let Some(id) = shown().lock().ok().and_then(|mut g| g.remove(&key(pk))) else {
            return;
        };
        let _ = Command::new("dbus-send")
            .args([
                "--session",
                "--dest=org.freedesktop.Notifications",
                "--type=method_call",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications.CloseNotification",
                &format!("uint32:{id}"),
            ])
            .status();
    }
}

#[cfg(all(target_os = "android", not(test)))]
mod imp {
    pub fn show(pk: &str, title: &str, body: &str) {
        if let Err(e) = crate::incoming_call_android::post_message(pk, title, body) {
            crate::flow_log::warn("DM/notify", format!("android message notify failed: {e}"));
        }
    }

    pub fn clear(pk: &str) {
        crate::incoming_call_android::cancel_message(pk);
    }
}

#[cfg(any(test, not(any(target_os = "linux", target_os = "android"))))]
mod imp {
    pub fn show(_pk: &str, _title: &str, _body: &str) {}

    pub fn clear(_pk: &str) {}
}
