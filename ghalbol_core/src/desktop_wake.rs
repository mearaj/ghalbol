//! Marker files so a notification tap can raise the running desktop app.

use std::path::PathBuf;

fn runtime_dir() -> PathBuf {
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            return PathBuf::from(runtime).join("ghalbol");
        }
    }
    PathBuf::from("/tmp/ghalbol")
}

fn marker_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
}

fn marker(name: &str) -> Option<PathBuf> {
    if !marker_name_ok(name) {
        return None;
    }
    Some(runtime_dir().join(name))
}

#[cfg(target_os = "linux")]
fn touch(name: &str) {
    let Some(path) = marker(name) else {
        return;
    };
    let dir = runtime_dir();
    let _ = std::fs::create_dir_all(&dir);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "1".to_string());
    let _ = std::fs::write(path, ts);
}

fn take(name: &str) -> bool {
    let Some(path) = marker(name) else {
        return false;
    };
    match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
pub fn touch_incoming_call_wake() {
    touch("incoming_call_wake");
}

pub fn take_incoming_call_wake() -> bool {
    take("incoming_call_wake")
}

pub fn clear_incoming_call_wake() {
    if let Some(path) = marker("incoming_call_wake") {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::marker_name_ok;

    #[test]
    fn marker_name_rejects_path_climb() {
        assert!(marker_name_ok("incoming_call_wake"));
        assert!(!marker_name_ok("../etc/passwd"));
        assert!(!marker_name_ok("a/b"));
        assert!(!marker_name_ok(""));
        assert!(!marker_name_ok(&"x".repeat(80)));
    }
}

#[cfg(target_os = "linux")]
pub fn touch_unlock_wake() {
    touch("unlock_wake");
}

pub fn take_unlock_wake() -> bool {
    take("unlock_wake")
}
