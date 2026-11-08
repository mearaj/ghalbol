//! QR scan, Android helpers, and file pick reads.




pub fn start_qr_scan() -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        return crate::desktop_media::start_qr_scan();
    }
    #[cfg(target_os = "android")]
    {
        return crate::android_qr::start_qr_scan();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
    Err("QR camera scan is not available on this device".into())
}

pub fn take_qr_scan() -> Option<Result<String, String>> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        return crate::desktop_media::take_qr_scan();
    }
    #[cfg(target_os = "android")]
    {
        return crate::android_qr::take_qr_scan();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
    None
}

/// Latest QR-scan camera preview as raw RGBA, if a new frame is ready.
pub fn take_qr_preview_rgba() -> Option<(u32, u32, Vec<u8>)> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        return crate::desktop_media::take_qr_preview_rgba();
    }
    #[cfg(target_os = "android")]
    {
        return crate::android_qr::take_qr_preview_rgba();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
    None
}

/// Stop an in-flight QR camera scan.
pub fn stop_qr_scan() {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        crate::desktop_media::stop_qr_scan();
    }
    #[cfg(target_os = "android")]
    {
        crate::android_qr::stop_qr_scan();
    }
}

/// Android: write the keystore backup to app files and the public Downloads folder.
#[cfg(target_os = "android")]
pub fn android_save_backup_json(json: &str) -> Result<String, String> {
    crate::incoming_call_android::save_keystore_backup(json)
}

/// Faster UI poll while the Scan sheet needs live camera frames.
pub fn set_qr_scan_ui_active(active: bool) {
    QR_SCAN_UI_ACTIVE.store(active, std::sync::atomic::Ordering::Relaxed);
}

pub fn qr_scan_ui_active() -> bool {
    QR_SCAN_UI_ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
}

static QR_SCAN_UI_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Decode an invite QR from a picture: a path on desktop, a picker `content://` URI on Android.
pub fn decode_qr_file(path: &str) -> Result<String, String> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        return crate::desktop_media::decode_qr_file(path);
    }
    #[cfg(target_os = "android")]
    {
        let (_, bytes) = read_picked_file(path, MAX_PICKED_PICTURE_BYTES)?;
        return crate::qr_luma::decode_image_bytes(&bytes);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows", target_os = "android")))]
    {
        let _ = path;
        Err("QR picture decode is not available on this device".into())
    }
}

/// Largest picture accepted for QR decode from the picker.
#[cfg(target_os = "android")]
const MAX_PICKED_PICTURE_BYTES: usize = 32 * 1024 * 1024;

/// Largest keystore backup accepted from the picker (real ones are under 1 KB).
pub const MAX_PICKED_BACKUP_BYTES: usize = 1024 * 1024;

/// A file chosen in the system picker, as (display name, bytes). Desktop pickers return a
/// path; Android returns a `content://` document URI, read through the content resolver.
pub fn read_picked_file(picked: &str, max_bytes: usize) -> Result<(String, Vec<u8>), String> {
    let picked = picked.trim();
    #[cfg(target_os = "android")]
    if picked.starts_with("content://") {
        return crate::incoming_call_android::read_content_uri(picked, max_bytes);
    }
    let path = std::path::Path::new(picked);
    let len = std::fs::metadata(path)
        .map_err(|e| format!("could not open {picked}: {e}"))?
        .len();
    if len > max_bytes as u64 {
        return Err(format!(
            "The chosen file is larger than {} MB",
            max_bytes / (1024 * 1024)
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {picked}: {e}"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok((name, bytes))
}

