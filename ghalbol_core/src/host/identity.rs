//! Session unlock/lock, keystore, password, and locale.


use crate::p2p_runtime::p2p_stop;
use crate::preferences_v1;
use crate::session_runtime::{self, lock_identity, unlock_identity};
use crate::storage::keystore_v1_file_exists;

use super::cfg;
use crate::contacts_v1;

/// Install namespace (data directory and desktop id): the app's baked `GHALBOL_APP_ID`
/// (`com.ghalbol` / `com.ghalbol.debug`), else the build profile.
pub fn default_app_namespace() -> String {
    std::env::var("GHALBOL_APP_ID")
        .ok()
        .map(|id| id.trim().to_string())
        .filter(|id| crate::storage::sanitize_namespace(id).is_ok())
        .unwrap_or_else(|| {
            if cfg!(debug_assertions) {
                "com.ghalbol.debug"
            } else {
                crate::storage::ANDROID_LIBRARY_NAMESPACE
            }
            .to_string()
        })
}

/// Hand this process's Java VM and Activity to native audio, camera, and HTTPS.
/// The Makepad app calls this once on Android. A second call is ignored.
#[cfg(target_os = "android")]
pub fn install_android_context(vm: *mut std::ffi::c_void, activity: *mut std::ffi::c_void) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if vm.is_null() || activity.is_null() {
        return;
    }
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        ndk_context::initialize_android_context(vm, activity);
    }
    crate::call_media::set_android_audio_ready();
    crate::rustls_init::ensure_rustls_crypto_provider();
    let vm = unsafe { jni::JavaVM::from_raw(vm.cast()) };
    let _ = vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        let activity_ref = unsafe { jni::objects::JObject::from_raw(env, activity as jni::sys::jobject) };
        let context = env.new_local_ref(&activity_ref)?;
        // `activity` is Makepad's global ref. Dropping `activity_ref` would delete it.
        std::mem::forget(activity_ref);
        rustls_platform_verifier::android::init_with_env(env, context)?;
        Ok(())
    });
    if let Ok(dir) = crate::incoming_call_android::android_files_dir() {
        crate::app_paths::configure_android_data_directory(&dir);
    }
}

pub fn keystore_exists(app_namespace: &str) -> bool {
    let cfg = cfg(app_namespace);
    keystore_v1_file_exists(&cfg).unwrap_or(false)
}

#[derive(Clone, Debug)]
pub struct UnlockedSession {
    pub app_namespace: String,
    pub public_key_hex: String,
    pub identity_wire: String,
}

pub fn unlock(app_namespace: &str, password: &str) -> Result<UnlockedSession, String> {
    let v = unlock_identity(app_namespace, password);
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("unlock failed");
        return Err(err.to_string());
    }
    let public_key_hex = v
        .get("public_key_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let identity_wire = v
        .get("libp2p_peer_id")
        .and_then(|x| x.as_str())
        .unwrap_or(&public_key_hex)
        .to_string();
    Ok(UnlockedSession {
        app_namespace: app_namespace.to_string(),
        public_key_hex,
        identity_wire,
    })
}

pub fn lock() {
    p2p_stop();
    #[cfg(target_os = "android")]
    crate::android_network::hold_multicast_lock(false);
    lock_identity();
}

pub fn session_unlocked() -> bool {
    session_runtime::session_unlocked()
}

pub fn unlock_with_options(
    app_namespace: &str,
    password: &str,
    create_algorithm: Option<&str>,
    import_secret_hex: Option<&str>,
) -> Result<UnlockedSession, String> {
    if password.is_empty() {
        return Err("App password is required.".into());
    }
    if keystore_exists(app_namespace) {
        return unlock(app_namespace, password);
    }
    let algorithm = match create_algorithm {
        Some(id) => crate::IdentityAlgorithm::from_wire_id(id)?,
        None => crate::IdentityAlgorithm::Secp256k1,
    };
    let ident = if let Some(secret) = import_secret_hex.map(str::trim).filter(|s| !s.is_empty()) {
        crate::import_identity_from_secret_hex_v1_with_algorithm(
            &cfg(app_namespace),
            password,
            secret,
            algorithm,
        )
        .map_err(|e| e.to_string())?
    } else {
        crate::create_or_unlock_identity_v1_with_algorithm(
            &cfg(app_namespace),
            password,
            Some(algorithm),
        )
        .map_err(|e| e.to_string())?
    };
    install_unlocked(app_namespace, ident)
}

pub fn import_keystore(
    app_namespace: &str,
    password: &str,
    keystore_json: &str,
) -> Result<UnlockedSession, String> {
    if password.is_empty() {
        return Err("App password is required.".into());
    }
    let ident = crate::import_keystore_from_json_v1(
        &cfg(app_namespace),
        password,
        keystore_json,
    )
    .map_err(|e| e.to_string())?;
    install_unlocked(app_namespace, ident)
}

pub fn delete_identity(app_namespace: &str, password: &str) -> Result<(), String> {
    unlock(app_namespace, password)?;
    crate::delete_stored_identity_v1(&cfg(app_namespace)).map_err(|e| e.to_string())?;
    lock();
    Ok(())
}

/// Display name embedded in invitations (`global_alias`). Empty clears.
pub fn local_display_name(app_namespace: &str) -> String {
    preferences_v1::local_display_name_get(&cfg(app_namespace))
        .ok()
        .flatten()
        .unwrap_or_default()
}

pub fn set_local_display_name(app_namespace: &str, name: &str) -> Result<(), String> {
    preferences_v1::local_display_name_set(&cfg(app_namespace), name).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn contacts_version() -> u64 {
    contacts_v1::contacts_change_version()
}

/// Invite URL from the Android view intent, once per distinct link.
pub fn take_view_invite() -> Option<String> {
    #[cfg(target_os = "android")]
    {
        let url = crate::incoming_call_android::view_intent_url()?;
        let url = url.trim().to_string();
        if url.is_empty() {
            return None;
        }
        use std::sync::Mutex;
        static SEEN: Mutex<String> = Mutex::new(String::new());
        let mut seen = SEEN.lock().ok()?;
        if *seen == url {
            return None;
        }
        *seen = url.clone();
        return Some(url);
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

/// Identity algorithm of the unlocked session (`secp256k1`, `ed25519`, …).
pub fn unlocked_algorithm() -> Option<String> {
    crate::session_runtime::unlocked_identity_clone()
        .ok()
        .map(|id| id.algorithm().wire_id().to_string())
}

pub fn reveal_secret(app_namespace: &str, password: &str) -> Result<String, String> {
    let (hex, algo) = crate::reveal_secret_key_hex_v1(&cfg(app_namespace), password)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "Anyone with this key and your password can control this identity.\n\nAlgorithm: {}\n\n{hex}",
        algo.wire_id()
    ))
}

pub fn export_keystore(app_namespace: &str) -> Result<String, String> {
    crate::export_keystore_json_v1(&cfg(app_namespace)).map_err(|e| e.to_string())
}

pub fn change_password(
    app_namespace: &str,
    old_password: &str,
    new_password: &str,
) -> Result<(), String> {
    let ident = crate::change_password_v1(
        &cfg(app_namespace),
        old_password,
        new_password,
    )
    .map_err(|e| e.to_string())?;
    install_unlocked(app_namespace, ident)?;
    Ok(())
}

fn install_unlocked(
    app_namespace: &str,
    ident: crate::DecryptedIdentity,
) -> Result<UnlockedSession, String> {
    let public_key_hex = ident.public_key_hex();
    let identity_wire = ident.identity_wire();
    crate::session_runtime::install_unlocked_identity(ident).map_err(|e| e.to_string())?;
    crate::set_p2p_handler_context(app_namespace);
    crate::delivery_runtime::delivery_start();
    Ok(UnlockedSession {
        app_namespace: app_namespace.to_string(),
        public_key_hex,
        identity_wire,
    })
}

pub fn ui_locale(app_namespace: &str) -> Option<String> {
    preferences_v1::ui_locale_get(&cfg(app_namespace)).ok().flatten()
}

pub fn set_ui_locale(app_namespace: &str, locale: &str) -> Result<(), String> {
    preferences_v1::ui_locale_set(&cfg(app_namespace), locale).map_err(|e| e.to_string())
}

