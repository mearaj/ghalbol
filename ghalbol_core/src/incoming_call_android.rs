//! Android notifications posted from this process. No extra Java class.

#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};

/// Provider-reported `OpenableColumns.SIZE` larger than the picker limit.
#[cfg(any(test, target_os = "android"))]
fn content_uri_reported_size_too_big(reported_size: i64, max_bytes: usize) -> bool {
    if reported_size < 0 {
        return false;
    }
    reported_size as usize > max_bytes
}

/// SAF display names must survive `Path::push` under app staging.
#[cfg(any(test, target_os = "android"))]
fn finalize_content_pick_name(raw: &str) -> String {
    crate::attach_v1::sanitize_file_name(raw)
}

#[cfg(target_os = "android")]
static UNLOCK_PROMPT_POSTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
mod imp {
    use jni::objects::{JObject, JValue};
    use jni::{JavaVM, jni_sig, jni_str};

    const CHANNEL: &str = "ghalbol";
    pub const INCOMING_ID: i32 = 71001;
    pub const UNLOCK_ID: i32 = 71002;

    fn with_context<F>(f: F) -> Result<(), String>
    where
        F: for<'local> FnOnce(&mut jni::Env<'local>, &JObject<'local>) -> jni::errors::Result<()>,
    {
        if !crate::call_media::android_p2p_context_ready() {
            return Err("android context is not installed".into());
        }
        let ctx = ndk_context::android_context();
        let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()) };
        vm.attach_current_thread(|env| -> jni::errors::Result<()> {
            let activity = unsafe { JObject::from_raw(env, ctx.context() as jni::sys::jobject) };
            let context = env.new_local_ref(&activity)?;
            std::mem::forget(activity);
            f(env, &context)
        })
        .map_err(|e| e.to_string())
    }

    fn notification_manager<'a>(
        env: &mut jni::Env<'a>,
        context: &JObject<'a>,
    ) -> jni::errors::Result<JObject<'a>> {
        let class_ctx = env.find_class(jni_str!("android/content/Context"))?;
        let service = env
            .get_static_field(
                &class_ctx,
                jni_str!("NOTIFICATION_SERVICE"),
                jni_sig!(java.lang.String),
            )?
            .l()?;
        env.call_method(
            context,
            jni_str!("getSystemService"),
            jni_sig!((java.lang.String) -> java.lang.Object),
            &[JValue::Object(&service)],
        )?
        .l()
    }

    fn ensure_channel(env: &mut jni::Env, context: &JObject, nm: &JObject) -> jni::errors::Result<()> {
        let version = env.find_class(jni_str!("android/os/Build$VERSION"))?;
        let sdk = env.get_static_field(&version, jni_str!("SDK_INT"), jni_sig!(int))?.i()?;
        if sdk < 26 {
            return Ok(());
        }
        let channel_class = env.find_class(jni_str!("android/app/NotificationChannel"))?;
        let id = env.new_string(CHANNEL)?;
        let name = env.new_string("Ghal Bol")?;
        let channel = env.new_object(
            &channel_class,
            jni_sig!("(Ljava/lang/String;Ljava/lang/CharSequence;I)V"),
            &[
                JValue::Object(&id),
                JValue::Object(&name),
                JValue::Int(4),
            ],
        )?;
        env.call_method(
            nm,
            jni_str!("createNotificationChannel"),
            jni_sig!("(Landroid/app/NotificationChannel;)V"),
            &[JValue::Object(&channel)],
        )?;
        let _ = context;
        Ok(())
    }

    pub fn post(id: i32, title: &str, body: &str) -> Result<(), String> {
        let title = title.to_string();
        let body = body.to_string();
        with_context(|env, context| {
            let nm = notification_manager(env, context)?;
            ensure_channel(env, context, &nm)?;
            let intent_class = env.find_class(jni_str!("android/content/Intent"))?;
            let activity_class = env.get_object_class(context)?;
            let intent = env.new_object(
                &intent_class,
                jni_sig!("(Landroid/content/Context;Ljava/lang/Class;)V"),
                &[JValue::Object(context), JValue::Object(&activity_class)],
            )?;
            let flags = 0x20000000 | 0x04000000;
            env.call_method(
                &intent,
                jni_str!("addFlags"),
                jni_sig!("(I)Landroid/content/Intent;"),
                &[JValue::Int(flags)],
            )?;
            let pi_class = env.find_class(jni_str!("android/app/PendingIntent"))?;
            let pending = env.call_static_method(
                &pi_class,
                jni_str!("getActivity"),
                jni_sig!("(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;"),
                &[
                    JValue::Object(context),
                    JValue::Int(id),
                    JValue::Object(&intent),
                    JValue::Int(0x08000000 | 0x04000000),
                ],
            )?.l()?;
            let builder_class = env.find_class(jni_str!("android/app/Notification$Builder"))?;
            let channel = env.new_string(CHANNEL)?;
            let builder = env.new_object(
                &builder_class,
                jni_sig!("(Landroid/content/Context;Ljava/lang/String;)V"),
                &[JValue::Object(context), JValue::Object(&channel)],
            )?;
            let jtitle = env.new_string(&title)?;
            let jbody = env.new_string(&body)?;
            env.call_method(
                &builder,
                jni_str!("setContentTitle"),
                jni_sig!("(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;"),
                &[JValue::Object(&jtitle)],
            )?;
            env.call_method(
                &builder,
                jni_str!("setContentText"),
                jni_sig!("(Ljava/lang/CharSequence;)Landroid/app/Notification$Builder;"),
                &[JValue::Object(&jbody)],
            )?;
            let drawable = env.find_class(jni_str!("android/R$drawable"))?;
            let icon = env
                .get_static_field(&drawable, jni_str!("stat_sys_warning"), jni_sig!(int))?
                .i()?;
            env.call_method(
                &builder,
                jni_str!("setSmallIcon"),
                jni_sig!("(I)Landroid/app/Notification$Builder;"),
                &[JValue::Int(icon)],
            )?;
            env.call_method(
                &builder,
                jni_str!("setContentIntent"),
                jni_sig!("(Landroid/app/PendingIntent;)Landroid/app/Notification$Builder;"),
                &[JValue::Object(&pending)],
            )?;
            env.call_method(
                &builder,
                jni_str!("setAutoCancel"),
                jni_sig!("(Z)Landroid/app/Notification$Builder;"),
                &[JValue::Bool(true)],
            )?;
            let notification = env
                .call_method(
                    &builder,
                    jni_str!("build"),
                    jni_sig!("()Landroid/app/Notification;"),
                    &[],
                )?
                .l()?;
            env.call_method(
                &nm,
                jni_str!("notify"),
                jni_sig!("(ILandroid/app/Notification;)V"),
                &[JValue::Int(id), JValue::Object(&notification)],
            )?;
            Ok(())
        })
    }

    pub fn cancel(id: i32) -> Result<(), String> {
        with_context(|env, context| {
            let nm = notification_manager(env, context)?;
            env.call_method(
                &nm,
                jni_str!("cancel"),
                jni_sig!((int) -> void),
                &[JValue::Int(id)],
            )?;
            Ok(())
        })
    }

    pub fn view_url() -> Option<String> {
        let mut url = String::new();
        let ok = with_context(|env, context| {
            let intent = env
                .call_method(
                    context,
                    jni_str!("getIntent"),
                    jni_sig!("()Landroid/content/Intent;"),
                    &[],
                )?
                .l()?;
            if intent.is_null() {
                return Ok(());
            }
            let data = env
                .call_method(
                    &intent,
                    jni_str!("getDataString"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            if data.is_null() {
                return Ok(());
            }
            let text = unsafe { jni::objects::JString::from_raw(env, data.as_raw()) };
            url = text.try_to_string(env)?;
            std::mem::forget(data);
            Ok(())
        });
        if ok.is_err() || url.is_empty() {
            return None;
        }
        Some(url)
    }

    pub fn view_file(path: &str, mime: &str) -> Result<(), String> {
        let path = path.to_string();
        let mime = mime.to_string();
        with_context(|env, context| {
            let uri_class = env.find_class(jni_str!("android/net/Uri"))?;
            let file_uri = format!("file://{path}");
            let juri = env.new_string(&file_uri)?;
            let uri = env
                .call_static_method(
                    &uri_class,
                    jni_str!("parse"),
                    jni_sig!("(Ljava/lang/String;)Landroid/net/Uri;"),
                    &[JValue::Object(&juri)],
                )?
                .l()?;
            let intent_class = env.find_class(jni_str!("android/content/Intent"))?;
            let action = env
                .get_static_field(
                    &intent_class,
                    jni_str!("ACTION_VIEW"),
                    jni_sig!("Ljava/lang/String;"),
                )?
                .l()?;
            let intent = env.new_object(
                &intent_class,
                jni_sig!("(Ljava/lang/String;)V"),
                &[JValue::Object(&action)],
            )?;
            let jmime = env.new_string(&mime)?;
            env.call_method(
                &intent,
                jni_str!("setDataAndType"),
                jni_sig!("(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;"),
                &[JValue::Object(&uri), JValue::Object(&jmime)],
            )?;
            env.call_method(
                &intent,
                jni_str!("addFlags"),
                jni_sig!("(I)Landroid/content/Intent;"),
                &[JValue::Int(0x10000000)],
            )?;
            env.call_method(
                context,
                jni_str!("startActivity"),
                jni_sig!("(Landroid/content/Intent;)V"),
                &[JValue::Object(&intent)],
            )?;
            Ok(())
        })
    }

    pub fn files_dir() -> Result<String, String> {
        let mut path = String::new();
        with_context(|env, context| {
            let file = env
                .call_method(
                    context,
                    jni_str!("getFilesDir"),
                    jni_sig!(() -> java.io.File),
                    &[],
                )?
                .l()?;
            let abs = env
                .call_method(
                    &file,
                    jni_str!("getAbsolutePath"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            let text = unsafe { jni::objects::JString::from_raw(env, abs.as_raw()) };
            path = text.try_to_string(env)?;
            std::mem::forget(abs);
            Ok(())
        })?;
        if path.is_empty() {
            return Err("android files directory is empty".into());
        }
        Ok(path)
    }

    /// Read a Storage Access Framework document (`content://…`) the user picked.
    /// Returns the provider's display name (empty when it reports none) and the bytes.
    pub fn read_content_uri(uri: &str, max_bytes: usize) -> Result<(String, Vec<u8>), String> {
        let mut name = String::new();
        let mut data = Vec::new();
        let mut too_big = false;
        with_context(|env, context| {
            let result = read_content_uri_jni(
                env,
                context,
                uri,
                max_bytes,
                &mut name,
                &mut data,
                &mut too_big,
            );
            if env.exception_check() {
                // Leave no pending SecurityException / FileNotFoundException on this thread.
                env.exception_clear();
            }
            result
        })
        .map_err(|e| format!("could not read the chosen file: {e}"))?;
        if too_big {
            return Err(format!(
                "The chosen file is larger than {} MB",
                max_bytes / (1024 * 1024)
            ));
        }
        let name =
            super::finalize_content_pick_name(if name.is_empty() { "file" } else { &name });
        Ok((name, data))
    }

    fn read_content_uri_jni<'a>(
        env: &mut jni::Env<'a>,
        context: &JObject<'a>,
        uri: &str,
        max_bytes: usize,
        name: &mut String,
        data: &mut Vec<u8>,
        too_big: &mut bool,
    ) -> jni::errors::Result<()> {
        let resolver = env
            .call_method(
                context,
                jni_str!("getContentResolver"),
                jni_sig!(() -> android.content.ContentResolver),
                &[],
            )?
            .l()?;
        let uri_class = env.find_class(jni_str!("android/net/Uri"))?;
        let uri_text = env.new_string(uri)?;
        let juri = env
            .call_static_method(
                &uri_class,
                jni_str!("parse"),
                jni_sig!("(Ljava/lang/String;)Landroid/net/Uri;"),
                &[JValue::Object(&uri_text)],
            )?
            .l()?;
        let null_obj = JObject::null();
        let cursor = env
            .call_method(
                &resolver,
                jni_str!("query"),
                jni_sig!("(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"),
                &[
                    JValue::Object(&juri),
                    JValue::Object(&null_obj),
                    JValue::Object(&null_obj),
                    JValue::Object(&null_obj),
                    JValue::Object(&null_obj),
                ],
            )?
            .l()?;
        if !cursor.is_null() {
            let has_row = env
                .call_method(&cursor, jni_str!("moveToFirst"), jni_sig!("()Z"), &[])?
                .z()?;
            if has_row {
                let column = env.new_string("_display_name")?;
                let index = env
                    .call_method(
                        &cursor,
                        jni_str!("getColumnIndex"),
                        jni_sig!("(Ljava/lang/String;)I"),
                        &[JValue::Object(&column)],
                    )?
                    .i()?;
                if index >= 0 {
                    let value = env
                        .call_method(
                            &cursor,
                            jni_str!("getString"),
                            jni_sig!("(I)Ljava/lang/String;"),
                            &[JValue::Int(index)],
                        )?
                        .l()?;
                    if !value.is_null() {
                        let text = unsafe { jni::objects::JString::from_raw(env, value.as_raw()) };
                        *name = text.try_to_string(env)?;
                        std::mem::forget(value);
                    }
                }
                let size_col = env.new_string("_size")?;
                let size_idx = env
                    .call_method(
                        &cursor,
                        jni_str!("getColumnIndex"),
                        jni_sig!("(Ljava/lang/String;)I"),
                        &[JValue::Object(&size_col)],
                    )?
                    .i()?;
                if size_idx >= 0 {
                    let reported = env
                        .call_method(
                            &cursor,
                            jni_str!("getLong"),
                            jni_sig!("(I)J"),
                            &[JValue::Int(size_idx)],
                        )?
                        .j()?;
                    if super::content_uri_reported_size_too_big(reported, max_bytes) {
                        *too_big = true;
                    }
                }
            }
            env.call_method(&cursor, jni_str!("close"), jni_sig!("()V"), &[])?;
        }
        if *too_big {
            return Ok(());
        }
        let stream = env
            .call_method(
                &resolver,
                jni_str!("openInputStream"),
                jni_sig!("(Landroid/net/Uri;)Ljava/io/InputStream;"),
                &[JValue::Object(&juri)],
            )?
            .l()?;
        if stream.is_null() {
            return Err(jni::errors::Error::NullPtr("openInputStream returned null"));
        }
        const CHUNK: usize = 64 * 1024;
        let buffer = env.new_byte_array(CHUNK)?;
        let mut chunk = vec![0i8; CHUNK];
        let read = loop {
            let n = match env
                .call_method(&stream, jni_str!("read"), jni_sig!("([B)I"), &[JValue::Object(buffer.as_ref())])
                .and_then(|v| v.i())
            {
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            if n < 0 {
                break Ok(());
            }
            let n = n as usize;
            if data.len() + n > max_bytes {
                *too_big = true;
                break Ok(());
            }
            if let Err(e) = buffer.get_region(env, 0, &mut chunk[..n]) {
                break Err(e);
            }
            data.extend(chunk[..n].iter().map(|b| *b as u8));
        };
        env.call_method(&stream, jni_str!("close"), jni_sig!("()V"), &[])?;
        read
    }

    /// Write keystore JSON to app files + MediaStore Downloads when possible.
    pub fn save_keystore_backup(json: &str) -> Result<String, String> {
        let json = json.to_string();
        let files = files_dir()?;
        let backup_dir = std::path::PathBuf::from(&files).join("backups");
        std::fs::create_dir_all(&backup_dir).map_err(|e| format!("backup dir: {e}"))?;
        let local = backup_dir.join("ghalbol-keystore.json");
        std::fs::write(&local, json.as_bytes()).map_err(|e| format!("write backup: {e}"))?;

        let mut downloads_ok = false;
        let media_err = with_context(|env, context| {
            let resolver = env
                .call_method(
                    context,
                    jni_str!("getContentResolver"),
                    jni_sig!(() -> android.content.ContentResolver),
                    &[],
                )?
                .l()?;
            let values_class = env.find_class(jni_str!("android/content/ContentValues"))?;
            let values = env.new_object(&values_class, jni_sig!("()V"), &[])?;
            let put_str = |env: &mut jni::Env, values: &JObject, key: &str, val: &str| {
                let jkey = env.new_string(key)?;
                let jval = env.new_string(val)?;
                env.call_method(
                    values,
                    jni_str!("put"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"),
                    &[JValue::Object(&jkey), JValue::Object(&jval)],
                )?;
                Ok::<(), jni::errors::Error>(())
            };
            let put_int = |env: &mut jni::Env, values: &JObject, key: &str, val: i32| {
                let jkey = env.new_string(key)?;
                let integer_class = env.find_class(jni_str!("java/lang/Integer"))?;
                let boxed = env.new_object(
                    &integer_class,
                    jni_sig!("(I)V"),
                    &[JValue::Int(val)],
                )?;
                env.call_method(
                    values,
                    jni_str!("put"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/Integer;)V"),
                    &[JValue::Object(&jkey), JValue::Object(&boxed)],
                )?;
                Ok::<(), jni::errors::Error>(())
            };
            put_str(env, &values, "_display_name", "ghalbol-keystore.json")?;
            put_str(env, &values, "mime_type", "application/json")?;
            put_str(env, &values, "relative_path", "Download/")?;
            put_int(env, &values, "is_pending", 1)?;

            let downloads = env.find_class(jni_str!("android/provider/MediaStore$Downloads"))?;
            let collection = env
                .get_static_field(
                    &downloads,
                    jni_str!("EXTERNAL_CONTENT_URI"),
                    jni_sig!(android.net.Uri),
                )?
                .l()?;
            let uri = env
                .call_method(
                    &resolver,
                    jni_str!("insert"),
                    jni_sig!("(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;"),
                    &[JValue::Object(&collection), JValue::Object(&values)],
                )?
                .l()?;
            if uri.is_null() {
                return Err(jni::errors::Error::NullPtr("MediaStore insert returned null"));
            }
            let stream = env
                .call_method(
                    &resolver,
                    jni_str!("openOutputStream"),
                    jni_sig!("(Landroid/net/Uri;)Ljava/io/OutputStream;"),
                    &[JValue::Object(&uri)],
                )?
                .l()?;
            if stream.is_null() {
                return Err(jni::errors::Error::NullPtr("openOutputStream returned null"));
            }
            let bytes = env.byte_array_from_slice(json.as_bytes())?;
            env.call_method(
                &stream,
                jni_str!("write"),
                jni_sig!("([B)V"),
                &[JValue::Object(bytes.as_ref())],
            )?;
            env.call_method(&stream, jni_str!("flush"), jni_sig!("()V"), &[])?;
            env.call_method(&stream, jni_str!("close"), jni_sig!("()V"), &[])?;

            let done = env.new_object(&values_class, jni_sig!("()V"), &[])?;
            put_int(env, &done, "is_pending", 0)?;
            let null_obj = JObject::null();
            env.call_method(
                &resolver,
                jni_str!("update"),
                jni_sig!("(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"),
                &[
                    JValue::Object(&uri),
                    JValue::Object(&done),
                    JValue::Object(&null_obj),
                    JValue::Object(&null_obj),
                ],
            )?;
            downloads_ok = true;
            Ok(())
        });

        if downloads_ok {
            Ok(
                "Saved to Downloads as ghalbol-keystore.json (also kept under app files). Keep this file and your app password. Older backups still use the password they were exported with."
                    .into(),
            )
        } else {
            let _ = media_err;
            Ok(format!(
                "Saved {}. Keep this file and your app password. Older backups still use the password they were exported with.",
                local.display()
            ))
        }
    }

    /// Write `bytes` into MediaStore Downloads as `display_name` with `mime`.
    pub fn save_bytes_to_downloads(
        bytes: &[u8],
        display_name: &str,
        mime: &str,
    ) -> Result<String, String> {
        let display_name = crate::attach_v1::sanitize_file_name(display_name);
        if display_name.is_empty() {
            return Err("missing file name".into());
        }
        let mime = if mime.trim().is_empty() {
            "application/octet-stream"
        } else {
            mime
        };
        let bytes = bytes.to_vec();
        let mut downloads_ok = false;
        let media_err = with_context(|env, context| {
            let resolver = env
                .call_method(
                    context,
                    jni_str!("getContentResolver"),
                    jni_sig!(() -> android.content.ContentResolver),
                    &[],
                )?
                .l()?;
            let values_class = env.find_class(jni_str!("android/content/ContentValues"))?;
            let values = env.new_object(&values_class, jni_sig!("()V"), &[])?;
            let put_str = |env: &mut jni::Env, values: &JObject, key: &str, val: &str| {
                let jkey = env.new_string(key)?;
                let jval = env.new_string(val)?;
                env.call_method(
                    values,
                    jni_str!("put"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"),
                    &[JValue::Object(&jkey), JValue::Object(&jval)],
                )?;
                Ok::<(), jni::errors::Error>(())
            };
            let put_int = |env: &mut jni::Env, values: &JObject, key: &str, val: i32| {
                let jkey = env.new_string(key)?;
                let integer_class = env.find_class(jni_str!("java/lang/Integer"))?;
                let boxed = env.new_object(
                    &integer_class,
                    jni_sig!("(I)V"),
                    &[JValue::Int(val)],
                )?;
                env.call_method(
                    values,
                    jni_str!("put"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/Integer;)V"),
                    &[JValue::Object(&jkey), JValue::Object(&boxed)],
                )?;
                Ok::<(), jni::errors::Error>(())
            };
            put_str(env, &values, "_display_name", &display_name)?;
            put_str(env, &values, "mime_type", mime)?;
            put_str(env, &values, "relative_path", "Download/")?;
            put_int(env, &values, "is_pending", 1)?;

            let downloads = env.find_class(jni_str!("android/provider/MediaStore$Downloads"))?;
            let collection = env
                .get_static_field(
                    &downloads,
                    jni_str!("EXTERNAL_CONTENT_URI"),
                    jni_sig!(android.net.Uri),
                )?
                .l()?;
            let uri = env
                .call_method(
                    &resolver,
                    jni_str!("insert"),
                    jni_sig!("(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;"),
                    &[JValue::Object(&collection), JValue::Object(&values)],
                )?
                .l()?;
            if uri.is_null() {
                return Err(jni::errors::Error::NullPtr("MediaStore insert returned null"));
            }
            let stream = env
                .call_method(
                    &resolver,
                    jni_str!("openOutputStream"),
                    jni_sig!("(Landroid/net/Uri;)Ljava/io/OutputStream;"),
                    &[JValue::Object(&uri)],
                )?
                .l()?;
            if stream.is_null() {
                return Err(jni::errors::Error::NullPtr("openOutputStream returned null"));
            }
            let jbytes = env.byte_array_from_slice(&bytes)?;
            env.call_method(
                &stream,
                jni_str!("write"),
                jni_sig!("([B)V"),
                &[JValue::Object(jbytes.as_ref())],
            )?;
            env.call_method(&stream, jni_str!("flush"), jni_sig!("()V"), &[])?;
            env.call_method(&stream, jni_str!("close"), jni_sig!("()V"), &[])?;

            let done = env.new_object(&values_class, jni_sig!("()V"), &[])?;
            put_int(env, &done, "is_pending", 0)?;
            let null_obj = JObject::null();
            env.call_method(
                &resolver,
                jni_str!("update"),
                jni_sig!("(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"),
                &[
                    JValue::Object(&uri),
                    JValue::Object(&done),
                    JValue::Object(&null_obj),
                    JValue::Object(&null_obj),
                ],
            )?;
            downloads_ok = true;
            Ok(())
        });
        if downloads_ok {
            Ok(format!("Saved to Downloads as {display_name}"))
        } else {
            Err(match media_err {
                Err(e) => format!("Could not save attachment: {e}"),
                Ok(()) => "Could not save attachment: MediaStore insert failed".into(),
            })
        }
    }
}

#[cfg(target_os = "android")]
pub fn show(peer_public_key_hex: &str, _call_id: &str) {
    let name = short_display_name(peer_public_key_hex);
    if let Err(e) = imp::post(imp::INCOMING_ID, "Incoming call", &format!("{name} is calling")) {
        crate::flow_log::warn("call", format!("android incoming call notify failed: {e}"));
    }
}

#[cfg(target_os = "android")]
pub fn dismiss() {
    let _ = imp::cancel(imp::INCOMING_ID);
}

#[cfg(test)]
mod notify_id_tests {
    use crate::message_notify::android_message_notification_id;

    #[test]
    fn message_notification_ids_stay_out_of_call_unlock_slots() {
        const INCOMING_ID: i32 = 71_001;
        const UNLOCK_ID: i32 = 71_002;
        assert!(
            (72_000..82_000).contains(&android_message_notification_id(
                "0305b1b0d27745e0a38a7254ea100abc38857b51ded2ac7ea88d3063fb8da21784"
            ))
        );
        for h in 0..10_000 {
            let id = 72_000 + h;
            assert_ne!(id, INCOMING_ID);
            assert_ne!(id, UNLOCK_ID);
        }
    }
}

#[cfg(test)]
mod content_pick_tests {
    use super::{content_uri_reported_size_too_big, finalize_content_pick_name};

    #[test]
    fn content_uri_size_unknown_is_not_too_big() {
        assert!(!content_uri_reported_size_too_big(-1, 1024));
    }

    #[test]
    fn content_uri_size_over_limit() {
        assert!(content_uri_reported_size_too_big(1025, 1024));
        assert!(!content_uri_reported_size_too_big(1024, 1024));
    }

    #[test]
    fn content_pick_name_sanitized_for_staging() {
        assert_eq!(finalize_content_pick_name("../evil"), ".._evil");
        assert_eq!(finalize_content_pick_name("."), "file");
    }
}

#[cfg(target_os = "android")]
pub fn post_message(peer_public_key_hex: &str, title: &str, body: &str) -> Result<(), String> {
    let id = crate::message_notify::android_message_notification_id(peer_public_key_hex);
    imp::post(id, title, body)
}

#[cfg(target_os = "android")]
pub fn cancel_message(peer_public_key_hex: &str) {
    let id = crate::message_notify::android_message_notification_id(peer_public_key_hex);
    let _ = imp::cancel(id);
}

#[cfg(target_os = "android")]
pub fn notify_unlock_needed() {
    if crate::session_runtime::session_unlocked() {
        UNLOCK_PROMPT_POSTED.store(false, Ordering::Release);
        return;
    }
    if UNLOCK_PROMPT_POSTED.swap(true, Ordering::AcqRel) {
        return;
    }
    if crate::session_runtime::session_unlocked() {
        UNLOCK_PROMPT_POSTED.store(false, Ordering::Release);
        return;
    }
    if imp::post(
        imp::UNLOCK_ID,
        "Ghal Bol",
        "Enter your password to receive messages",
    )
    .is_err()
    {
        UNLOCK_PROMPT_POSTED.store(false, Ordering::Release);
    }
}

#[cfg(target_os = "android")]
pub fn dismiss_unlock_prompt() {
    UNLOCK_PROMPT_POSTED.store(false, Ordering::Release);
    let _ = imp::cancel(imp::UNLOCK_ID);
}

#[cfg(target_os = "android")]
pub fn view_intent_url() -> Option<String> {
    imp::view_url()
}

#[cfg(target_os = "android")]
pub fn open_file(path: &str) -> Result<(), String> {
    let mime = match std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "opus" | "ogg" => "audio/ogg",
        _ => "application/octet-stream",
    };
    imp::view_file(path, mime)
}

#[cfg(target_os = "android")]
pub fn android_files_dir() -> Result<String, String> {
    imp::files_dir()
}

#[cfg(target_os = "android")]
pub fn save_keystore_backup(json: &str) -> Result<String, String> {
    imp::save_keystore_backup(json)
}

/// Read a `content://` document from the system picker as (display name, bytes).
#[cfg(target_os = "android")]
pub fn read_content_uri(uri: &str, max_bytes: usize) -> Result<(String, Vec<u8>), String> {
    imp::read_content_uri(uri, max_bytes)
}

/// Copy a local file into MediaStore Downloads (same path as keystore backup).
#[cfg(target_os = "android")]
pub fn save_file_to_downloads(path: &str, display_name: &str) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read attachment: {e}"))?;
    let ext = std::path::Path::new(display_name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "opus" | "ogg" => "audio/ogg",
        "json" => "application/json",
        _ => "application/octet-stream",
    };
    imp::save_bytes_to_downloads(&bytes, display_name, mime)
}

#[cfg(target_os = "android")]
fn short_display_name(pk: &str) -> String {
    let p = pk.trim();
    if p.is_empty() {
        return "Contact".into();
    }
    if p.len() >= 16 && p.is_ascii() {
        format!("{}…", &p[..8])
    } else {
        p.chars().take(16).collect()
    }
}
