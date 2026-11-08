//! Bake `env/development.env` or `env/production.env` (under this crate) into the binary.
//
//! Selection:
//! - `GHALBOL_ENV=development|production` if set (scripts export this)
//! - else Cargo `PROFILE=release` → production, otherwise development
//!
//! Output: `$OUT_DIR/ghalbol.env` (embedded by `main.rs` via `include_str!`) and the
//! `GHALBOL_ENV` compile-time variable naming the profile.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn defaults(profile: &str) -> BTreeMap<&'static str, &'static str> {
    match profile {
        "production" => BTreeMap::from([
            ("GHALBOL_APP_ID", "com.ghalbol"),
            ("GHALBOL_APP_LABEL", "Ghal Bol"),
        ]),
        _ => BTreeMap::from([
            ("GHALBOL_APP_ID", "com.ghalbol.debug"),
            ("GHALBOL_APP_LABEL", "Ghal Bol Dev"),
        ]),
    }
}

/// `env/` beside this crate's `Cargo.toml`. cargo-makepad's Android build compiles the app
/// through a generated wrapper manifest elsewhere, with `build` pointing back at this file,
/// so fall back to the directory holding `build.rs`.
fn env_dir() -> PathBuf {
    let manifest_env = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("env");
    if manifest_env.is_dir() {
        return manifest_env;
    }
    Path::new(file!())
        .parent()
        .map(|dir| dir.join("env"))
        .unwrap_or(manifest_env)
}

fn main() {
    // Tell rustc about custom cfgs set below (avoids unexpected_cfgs warnings).
    println!("cargo:rustc-check-cfg=cfg(ghalbol_hide_console)");

    let ghalbol_env = env::var("GHALBOL_ENV").unwrap_or_else(|_| {
        match env::var("PROFILE").as_deref() {
            Ok("release") => "production".into(),
            _ => "development".into(),
        }
    });

    match ghalbol_env.as_str() {
        "development" | "production" => {}
        other => {
            panic!(
                "GHALBOL_ENV must be development or production, got {:?}",
                other
            );
        }
    }

    let env_path = env_dir().join(format!("{ghalbol_env}.env"));
    println!("cargo:rerun-if-changed={}", env_path.display());
    println!("cargo:rerun-if-env-changed=GHALBOL_ENV");

    let mut vars: BTreeMap<String, String> = defaults(&ghalbol_env)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut file_ghalbol_env = String::new();
    if let Ok(text) = fs::read_to_string(&env_path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if key.is_empty() {
                continue;
            }
            let valid_key = key
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid_key {
                continue;
            }
            vars.insert(key.to_string(), value.to_string());
            if key == "GHALBOL_ENV" {
                file_ghalbol_env = value.to_string();
            }
        }
    } else if ghalbol_env == "production" {
        panic!(
            "GhalBol production env file missing at {} — refusing release bake with defaults",
            env_path.display()
        );
    } else {
        println!(
            "cargo:warning=GhalBol env file missing at {} — using built-in defaults",
            env_path.display()
        );
    }

    if !file_ghalbol_env.is_empty() && file_ghalbol_env != ghalbol_env {
        panic!(
            "GHALBOL_ENV in {} is {:?} but build selected {:?}",
            env_path.display(),
            file_ghalbol_env,
            ghalbol_env
        );
    }

    if ghalbol_env == "production" {
        for req in ["GHALBOL_APP_ID", "GHALBOL_APP_LABEL", "GHALBOL_COORD_URLS", "GHALBOL_DELIVERY_URL"]
        {
            let v = vars.get(req).map(String::as_str).unwrap_or("");
            if v.is_empty() {
                panic!(
                    "GhalBol production env file at {} missing required key {}",
                    env_path.display(),
                    req
                );
            }
        }
    }

    // Ensure ENV key matches the selected profile even if the file omits it.
    vars.insert("GHALBOL_ENV".into(), ghalbol_env.clone());

    // Production Windows PE: no console when the user double-clicks the exe.
    // Dev packages keep the console. Driven by GHALBOL_ENV, not Cargo profile
    // (Windows Dev packages also use --release — Cargo debug PE is huge).
    if ghalbol_env == "production" {
        println!("cargo:rustc-cfg=ghalbol_hide_console");
    }

    let baked: String = vars.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("ghalbol.env");
    fs::write(&out, baked).expect("write baked env");
    println!("cargo:rustc-env=GHALBOL_ENV={ghalbol_env}");
}
