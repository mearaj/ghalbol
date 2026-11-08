//! Thin cargo entrypoint for `cargo ghalbol-dev`.
//! Delegates to `apps/ghalbol/scripts/dev.sh` (loads apps/ghalbol/env/development.env).
//!
//! Usage:
//!   cargo ghalbol-dev         # Development build with hot reload + Tweaker (F12)

use std::env;
use std::path::PathBuf;
use std::process::{Command, exit};

fn main() {
    let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR").map(PathBuf::from) else {
        eprintln!("CARGO_MANIFEST_DIR unset");
        exit(1);
    };
    let Some(root) = manifest_dir.parent().and_then(|p| p.parent()) else {
        eprintln!("tools/ghalbol-dev: cannot resolve workspace root");
        exit(1);
    };
    let script = root.join("apps/ghalbol/scripts/dev.sh");
    if !script.is_file() {
        eprintln!("missing {}", script.display());
        exit(1);
    }
    let mut cmd = Command::new("bash");
    cmd.arg(&script);
    cmd.args(env::args().skip(1));
    cmd.current_dir(root);
    match cmd.status() {
        Ok(status) => exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("failed to run {}: {err}", script.display());
            exit(1);
        }
    }
}
