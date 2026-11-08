//! Ghal Bol delivery server binary.

use axum_server::tls_rustls::RustlsConfig;
use ghalbol_delivery::{
    AppState, DeliveryConfig, app, export_mailbox, import_mailbox, mailbox_stats,
};
use ghalbol_ddns::{DdnsConfig, spawn_ddns_task};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("export-mailbox") => return run_export_mailbox(&args),
        Some("import-mailbox") => return run_import_mailbox(&args),
        Some("mailbox-stats") => return run_mailbox_stats(),
        _ => run_server().await,
    }
}

fn run_export_mailbox(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out = parse_flag(args, "--out").ok_or("--out required")?;
    let config = DeliveryConfig::from_env();
    export_mailbox(&config, std::path::Path::new(&out))?;
    println!("exported mailbox to {out}");
    Ok(())
}

fn run_import_mailbox(args: &[String]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let input = parse_flag(args, "--in").ok_or("--in required")?;
    let replace = args.iter().any(|a| a == "--replace");
    let config = DeliveryConfig::from_env();
    let stats = import_mailbox(&config, std::path::Path::new(&input), replace)?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn run_mailbox_stats() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = DeliveryConfig::from_env();
    let stats = mailbox_stats(&config)?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .filter(|s| !s.is_empty())
}

async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = DeliveryConfig::from_env();
    let state = AppState::new(config.clone())?;
    let ddns_shutdown = Arc::new(Notify::new());

    let tls = config.tls_cert.as_ref().zip(config.tls_key.as_ref());
    if let Some((cert, key)) = &tls {
        if !cert.is_file() {
            return Err(format!("TLS cert not found: {}", cert.display()).into());
        }
        if !key.is_file() {
            return Err(format!("TLS key not found: {}", key.display()).into());
        }
    }

    let ddns = DdnsConfig::from_env().map(|cfg| spawn_ddns_task(cfg, Arc::clone(&ddns_shutdown)));
    let router = app(state.clone());
    tracing::info!(
        listen = %config.listen,
        tls = tls.is_some(),
        data_dir = %config.data_dir.display(),
        instance_id = %ghalbol_delivery::instance_id(),
        min_ttl_secs = config.min_ttl_secs,
        max_ttl_secs = config.max_ttl_secs,
        quota_bytes = config.quota_bytes_per_peer,
        max_connections = config.max_connections,
        "ghalbol_delivery listening"
    );

    let serve_result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        if let Some((cert, key)) = tls {
            let tls_config = RustlsConfig::from_pem_file(cert, key).await?;
            let handle = axum_server::Handle::new();
            let signal_handle = handle.clone();
            let signal_state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(e) = wait_for_os_shutdown().await {
                    tracing::error!(error = %e, "failed to listen for shutdown signal");
                    return;
                }
                tracing::info!("shutdown signal received");
                signal_state.shutdown.signal();
                signal_handle.graceful_shutdown(Some(Duration::from_secs(15)));
            });
            axum_server::bind_rustls(config.listen, tls_config)
                .handle(handle)
                .serve(router.into_make_service())
                .await
                .map_err(|e| e.into())
        } else {
            let listener = TcpListener::bind(config.listen).await?;
            let signal_state = Arc::clone(&state);
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    if let Err(e) = wait_for_os_shutdown().await {
                        tracing::error!(error = %e, "failed to listen for shutdown signal");
                        return;
                    }
                    tracing::info!("shutdown signal received");
                    signal_state.shutdown.signal();
                })
                .await
                .map_err(|e| e.into())
        };

    if let Err(e) = state.store.checkpoint() {
        tracing::warn!(error = %e, "wal checkpoint on shutdown failed");
    }
    ddns_shutdown.notify_waiters();
    if let Some(handle) = ddns {
        let _ = handle.await;
    }
    tracing::info!("ghalbol_delivery stopped");
    serve_result
}

async fn wait_for_os_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
