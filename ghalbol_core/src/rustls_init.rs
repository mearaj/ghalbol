//! Process-wide rustls 0.23 crypto provider (required before TLS/WSS).

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install aws-lc-rs as the default rustls `CryptoProvider` once per process.
pub fn ensure_rustls_crypto_provider() {
    INSTALL.call_once(|| {
        // Already-installed (tests / double start) is fine — do not panic the process.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::ensure_rustls_crypto_provider;

    #[test]
    fn ensure_rustls_is_idempotent() {
        ensure_rustls_crypto_provider();
        ensure_rustls_crypto_provider();
    }
}
