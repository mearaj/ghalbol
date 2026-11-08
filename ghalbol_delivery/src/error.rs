use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    QuotaExceeded(String),
    #[error("{0}")]
    TtlInvalid(String),
    #[error("{0}")]
    Expired(String),
    #[error("{0}")]
    InvalidEnvelope(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, DeliveryError>;

impl DeliveryError {
    pub fn ws_code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::QuotaExceeded(_) => "quota_exceeded",
            Self::InvalidEnvelope(_) => "invalid_envelope",
            Self::NotFound(_) => "not_found",
            Self::TtlInvalid(_) => "ttl_invalid",
            Self::Expired(_) => "expired",
            Self::BadRequest(_) => "bad_request",
            _ => "error",
        }
    }

    /// Text safe to return to a peer. Database and internal details stay in the log.
    pub fn client_message(&self) -> String {
        let raw = match self {
            Self::Db(_) | Self::Internal(_) | Self::Io(_) => return "internal error".to_string(),
            other => other.to_string(),
        };
        const MAX_CHARS: usize = 240;
        if raw.chars().count() <= MAX_CHARS {
            raw
        } else {
            let trimmed: String = raw.chars().take(MAX_CHARS).collect();
            format!("{trimmed}…")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_are_not_echoed_to_clients() {
        let err = DeliveryError::Internal("db path /var/lib/secret".into());
        assert_eq!(err.client_message(), "internal error");
        let long = DeliveryError::BadRequest("x".repeat(500));
        assert!(long.client_message().chars().count() <= 241);
    }
}
