//! Client errors.

use thiserror::Error;

/// Client-side failures.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Configuration / credentials problem.
    #[error("config: {0}")]
    Config(String),
    /// Not authenticated.
    #[error("not logged in; run `sh auth login`")]
    NotLoggedIn,
    /// HTTP / transport.
    #[error("http: {0}")]
    Http(String),
    /// API returned an error status.
    #[error("api {status}: {body}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: String,
    },
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    /// Crypto.
    #[error(transparent)]
    Crypto(#[from] safehub_crypto::CryptoError),
    /// AEAD.
    #[error(transparent)]
    Aead(#[from] safehub_crypto::AeadError),
    /// Other.
    #[error("{0}")]
    Other(String),
}

impl ClientError {
    /// True when the server rejected a head append due to CAS conflict (HTTP 409).
    pub fn is_cas_conflict(&self) -> bool {
        matches!(self, ClientError::Api { status: 409, .. })
            || matches!(self, ClientError::Api { body, .. } if body.contains("cas conflict"))
    }
}
