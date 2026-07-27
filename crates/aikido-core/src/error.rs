//! Structured API errors carrying the stable machine-readable `code` and
//! recovery `hint` that the CLI's JSON error envelope exposes.

/// Error from the Aikido API or the transport underneath it.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{message}")]
    Auth { message: String },

    #[error("{message}")]
    NotFound { message: String },

    #[error("rate limited")]
    RateLimit,

    #[error("{message}")]
    Api { status: u16, message: String },

    #[error("http request: {0}")]
    Transport(#[from] reqwest::Error),
}

impl ApiError {
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    /// The stable error code used in the CLI's JSON error envelope.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth { .. } => "auth_error",
            Self::NotFound { .. } => "not_found",
            Self::RateLimit => "rate_limit",
            Self::Api { .. } | Self::Transport(_) => "api_error",
        }
    }

    /// Recovery hint shown alongside the error, when one exists.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Auth { .. } => Some("Run: aikido auth login"),
            Self::RateLimit => Some("Wait and retry"),
            _ => None,
        }
    }
}
