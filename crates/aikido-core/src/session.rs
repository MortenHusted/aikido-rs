//! Resolve the authenticated [`Client`] from the environment and the
//! credential store — the single code path both the CLI and the MCP server
//! use, so token-source precedence can never diverge between them.
//!
//! Precedence: `AIKIDO_TOKEN` > stored access token. Client credentials
//! (`AIKIDO_CLIENT_ID`/`AIKIDO_CLIENT_SECRET` > stored) are attached to the
//! client whenever they are available, regardless of where the token came
//! from, so the 401 auto-refresh always works — an env token with no attached
//! credentials was the Go CLI's unrecoverable-failure bug.

use crate::client::{base_url_from_env, Client, RefreshCredentials};
use crate::credentials::CredentialStore;
use crate::error::ApiError;

pub const TOKEN_ENV: &str = "AIKIDO_TOKEN";
pub const CLIENT_ID_ENV: &str = "AIKIDO_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "AIKIDO_CLIENT_SECRET";

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Where the active access token came from — reported by `auth status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Env,
    Store,
}

impl TokenSource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Store => "store",
        }
    }
}

/// A resolved client plus where its token came from.
#[derive(Debug)]
pub struct Session {
    pub client: Client,
    pub token_source: TokenSource,
    /// Stored expiry (RFC3339) when the token came from the store.
    pub expires_at: Option<String>,
}

/// Build the authenticated client, or `Err(auth_error)` when no credential
/// source exists. `verbose` enables request logging on stderr.
pub fn resolve(store: &CredentialStore, verbose: bool) -> Result<Session, ApiError> {
    let base_url = base_url_from_env();
    let env_token = non_empty_env(TOKEN_ENV);
    let env_refresh = match (
        non_empty_env(CLIENT_ID_ENV),
        non_empty_env(CLIENT_SECRET_ENV),
    ) {
        (Some(client_id), Some(client_secret)) => Some(RefreshCredentials {
            client_id,
            client_secret,
        }),
        _ => None,
    };

    // Consult the store only when the env doesn't fully configure the run —
    // a keychain that hangs or fails must never take down a run that didn't
    // need it, and never silently masquerade as "not authenticated".
    let stored = if env_token.is_some() && env_refresh.is_some() {
        None
    } else {
        match store.load() {
            Ok(stored) => stored,
            Err(err) if env_token.is_some() => {
                // An env token can proceed without stored refresh
                // credentials; degrade with a warning instead of dying.
                eprintln!("Warning: could not read stored credentials: {err:#}");
                None
            }
            Err(err) => return Err(ApiError::auth(format!("{err:#}"))),
        }
    };

    // Client credentials: env wins, else whatever the store holds.
    let refresh = env_refresh.or_else(|| {
        stored
            .as_ref()
            .filter(|creds| !creds.client_id.is_empty() && !creds.client_secret.is_empty())
            .map(|creds| RefreshCredentials {
                client_id: creds.client_id.clone(),
                client_secret: creds.client_secret.clone(),
            })
    });

    let (token, token_source, expires_at) = if let Some(token) = env_token {
        (token, TokenSource::Env, None)
    } else if let Some(creds) = &stored {
        // An empty stored access token is fine when refresh credentials
        // exist: the first request 401s and the refresh path mints one.
        if creds.access_token.is_empty() && refresh.is_none() {
            return Err(ApiError::auth("not authenticated"));
        }
        (
            creds.access_token.clone(),
            TokenSource::Store,
            Some(creds.expires_at.clone()).filter(|s| !s.is_empty()),
        )
    } else if refresh.is_some() {
        // Credentials from env only; token minted on first 401.
        (String::new(), TokenSource::Env, None)
    } else {
        return Err(ApiError::auth("not authenticated"));
    };

    let mut client = Client::new(base_url, token).with_verbose(verbose);
    if let Some(refresh) = refresh {
        client = client.with_refresh(refresh);
        // Persist refreshed tokens only when the store already holds
        // credentials — never write env-provided secrets to disk as a side
        // effect of an API call.
        if stored.is_some() {
            client = client.with_store(store.clone());
        }
    }

    Ok(Session {
        client,
        token_source,
        expires_at,
    })
}
