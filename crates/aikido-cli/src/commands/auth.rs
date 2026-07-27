//! `aikido auth` — login, status, logout.
//!
//! `auth status` never reports token presence as validity: when a token
//! exists it is validated with a cheap authenticated call
//! (`GET /repositories/code?per_page=1`). If the check cannot run (network
//! down), the output says plainly that validity is unchecked. The Go CLI
//! reported any set `AIKIDO_TOKEN` as `authenticated: true`, which masked a
//! revoked token for three weeks.

use std::io::{BufRead, Write};

use aikido_core::auth::exchange_token;
use aikido_core::client::base_url_from_env;
use aikido_core::credentials::{CredentialStore, Credentials};
use aikido_core::error::ApiError;
use aikido_core::session::{self, TokenSource, CLIENT_ID_ENV, CLIENT_SECRET_ENV};
use serde_json::json;

use crate::output::{render_ok, Format, GlobalFlags, Response};

use super::issues::render_failure;

fn store() -> CredentialStore {
    CredentialStore::default()
}

pub async fn login(flags: &GlobalFlags) -> Result<(), ApiError> {
    let (client_id, client_secret) = credentials_from_env_or_prompt()?;

    let token = exchange_token(&base_url_from_env(), &client_id, &client_secret).await?;
    let expires_at = token.expires_at();

    store()
        .save(&Credentials {
            client_id,
            client_secret,
            access_token: token.access_token,
            expires_at: expires_at.clone(),
        })
        .map_err(|err| ApiError::Api {
            status: 0,
            message: format!("save credentials: {err:#}"),
        })?;

    let summary = format!("Authenticated successfully. Token expires at {expires_at}");
    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => render_ok(
            &format,
            Response::new(json!({ "expires_at": expires_at })).with_summary(summary),
            &[],
            None,
        )
        .map_err(render_failure),
    }
}

fn credentials_from_env_or_prompt() -> Result<(String, String), ApiError> {
    let env_id = std::env::var(CLIENT_ID_ENV).unwrap_or_default();
    let env_secret = std::env::var(CLIENT_SECRET_ENV).unwrap_or_default();
    if !env_id.is_empty() && !env_secret.is_empty() {
        return Ok((env_id, env_secret));
    }

    let prompt = |label: &str| -> Result<String, ApiError> {
        eprint!("{label}: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|err| ApiError::Api {
                status: 0,
                message: format!("read {label}: {err}"),
            })?;
        Ok(line.trim().to_string())
    };

    let client_id = prompt("Client ID")?;
    let client_secret = prompt("Client Secret")?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(ApiError::Api {
            status: 0,
            message: "client ID and secret are required".to_string(),
        });
    }
    Ok((client_id, client_secret))
}

pub async fn status(flags: &GlobalFlags) -> Result<(), ApiError> {
    let store = store();
    let format = flags.format();

    let session = match session::resolve(&store, flags.verbose) {
        Ok(session) => session,
        Err(_) => {
            // No credentials anywhere.
            let data = json!({
                "authenticated": false,
                "source": "",
                "expires_at": "",
                "expired": false,
                "checked": false,
            });
            if format == Format::Styled {
                eprintln!("Not authenticated. Run `aikido auth login` to authenticate.");
                return Ok(());
            }
            return render_ok(&format, Response::new(data), &[], None).map_err(render_failure);
        }
    };

    let source = match session.token_source {
        TokenSource::Env => "env".to_string(),
        TokenSource::Store => {
            if store.file_exists() {
                "file".to_string()
            } else {
                "keyring".to_string()
            }
        }
    };

    let expires_at = session.expires_at.clone().unwrap_or_default();
    let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|t| t < chrono::Utc::now())
        .unwrap_or(false);

    // Validity check: one cheap authenticated call. The client itself may
    // transparently refresh on 401, which is exactly the recovery we want to
    // exercise.
    let (authenticated, checked, check_note) = match session
        .client
        .get("/repositories/code", &[("per_page", "1".to_string()), ("page", "0".to_string())])
        .await
    {
        Ok(_) => (true, true, String::new()),
        Err(ApiError::Auth { message }) => (false, true, message),
        Err(err) => (true, false, format!("validity not checked: {err}")),
    };

    let summary = match (authenticated, checked) {
        (true, true) if expired => format!(
            "Authenticated (source: {source}); stored expiry {expires_at} has passed but the token refreshed"
        ),
        (true, true) if expires_at.is_empty() => {
            format!("Authenticated (source: {source}, verified with a live API call)")
        }
        (true, true) => {
            format!("Authenticated (source: {source}, expires: {expires_at}, verified)")
        }
        (false, true) => format!("Token invalid (source: {source}): {check_note}"),
        _ => format!("Credentials present (source: {source}) — {check_note}"),
    };

    let data = json!({
        "authenticated": authenticated,
        "source": source,
        "expires_at": expires_at,
        "expired": expired,
        "checked": checked,
    });

    if format == Format::Styled {
        println!("{summary}");
        return Ok(());
    }
    render_ok(&format, Response::new(data).with_summary(summary), &[], None)
        .map_err(render_failure)
}

pub fn logout(flags: &GlobalFlags) -> Result<(), ApiError> {
    store().clear().map_err(|err| ApiError::Api {
        status: 0,
        message: format!("logout failed: {err:#}"),
    })?;
    let summary = "Logged out successfully.";
    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => render_ok(&format, Response::summary_only(summary), &[], None)
            .map_err(render_failure),
    }
}
