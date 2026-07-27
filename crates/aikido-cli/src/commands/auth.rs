//! `aikido auth` — login, status, logout.
//!
//! `auth status` never reports token presence as validity: when a token
//! exists it is validated with a cheap authenticated call
//! (`GET /repositories/code?per_page=1`). If the check cannot run (network
//! down), the output says plainly that validity is unchecked. The Go CLI
//! reported any set `AIKIDO_TOKEN` as `authenticated: true`, which masked a
//! revoked token for three weeks.

use std::io::{BufRead, IsTerminal, Write};

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

/// Where `auth login` gets the client credentials, in precedence order:
/// env vars (announced on stderr so a stale export is never silent), then an
/// interactive prompt when stdin is a TTY (secret read without echo), then
/// two lines piped on stdin. Empty/EOF stdin fails with the alternatives
/// spelled out instead of the Go CLI's bare "EOF".
fn credentials_from_env_or_prompt() -> Result<(String, String), ApiError> {
    let env_id = std::env::var(CLIENT_ID_ENV).unwrap_or_default();
    let env_secret = std::env::var(CLIENT_SECRET_ENV).unwrap_or_default();
    if !env_id.is_empty() && !env_secret.is_empty() {
        eprintln!(
            "Using client credentials from {CLIENT_ID_ENV}/{CLIENT_SECRET_ENV} \
             environment variables (unset them to be prompted)."
        );
        return Ok((env_id, env_secret));
    }

    let (client_id, client_secret) = if std::io::stdin().is_terminal() {
        prompt_interactive()?
    } else {
        read_piped_credentials()?
    };

    if client_id.is_empty() || client_secret.is_empty() {
        return Err(missing_credentials_error());
    }
    Ok((client_id, client_secret))
}

/// Interactive prompt: client ID echoed, secret read without echo.
fn prompt_interactive() -> Result<(String, String), ApiError> {
    eprint!("Client ID: ");
    std::io::stderr().flush().ok();
    let mut client_id = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut client_id)
        .map_err(|err| ApiError::auth(format!("read client ID: {err}")))?;

    let client_secret = rpassword::prompt_password("Client Secret (hidden): ")
        .map_err(|err| ApiError::auth(format!("read client secret: {err}")))?;

    Ok((
        client_id.trim().to_string(),
        client_secret.trim().to_string(),
    ))
}

/// Scripted login: two lines on stdin — client ID, then client secret.
fn read_piped_credentials() -> Result<(String, String), ApiError> {
    let mut lines = std::io::stdin().lock().lines();
    let mut next_line = || -> Result<String, ApiError> {
        match lines.next() {
            Some(Ok(line)) => Ok(line.trim().to_string()),
            Some(Err(err)) => Err(ApiError::auth(format!(
                "read credentials from stdin: {err}"
            ))),
            None => Err(missing_credentials_error()),
        }
    };
    let client_id = next_line()?;
    let client_secret = next_line()?;
    Ok((client_id, client_secret))
}

fn missing_credentials_error() -> ApiError {
    ApiError::auth(
        "no client credentials provided. Run `aikido auth login` in an interactive terminal, \
         set AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET, or pipe two lines to stdin \
         (client ID, then client secret)",
    )
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
        .get(
            "/repositories/code",
            &[("per_page", "1".to_string()), ("page", "0".to_string())],
        )
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
    render_ok(
        &format,
        Response::new(data).with_summary(summary),
        &[],
        None,
    )
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
        format => {
            render_ok(&format, Response::summary_only(summary), &[], None).map_err(render_failure)
        }
    }
}
