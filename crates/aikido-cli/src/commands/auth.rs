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
use aikido_core::credentials::{CredentialStore, Credentials, SaveTarget, StoreSource};
use aikido_core::error::ApiError;
use aikido_core::session::{self, Session, TokenSource, CLIENT_ID_ENV, CLIENT_SECRET_ENV};
use serde_json::json;
use std::path::PathBuf;

use crate::output::{render_ok, Format, GlobalFlags, Response};

use super::issues::render_failure;

fn store() -> CredentialStore {
    CredentialStore::default()
}

pub async fn login(flags: &GlobalFlags) -> Result<(), ApiError> {
    let (client_id, client_secret) = credentials_from_env_or_prompt()?;

    let token = exchange_token(&base_url_from_env(), &client_id, &client_secret).await?;
    let expires_at = token.expires_at();

    let store = store();
    let target = store
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

    let summary = format!(
        "Authenticated successfully. Token expires at {expires_at}. {}",
        describe_save_target(&store, &target)
    );
    match flags.format() {
        Format::Styled => {
            eprintln!("{summary}");
            Ok(())
        }
        format => render_ok(
            &format,
            Response::new(json!({
                "expires_at": expires_at,
                "store": target.label(),
                "keychain_fallback": matches!(target, SaveTarget::FileAfterKeychainFailure(_)),
            }))
            .with_summary(summary),
            &[],
            None,
        )
        .map_err(render_failure),
    }
}

/// Say where the secret went. The default backend falls back to the
/// plaintext file when the keychain refuses the write; a login that reports
/// success without naming the backend hides exactly that.
fn describe_save_target(store: &CredentialStore, target: &SaveTarget) -> String {
    match target {
        SaveTarget::Keychain => "Credentials stored in the OS keychain.".to_string(),
        SaveTarget::File => format!(
            "Credentials stored in {} (owner-only file).",
            store.credentials_path().display()
        ),
        SaveTarget::FileAfterKeychainFailure(err) => format!(
            "WARNING: the OS keychain refused the write ({err}); credentials stored in the \
             plaintext file {} instead.",
            store.credentials_path().display()
        ),
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
    let report = match session::resolve(&store, flags.verbose) {
        Ok(session) => StatusReport::from_session(&store, session).await,
        Err(err) => StatusReport::unresolved(&err),
    };
    render_status(&flags.format(), report)
}

/// What `auth status` knows, gathered before any rendering so the styled
/// line and the JSON envelope can never disagree.
struct StatusReport {
    authenticated: bool,
    source: &'static str,
    expires_at: String,
    expired: bool,
    checked: bool,
    /// A plaintext credentials file that exists although the keychain was
    /// the backend read — left by an earlier keychain-to-file fallback.
    shadow_file: Option<PathBuf>,
    summary: String,
}

impl StatusReport {
    /// No credentials anywhere, or a credential store that failed (e.g. an
    /// unanswerable keychain prompt timing out). The two must not read the
    /// same: a store failure keeps its message.
    fn unresolved(err: &ApiError) -> Self {
        let message = err.to_string();
        let summary = if message == "not authenticated" {
            "Not authenticated. Run `aikido auth login` to authenticate.".to_string()
        } else {
            format!("Cannot read credentials: {message}")
        };
        Self {
            authenticated: false,
            source: "",
            expires_at: String::new(),
            expired: false,
            checked: false,
            shadow_file: None,
            summary,
        }
    }

    async fn from_session(store: &CredentialStore, session: Session) -> Self {
        let (source, shadow_file) = credential_source(store, &session);
        let expires_at = session.expires_at.clone().unwrap_or_default();
        let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
            .map(|t| t < chrono::Utc::now())
            .unwrap_or(false);
        let (authenticated, checked, check_note) = validate_token(&session.client).await;
        let mut report = Self {
            authenticated,
            source,
            expires_at,
            expired,
            checked,
            shadow_file,
            summary: String::new(),
        };
        report.summary = report.summary_line(&check_note);
        report
    }

    fn summary_line(&self, check_note: &str) -> String {
        let (source, expires_at) = (self.source, &self.expires_at);
        let mut summary = match (self.authenticated, self.checked) {
            (true, true) if self.expired => format!(
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
        if let Some(path) = &self.shadow_file {
            summary.push_str(&format!(
                ". A plaintext credentials file also exists at {} (left by an earlier keychain \
                 fallback); `aikido auth logout` removes both",
                path.display()
            ));
        }
        summary
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "authenticated": self.authenticated,
            "source": self.source,
            "expires_at": self.expires_at,
            "expired": self.expired,
            "checked": self.checked,
            "shadow_file": self.shadow_file,
        })
    }
}

/// Where the active token was read from, and any stale plaintext copy the
/// operator should know about. After a keychain-to-file fallback both
/// backends hold credentials; only the one actually read names the source,
/// and `auth logout` clears both.
fn credential_source(
    store: &CredentialStore,
    session: &Session,
) -> (&'static str, Option<PathBuf>) {
    let source = match (session.token_source, session.store_source) {
        (TokenSource::Env, _) => "env",
        (TokenSource::Store, Some(read_from)) => read_from.label(),
        // A stored token always comes with the backend that held it.
        (TokenSource::Store, None) => "store",
    };
    let shadow_file = match session.store_source {
        Some(StoreSource::Keychain) if store.file_exists() => Some(store.credentials_path()),
        _ => None,
    };
    (source, shadow_file)
}

/// One cheap authenticated call: `(authenticated, checked, note)`. The
/// client may transparently refresh on 401, which is exactly the recovery
/// worth exercising here.
async fn validate_token(client: &aikido_core::client::Client) -> (bool, bool, String) {
    match client
        .get(
            "/repositories/code",
            &[("per_page", "1".to_string()), ("page", "0".to_string())],
        )
        .await
    {
        Ok(_) => (true, true, String::new()),
        Err(ApiError::Auth { message }) => (false, true, message),
        Err(err) => (true, false, format!("validity not checked: {err}")),
    }
}

fn render_status(format: &Format, report: StatusReport) -> Result<(), ApiError> {
    if *format == Format::Styled {
        if report.authenticated || report.checked {
            println!("{}", report.summary);
        } else {
            eprintln!("{}", report.summary);
        }
        return Ok(());
    }
    render_ok(
        format,
        Response::new(report.to_json()).with_summary(report.summary),
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
