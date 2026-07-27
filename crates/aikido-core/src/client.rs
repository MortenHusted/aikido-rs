//! Authenticated HTTP client for the Aikido public API
//! (`{base}/api/public/v1`).
//!
//! On a 401 the client exchanges its OAuth client credentials for a fresh
//! access token, persists that token (and its new expiry) back to the
//! credential store, and retries the request once. The Go CLI this replaces
//! refreshed only in memory, so every process start burned a wasted 401 and
//! the stored expiry froze — persisting here is deliberate, not optional.
//!
//! Policy (this CLI feeds an unattended scheduled job — it must fail rather
//! than hang, and ride out transient throttling):
//! - connect timeout 10s, total request timeout 30s;
//! - at most 2 retries with exponential backoff. GETs retry on connect
//!   errors, 429 (honouring `Retry-After`, capped), and 502/503/504.
//!   Mutations (PUT/POST) retry only where a replay is provably safe: 429
//!   (the server rejected the request without processing it) and connect
//!   errors (the request never went out). An ambiguous 502/504 on a
//!   mutation is surfaced, not replayed.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::auth;
use crate::credentials::CredentialStore;
use crate::error::ApiError;

pub const DEFAULT_BASE_URL: &str = "https://app.aikido.dev";
pub const BASE_URL_ENV: &str = "AIKIDO_BASE_URL";

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 2;
const RETRY_AFTER_CAP: Duration = Duration::from_secs(10);

/// HTTP client with the connect timeout applied — shared with the token
/// exchange path so nothing in this crate can hang indefinitely.
pub(crate) fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .expect("constructing HTTP client")
}

/// The Aikido base URL, honouring the `AIKIDO_BASE_URL` override
/// (used by tests to point at a mock server).
pub fn base_url_from_env() -> String {
    std::env::var(BASE_URL_ENV)
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
}

/// OAuth client credentials enabling 401 auto-refresh.
#[derive(Debug, Clone)]
pub struct RefreshCredentials {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug)]
pub struct Client {
    base_url: String,
    http: reqwest::Client,
    /// Interior mutability: a 401 refresh swaps the token mid-request.
    token: Mutex<String>,
    refresh: Option<RefreshCredentials>,
    /// Where a refreshed token is persisted. `None` skips persistence
    /// (e.g. when no credentials were ever stored).
    store: Option<CredentialStore>,
    request_timeout: Duration,
    verbose: bool,
}

impl Client {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: http_client(),
            token: Mutex::new(token.into()),
            refresh: None,
            store: None,
            request_timeout: REQUEST_TIMEOUT,
            verbose: false,
        }
    }

    /// Override the total request timeout (tests use a short one to prove
    /// the client fails instead of hanging).
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Attach OAuth client credentials so 401s auto-refresh. Any client that
    /// has credentials available must carry them, whatever the token source —
    /// a revoked env token must still be recoverable.
    pub fn with_refresh(mut self, refresh: RefreshCredentials) -> Self {
        self.refresh = Some(refresh);
        self
    }

    /// Persist refreshed tokens (and their expiry) to `store`.
    pub fn with_store(mut self, store: CredentialStore) -> Self {
        self.store = Some(store);
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/public/v1{}", self.base_url, path)
    }

    fn current_token(&self) -> String {
        self.token.lock().expect("token mutex poisoned").clone()
    }

    /// GET with optional query parameters.
    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, ApiError> {
        self.request(reqwest::Method::GET, path, query, None).await
    }

    /// PUT with a JSON body.
    pub async fn put(&self, path: &str, body: Value) -> Result<Value, ApiError> {
        self.request(reqwest::Method::PUT, path, &[], Some(body))
            .await
    }

    /// POST with a JSON body.
    pub async fn post(&self, path: &str, body: Value) -> Result<Value, ApiError> {
        self.request(reqwest::Method::POST, path, &[], Some(body))
            .await
    }

    /// POST with query parameters and no body (scan trigger, expects 204).
    pub async fn post_no_content(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<(), ApiError> {
        self.request(reqwest::Method::POST, path, query, None)
            .await?;
        Ok(())
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value, ApiError> {
        let url = self.api_url(path);
        let response = self.send(&method, &url, query, body.as_ref()).await?;

        // On 401, refresh the token via client credentials, persist it, and
        // retry once.
        let response =
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && self.refresh.is_some() {
                self.refresh_token().await?;
                self.send(&method, &url, query, body.as_ref()).await?
            } else {
                response
            };

        parse_response(response).await
    }

    /// Issue the request, retrying at most [`MAX_RETRIES`] times per the
    /// module-level policy (429 honours `Retry-After`; only GETs retry the
    /// ambiguous 502/504 statuses).
    async fn send(
        &self,
        method: &reqwest::Method,
        url: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<reqwest::Response, ApiError> {
        let mut attempt: u32 = 0;
        loop {
            let mut request = self
                .http
                .request(method.clone(), url)
                .timeout(self.request_timeout)
                .bearer_auth(self.current_token());
            if !query.is_empty() {
                request = request.query(query);
            }
            if let Some(body) = body {
                request = request.json(body);
            }
            if self.verbose {
                eprintln!("--> {method} {url}");
            }
            match request.send().await {
                Ok(response) => {
                    if self.verbose {
                        eprintln!("<-- {}", response.status().as_u16());
                    }
                    let status = response.status();
                    if attempt < MAX_RETRIES && retryable(method, status) {
                        let delay = retry_after(&response).unwrap_or_else(|| backoff(attempt));
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Ok(response);
                }
                // A connect error means the request never went out, so a
                // retry is safe for mutations too.
                Err(err) if err.is_connect() && attempt < MAX_RETRIES => {
                    tokio::time::sleep(backoff(attempt)).await;
                    attempt += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Exchange client credentials for a fresh access token, swap it into
    /// this client, and persist it (with its new expiry) to the store.
    async fn refresh_token(&self) -> Result<(), ApiError> {
        let refresh = self
            .refresh
            .as_ref()
            .expect("refresh_token without credentials");
        let token =
            auth::exchange_token(&self.base_url, &refresh.client_id, &refresh.client_secret)
                .await?;

        *self.token.lock().expect("token mutex poisoned") = token.access_token.clone();

        if let Some(store) = &self.store {
            // Update the stored access token in place, preserving whatever
            // client credentials the store already holds. Persistence is
            // best-effort: a store failure must not fail the API call.
            let mut creds = store.load().ok().flatten().unwrap_or_default();
            if creds.client_id.is_empty() {
                creds.client_id = refresh.client_id.clone();
                creds.client_secret = refresh.client_secret.clone();
            }
            creds.access_token = token.access_token.clone();
            creds.expires_at = token.expires_at();
            if let Err(err) = store.save(&creds) {
                eprintln!("Warning: could not persist refreshed token: {err:#}");
            }
        }
        Ok(())
    }
}

/// Whether `status` may be retried for `method` — see the module policy.
fn retryable(method: &reqwest::Method, status: reqwest::StatusCode) -> bool {
    match status.as_u16() {
        // The server refused without processing — safe for any method.
        429 => true,
        // Ambiguous whether the origin processed the request — only replay
        // reads.
        502..=504 => *method == reqwest::Method::GET,
        _ => false,
    }
}

/// 250ms, then 500ms.
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250u64 << attempt)
}

/// `Retry-After` in seconds, capped so a hostile/buggy header cannot stall
/// the unattended job.
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let secs: u64 = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(secs).min(RETRY_AFTER_CAP))
}

/// Map a response to its JSON body or a structured [`ApiError`].
async fn parse_response(response: reqwest::Response) -> Result<Value, ApiError> {
    let status = response.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }

    if status.is_success() {
        // A malformed 2xx body must be an error, never silently `null` —
        // the scheduled security loop would read fabricated emptiness as
        // "no findings" and report all-clear. An entirely absent body is
        // fine (like 204); garbage is not.
        let text = response.text().await.map_err(ApiError::Transport)?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        return serde_json::from_str(&text).map_err(|err| ApiError::Api {
            status: status.as_u16(),
            message: format!("response claimed success but its body is not valid JSON: {err}"),
        });
    }

    let body: Value = response.json().await.unwrap_or(Value::Null);

    // Aikido error bodies carry a human-readable `reason_phrase`.
    let reason = body
        .get("reason_phrase")
        .and_then(Value::as_str)
        .map(str::to_string);

    Err(match status {
        reqwest::StatusCode::UNAUTHORIZED => ApiError::Auth {
            message: reason.unwrap_or_else(|| "unauthorized".to_string()),
        },
        reqwest::StatusCode::NOT_FOUND => ApiError::NotFound {
            message: reason.unwrap_or_else(|| "resource not found".to_string()),
        },
        reqwest::StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimit,
        _ => ApiError::Api {
            status: status.as_u16(),
            message: reason
                .unwrap_or_else(|| format!("request failed with status {}", status.as_u16())),
        },
    })
}
