//! OAuth2 `client_credentials` token exchange against the Aikido token
//! endpoint (`{base}/api/oauth/token`).

use serde::Deserialize;

use crate::error::ApiError;

#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds.
    pub expires_in: i64,
}

impl TokenResponse {
    /// Absolute expiry as an RFC3339 timestamp, computed from `expires_in`.
    /// Empty when the server's lifetime does not fit a timestamp: the stored
    /// `expires_at` field already documents empty as "unknown", and a server
    /// value must never be able to panic the client.
    pub fn expires_at(&self) -> String {
        chrono::TimeDelta::try_seconds(self.expires_in)
            .and_then(|lifetime| chrono::Utc::now().checked_add_signed(lifetime))
            .map(|expiry| expiry.to_rfc3339())
            .unwrap_or_default()
    }
}

/// Exchange OAuth client credentials for a short-lived access token.
pub async fn exchange_token(
    base_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, ApiError> {
    let url = format!("{}/api/oauth/token", base_url.trim_end_matches('/'));
    // Same timeout policy as the API client — the exchange also runs inside
    // the unattended scheduled job and must fail rather than hang. Never
    // retried: the 401-refresh path that calls this is itself the retry.
    let response = crate::client::http_client()
        .post(&url)
        .timeout(crate::client::REQUEST_TIMEOUT)
        .basic_auth(client_id, Some(client_secret))
        .json(&serde_json::json!({ "grant_type": "client_credentials" }))
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
        let message = body
            .get("reason_phrase")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("authentication failed")
            .to_string();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ApiError::Auth { message });
        }
        return Err(ApiError::Api {
            status: status.as_u16(),
            message,
        });
    }

    response
        .json::<TokenResponse>()
        .await
        .map_err(|err| ApiError::Api {
            status: status.as_u16(),
            message: format!("decode token response: {err}"),
        })
}
