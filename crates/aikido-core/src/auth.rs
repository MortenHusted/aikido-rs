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
    pub fn expires_at(&self) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(self.expires_in)).to_rfc3339()
    }
}

/// Exchange OAuth client credentials for a short-lived access token.
pub async fn exchange_token(
    base_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, ApiError> {
    let url = format!("{}/api/oauth/token", base_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(&url)
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
