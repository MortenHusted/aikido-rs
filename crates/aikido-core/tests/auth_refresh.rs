//! The 401 → refresh → persist → retry cycle. These tests exist because the
//! Go CLI shipped three auth defects: env tokens without attached refresh
//! credentials (unrecoverable 401), refreshed tokens never persisted (wasted
//! 401 + token exchange on every process start, frozen expires_at), and
//! `auth status` equating presence with validity. The first two are covered
//! here; the third in the CLI tests.

use aikido_core::api::{self, IssueFilters};
use aikido_core::auth;
use aikido_core::client::{Client, RefreshCredentials};
use aikido_core::credentials::{CredentialStore, Credentials};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn refresh_creds() -> RefreshCredentials {
    RefreshCredentials {
        client_id: "test-client-id".into(),
        client_secret: "test-client-secret".into(),
    }
}

/// Mounts the OAuth token endpoint: Basic auth for the test credentials,
/// `client_credentials` grant, returning `fresh-token` valid for 3600s.
async fn mount_token_endpoint(server: &MockServer, expected_calls: u64) {
    // base64("test-client-id:test-client-secret")
    let basic = "Basic dGVzdC1jbGllbnQtaWQ6dGVzdC1jbGllbnQtc2VjcmV0";
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .and(header("authorization", basic))
        .and(body_json(json!({ "grant_type": "client_credentials" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(expected_calls)
        .mount(server)
        .await;
}

#[tokio::test]
async fn token_exchange_sends_basic_auth_and_parses_response() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server, 1).await;

    let token = auth::exchange_token(&server.uri(), "test-client-id", "test-client-secret")
        .await
        .unwrap();
    assert_eq!(token.access_token, "fresh-token");
    assert_eq!(token.expires_in, 3600);

    // expires_at is an absolute RFC3339 timestamp ~3600s out.
    let expires_at = chrono::DateTime::parse_from_rfc3339(&token.expires_at()).unwrap();
    let delta = expires_at.timestamp() - chrono::Utc::now().timestamp();
    assert!((3590..=3610).contains(&delta), "unexpected expiry delta {delta}");
}

#[tokio::test]
async fn token_exchange_surfaces_reason_phrase_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "invalid client credentials"
        })))
        .mount(&server)
        .await;

    let err = auth::exchange_token(&server.uri(), "bad", "creds")
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth_error");
    assert_eq!(err.to_string(), "invalid client credentials");
}

/// Bug 2 (client.go:111-113): the refreshed token must be persisted with its
/// new expiry, not just swapped in memory.
#[tokio::test]
async fn refresh_on_401_persists_new_token_and_expiry_to_the_store() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server, 1).await;

    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer stale-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "token expired"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer fresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(2) // the post-refresh retry + the fresh-process client below
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::file_at(dir.path());
    store
        .save(&Credentials {
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            access_token: "stale-token".into(),
            expires_at: "2020-01-01T00:00:00Z".into(),
        })
        .unwrap();

    let client = Client::new(server.uri(), "stale-token")
        .with_refresh(refresh_creds())
        .with_store(store.clone());

    let issues = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap();
    assert!(issues.is_empty());

    // The store now holds the fresh token, a moved expiry, and untouched
    // client credentials.
    let persisted = store.load().unwrap().expect("credentials persisted");
    assert_eq!(persisted.access_token, "fresh-token");
    assert_eq!(persisted.client_id, "test-client-id");
    assert_eq!(persisted.client_secret, "test-client-secret");
    assert_ne!(persisted.expires_at, "2020-01-01T00:00:00Z", "expiry must move");
    let expires_at = chrono::DateTime::parse_from_rfc3339(&persisted.expires_at).unwrap();
    assert!(expires_at.timestamp() > chrono::Utc::now().timestamp() + 3000);

    // A second client reading the store starts with the fresh token — no
    // wasted 401 + exchange per process start.
    let persisted_client = Client::new(server.uri(), persisted.access_token.clone());
    let again = api::list_issues(&persisted_client, &IssueFilters::default(), None)
        .await
        .unwrap();
    assert!(again.is_empty());
}

/// Bug 1 (root.go:55): a client built from an env token still carries client
/// credentials, so a revoked env token recovers via refresh instead of
/// failing hard.
#[tokio::test]
async fn revoked_env_token_recovers_when_refresh_credentials_are_attached() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server, 1).await;

    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer revoked-env-token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "token revoked"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer fresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "id": 1 }])))
        .expect(1)
        .mount(&server)
        .await;

    // Env-token path: refresh credentials attached, but no store — env
    // secrets must never be written to disk as a side effect.
    let client = Client::new(server.uri(), "revoked-env-token").with_refresh(refresh_creds());

    let issues = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap();
    assert_eq!(issues.len(), 1);
}

#[tokio::test]
async fn refresh_failure_reports_auth_error_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "token revoked"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "client credentials revoked"
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "revoked").with_refresh(refresh_creds());
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth_error");
    assert_eq!(err.to_string(), "client credentials revoked");
}

/// A 401 on the retried request (refresh succeeded but the API still refuses)
/// must not loop — exactly one refresh, then the auth error surfaces.
#[tokio::test]
async fn retry_after_refresh_happens_exactly_once() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server, 1).await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "still refused"
        })))
        .expect(2) // original + single retry, never more
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "whatever").with_refresh(refresh_creds());
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth_error");
}

// ---------------------------------------------------------------------------
// Credential store
// ---------------------------------------------------------------------------

#[test]
fn store_round_trips_the_go_wire_format() {
    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::file_at(dir.path());

    // A file written by the Go CLI parses as-is.
    let go_shape = r#"{"client_id":"id","client_secret":"sec","access_token":"tok","expires_at":"2026-01-01T00:00:00Z"}"#;
    std::fs::write(store.credentials_path(), go_shape).unwrap();
    let creds = store.load().unwrap().unwrap();
    assert_eq!(creds.client_id, "id");
    assert_eq!(creds.access_token, "tok");

    // Saving writes the same four keys back, in the Go field order.
    store.save(&creds).unwrap();
    let raw = std::fs::read_to_string(store.credentials_path()).unwrap();
    let positions: Vec<usize> = ["client_id", "client_secret", "access_token", "expires_at"]
        .iter()
        .map(|key| raw.find(&format!("\"{key}\"")).expect(key))
        .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "field order: {raw}");
}

#[cfg(unix)]
#[test]
fn store_writes_file_with_0600_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::file_at(dir.path());
    store.save(&Credentials::default()).unwrap();
    let mode = std::fs::metadata(store.credentials_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn store_load_returns_none_when_empty_and_clear_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = CredentialStore::file_at(dir.path());
    assert!(store.load().unwrap().is_none());
    store.clear().unwrap();
    store.save(&Credentials::default()).unwrap();
    store.clear().unwrap();
    assert!(store.load().unwrap().is_none());
    store.clear().unwrap();
}
