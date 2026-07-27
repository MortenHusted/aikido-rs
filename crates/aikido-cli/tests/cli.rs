//! End-to-end CLI tests: envelope shape, error contract, exit codes, and the
//! auth-status validity check. Every test runs the real `aikido` binary in a
//! subprocess against a wiremock server, with the credential store pinned to
//! a temp dir file backend so the user's keychain is never touched.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `aikido` wired to `server` with stored credentials in `dir`.
fn aikido(server: &MockServer, dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("aikido").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AIKIDO_BASE_URL", server.uri())
        .env("AIKIDO_TOKEN_STORE", "file")
        .env("AIKIDO_CONFIG_DIR", dir);
    cmd
}

fn write_credentials(dir: &std::path::Path, access_token: &str, expires_at: &str) {
    std::fs::write(
        dir.join("credentials.json"),
        json!({
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "access_token": access_token,
            "expires_at": expires_at,
        })
        .to_string(),
    )
    .unwrap();
}

async fn mount_token_endpoint(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .and(body_json(json!({ "grant_type": "client_credentials" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(server)
        .await;
}

fn issues_body() -> Value {
    json!([
        {
            "id": 1,
            "severity": "critical",
            "cve_id": "CVE-2026-0001",
            "affected_package": "left-pad",
            "code_repo_name": "acme/api",
            "status": "open"
        },
        {
            "id": 2,
            "severity": "high",
            "cve_id": "CVE-2026-0002",
            "affected_package": "right-pad",
            "code_repo_name": "acme/web",
            "status": "open"
        }
    ])
}

// ---------------------------------------------------------------------------
// The JSON envelope contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issues_list_json_envelope_is_exactly_ok_data_summary_meta() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(query_param("filter_severities", "critical,high"))
        .and(query_param("filter_status", "open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--severity", "critical,high", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let envelope: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"].as_array().unwrap().len(), 2);
    assert_eq!(envelope["summary"], "2 issues");
    assert_eq!(envelope["meta"]["count"], 2);
    // Exactly the envelope keys, and in contract order.
    let keys: Vec<&str> = envelope
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 4);
    for key in ["ok", "data", "summary", "meta"] {
        assert!(keys.contains(&key), "missing envelope key {key}");
    }
    let positions: Vec<usize> = ["\"ok\"", "\"data\"", "\"summary\"", "\"meta\""]
        .iter()
        .map(|k| stdout.find(k).unwrap())
        .collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "envelope key order: {stdout}"
    );
}

#[tokio::test]
async fn issues_list_limit_truncates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["issues", "list", "--limit", "1", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"summary\": \"1 issues\""));
}

#[tokio::test]
async fn quiet_prints_only_the_data() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--quiet"])
        .output()
        .unwrap();
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(data.is_array(), "quiet output must be bare data");
    assert_eq!(data.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn jq_filters_the_data_not_the_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--jq", ".[] | .cve_id"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, "\"CVE-2026-0001\"\n\"CVE-2026-0002\"\n");
}

#[tokio::test]
async fn md_renders_a_table_with_summary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["issues", "list", "--md"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "| Severity | CVE | Package | Repo | Status |",
        ))
        .stdout(predicate::str::contains(
            "| critical | CVE-2026-0001 | left-pad | acme/api | open |",
        ))
        .stdout(predicate::str::contains("2 issues"));
}

// ---------------------------------------------------------------------------
// Error contract: envelope shape preserved, but stderr + non-zero exit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_errors_render_the_envelope_on_stderr_with_nonzero_exit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/99"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "reason_phrase": "group not found"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "show", "99", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "errors must not pollute stdout");

    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "group not found");
    assert_eq!(envelope["code"], "not_found");
    assert!(envelope.get("hint").is_none(), "empty hint must be omitted");
}

#[tokio::test]
async fn auth_errors_use_code_hint_and_exit_4() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap(); // no credentials at all

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));

    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["code"], "auth_error");
    assert_eq!(envelope["hint"], "Run: aikido auth login");
}

#[tokio::test]
async fn rate_limit_maps_to_rate_limit_code_with_hint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["code"], "rate_limit");
    assert_eq!(envelope["hint"], "Wait and retry");
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issues_severity_posts_adjustment_and_reports_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/5/severity/adjust"))
        .and(body_json(
            json!({ "adjusted_severity": "low", "reason": "test env only" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args([
            "issues",
            "severity",
            "5",
            "--level",
            "low",
            "--reason",
            "test env only",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["summary"], "Issue 5 severity adjusted to low.");
}

#[tokio::test]
async fn issues_snooze_requires_until() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    aikido(&server, dir.path())
        .args(["issues", "snooze", "5", "--json"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--until"));
}

#[tokio::test]
async fn issues_severity_requires_level_and_reason() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    aikido(&server, dir.path())
        .args(["issues", "severity", "5", "--json"])
        .assert()
        .failure()
        .code(2);
}

#[tokio::test]
async fn repos_scan_sends_flags_and_succeeds_on_204() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/repositories/code/12/scan"))
        .and(query_param("include_sast_scan", "true"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["repos", "scan", "12", "--sast", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["summary"], "Scan initiated for repository 12.");
}

// ---------------------------------------------------------------------------
// The three Go bugs, end to end
// ---------------------------------------------------------------------------

/// Bug 1: a revoked AIKIDO_TOKEN must recover through stored client
/// credentials instead of failing hard.
#[tokio::test]
async fn revoked_env_token_recovers_via_stored_client_credentials() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;
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
        .respond_with(ResponseTemplate::new(200).set_body_json(issues_body()))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "stored-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .env("AIKIDO_TOKEN", "revoked-env-token")
        .args(["issues", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"));
}

/// Bug 2: after a 401 refresh, the new token and expiry are persisted, so
/// the next invocation authenticates first try.
#[tokio::test]
async fn refreshed_token_is_persisted_for_the_next_invocation() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer expired-stored-token"))
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
        .expect(2) // refresh retry + second invocation, first try
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "expired-stored-token", "2020-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["issues", "list", "--json"])
        .assert()
        .success();

    // The store was updated: fresh token, moved expiry, credentials intact.
    let creds: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("credentials.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(creds["access_token"], "fresh-token");
    assert_eq!(creds["client_id"], "test-client-id");
    assert_ne!(creds["expires_at"], "2020-01-01T00:00:00Z");

    // Second invocation uses the persisted token directly — no extra 401.
    aikido(&server, dir.path())
        .args(["issues", "list", "--json"])
        .assert()
        .success();
}

/// Bug 3: `auth status` validates instead of equating presence with
/// validity. A revoked env token reports authenticated: false.
#[tokio::test]
async fn auth_status_reports_revoked_env_token_as_unauthenticated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "token revoked"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap(); // no stored creds → no refresh path

    let output = aikido(&server, dir.path())
        .env("AIKIDO_TOKEN", "revoked-env-token")
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "status itself succeeds");

    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], false);
    assert_eq!(envelope["data"]["checked"], true);
    assert_eq!(envelope["data"]["source"], "env");
}

#[tokio::test]
async fn auth_status_validates_a_working_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code"))
        .and(header("authorization", "Bearer valid-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], true);
    assert_eq!(envelope["data"]["checked"], true);
    assert_eq!(envelope["data"]["source"], "file");
    assert_eq!(envelope["data"]["expires_at"], "2030-01-01T00:00:00Z");
    assert_eq!(envelope["data"]["expired"], false);
}

#[tokio::test]
async fn auth_status_says_unchecked_when_the_api_is_unreachable() {
    // Point at a closed port: the validity call fails with a transport
    // error, and status must say "unchecked" instead of claiming validity.
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "some-token", "2030-01-01T00:00:00Z");

    let mut cmd = Command::cargo_bin("aikido").unwrap();
    let output = cmd
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AIKIDO_BASE_URL", "http://127.0.0.1:1")
        .env("AIKIDO_TOKEN_STORE", "file")
        .env("AIKIDO_CONFIG_DIR", dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["checked"], false);
    assert!(
        envelope["summary"]
            .as_str()
            .unwrap()
            .contains("validity not checked"),
        "summary must state validity is unchecked: {}",
        envelope["summary"]
    );
}

#[tokio::test]
async fn auth_status_without_credentials_is_unauthenticated() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    let output = aikido(&server, dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], false);
}

// ---------------------------------------------------------------------------
// auth login / logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_login_with_env_credentials_stores_all_four_fields() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;

    let dir = tempfile::tempdir().unwrap();

    aikido(&server, dir.path())
        .env("AIKIDO_CLIENT_ID", "test-client-id")
        .env("AIKIDO_CLIENT_SECRET", "test-client-secret")
        .args(["auth", "login", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Authenticated successfully"));

    let creds: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("credentials.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(creds["client_id"], "test-client-id");
    assert_eq!(creds["client_secret"], "test-client-secret");
    assert_eq!(creds["access_token"], "fresh-token");
    assert!(creds["expires_at"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn auth_login_with_bad_credentials_fails_with_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "invalid client credentials"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let output = aikido(&server, dir.path())
        .env("AIKIDO_CLIENT_ID", "bad")
        .env("AIKIDO_CLIENT_SECRET", "creds")
        .args(["auth", "login", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["code"], "auth_error");
    assert!(
        !dir.path().join("credentials.json").exists(),
        "must not store bad creds"
    );
}

#[tokio::test]
async fn auth_logout_removes_the_credentials_file() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "tok", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["auth", "logout", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Logged out successfully."));
    assert!(!dir.path().join("credentials.json").exists());
}

// ---------------------------------------------------------------------------
// Containers & repos read paths through the binary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn containers_show_and_licenses_round_trip() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers/8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "registry/api", "provider": "ecr", "environment": "prod", "external_id": "x"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers/8/licenses/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "name": "openssl", "license": "Apache-2.0", "version": "3.0" }
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["containers", "show", "8", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("registry/api"));

    let output = aikido(&server, dir.path())
        .args(["containers", "licenses", "8", "--json"])
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["summary"], "1 packages");
    assert_eq!(envelope["data"][0]["license"], "Apache-2.0");
}

#[tokio::test]
async fn repos_list_passes_name_filter_and_renders_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code"))
        .and(query_param("filter_name", "api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "name": "acme/api", "provider": "github", "branch": "main" }
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["repos", "list", "--name", "api", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["summary"], "1 repositories");
    assert_eq!(envelope["data"][0]["name"], "acme/api");
}
