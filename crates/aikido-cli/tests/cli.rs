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
    let mut cmd = bare_aikido(server, dir);
    cmd.env("AIKIDO_TOKEN_STORE", "file");
    cmd
}

/// `aikido` with a scrubbed environment: only PATH, the mock server, and the
/// config dir, so no AIKIDO_* from the developer's shell leaks in. On Windows
/// a process with an empty environment cannot initialise Winsock (every
/// connection then fails with "error sending request"), so SYSTEMROOT is
/// passed through where it exists.
fn bare_aikido(server: &MockServer, dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("aikido").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AIKIDO_BASE_URL", server.uri())
        .env("AIKIDO_CONFIG_DIR", dir);
    if let Ok(system_root) = std::env::var("SYSTEMROOT") {
        cmd.env("SYSTEMROOT", system_root);
    }
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
// issues counts — two axes that must never blur
// ---------------------------------------------------------------------------

fn counts_body() -> Value {
    json!({
        "issue_groups": { "all": 25, "critical": 3, "high": 12, "medium": 7, "low": 3 },
        "issues": { "all": 168, "critical": 5, "high": 35, "medium": 52, "low": 76 }
    })
}

#[tokio::test]
async fn issues_counts_json_passes_raw_data_and_names_both_axes_in_summary() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/counts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(counts_body()))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "counts", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    // Raw API payload untouched.
    assert_eq!(envelope["data"], counts_body());
    // The summary states both units in words — the ambiguity this command
    // exists to kill.
    let summary = envelope["summary"].as_str().unwrap();
    assert!(summary.contains("25 open issue groups"), "{summary}");
    assert!(summary.contains("dashboard"), "{summary}");
    assert!(summary.contains("168 individual issues"), "{summary}");
}

#[tokio::test]
async fn issues_counts_md_labels_each_axis_in_words() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/counts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(counts_body()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["issues", "counts", "--md"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "| Unit | All | Critical | High | Medium | Low |",
        ))
        .stdout(predicate::str::contains(
            "Issue groups — the Aikido dashboard's \"Open Issues\" number | 25 | 3 | 12 | 7 | 3 |",
        ))
        .stdout(predicate::str::contains(
            "Individual issues — the rows `issues list` / `/issues/export` return | 168 | 5 | 35 | 52 | 76 |",
        ));
}

#[tokio::test]
async fn issues_counts_passes_since_and_repo_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/counts"))
        .and(query_param("filter_code_repo_name", "acme/api"))
        .and(query_param("since_timestamp", "1750000000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(counts_body()))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args([
            "issues",
            "counts",
            "--repo",
            "acme/api",
            "--since",
            "1750000000",
            "--json",
        ])
        .assert()
        .success();
}

#[tokio::test]
async fn issues_counts_rejects_bad_since() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "counts", "--since", "next tuesday", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert!(envelope["error"].as_str().unwrap().contains("--since"));
}

// ---------------------------------------------------------------------------
// issues groups — group-level reads and blast-radius-guarded mutations
// ---------------------------------------------------------------------------

/// Mounts the two preflight endpoints for group 42: detail (3 locations)
/// and its open-issue export (`expected` issues).
async fn mount_group_blast_radius(server: &MockServer, expected: usize) {
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "title": "left-pad",
            "locations": [
                { "id": 1, "name": "acme/api", "type": "code_repo" },
                { "id": 2, "name": "acme/web", "type": "code_repo" },
                { "id": 3, "name": "registry/api", "type": "container_repo" }
            ]
        })))
        .mount(server)
        .await;
    let issues: Vec<Value> = (0..expected).map(|i| json!({ "id": i })).collect();
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(query_param("filter_issue_group_id", "42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(issues)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn groups_list_renders_the_envelope_and_flags_touch_semantics() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/open-issue-groups"))
        .and(query_param("filter_code_repo_name", "acme/api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 42, "severity": "critical", "title": "left-pad", "group_status": "new",
              "locations": [
                  { "id": 1, "name": "acme/api", "type": "code_repo" },
                  { "id": 2, "name": "acme/web", "type": "code_repo" }
              ]}
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "groups", "list", "--repo", "acme/api", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"][0]["id"], 42);
    // A location-filtered listing must say it returns groups TOUCHING the
    // filter — the loop's summary must not imply repo-exclusive scope.
    let summary = envelope["summary"].as_str().unwrap();
    assert!(summary.contains("touching"), "{summary}");
    assert!(summary.contains("may also span"), "{summary}");
}

#[tokio::test]
async fn groups_ignore_reports_blast_radius_and_matching_amount() {
    let server = MockServer::start().await;
    mount_group_blast_radius(&server, 3).await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/ignore"))
        .and(body_json(json!({ "reason": "false positive" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "ignored_single_issues_amount": 3
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args([
            "issues",
            "groups",
            "ignore",
            "42",
            "--reason",
            "false positive",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["group_id"], 42);
    assert_eq!(envelope["data"]["expected_issues"], 3);
    assert_eq!(envelope["data"]["affected_issues"], 3);
    assert_eq!(envelope["data"]["locations"].as_array().unwrap().len(), 3);
    assert_eq!(
        envelope["summary"],
        "Group 42 ignored: 3 issues across 3 locations."
    );
}

/// The blast-radius assert: affected != expected is an ERROR, and the error
/// must say the mutation was applied anyway.
#[tokio::test]
async fn groups_ignore_amount_mismatch_is_an_error_that_names_both_numbers() {
    let server = MockServer::start().await;
    mount_group_blast_radius(&server, 3).await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/ignore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "ignored_single_issues_amount": 7
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["issues", "groups", "ignore", "42", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "mismatch must be an error");
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["ok"], false);
    let message = envelope["error"].as_str().unwrap();
    assert!(message.contains('7') && message.contains('3'), "{message}");
    assert!(
        message.contains("MUTATION WAS APPLIED"),
        "must not read as a no-op failure: {message}"
    );
}

#[tokio::test]
async fn groups_severity_carries_expectation_when_api_reports_no_amount() {
    let server = MockServer::start().await;
    mount_group_blast_radius(&server, 3).await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/groups/42/severity/adjust"))
        .and(body_json(
            json!({ "adjusted_severity": "low", "reason": "test env" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args([
            "issues", "groups", "severity", "42", "--level", "low", "--reason", "test env",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["affected_issues"], Value::Null);
    assert!(
        envelope["summary"]
            .as_str()
            .unwrap()
            .contains("no per-issue count"),
        "{}",
        envelope["summary"]
    );
}

#[tokio::test]
async fn undo_verbs_work_at_both_levels() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/unignore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/unsnooze"))
        .and(body_json(json!({ "apply_for_all_tags": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["issues", "groups", "unignore", "42", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Group 42 unignored."));

    aikido(&server, dir.path())
        .args(["issues", "unsnooze", "7", "--all-tags", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Issue 7 unsnoozed."));
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

/// A huge day count used to abort the process inside chrono (exit 101, no
/// envelope). It must come back as an ordinary error envelope on stderr.
#[tokio::test]
async fn issues_snooze_rejects_absurd_durations_with_an_envelope_not_a_panic() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    for (args, flag) in [
        (
            vec!["issues", "snooze", "5", "--until", "99999999999999999d"],
            "--until",
        ),
        (
            vec!["issues", "counts", "--since", "99999999999999999d"],
            "--since",
        ),
    ] {
        let mut full = args.clone();
        full.push("--json");
        let output = aikido(&server, dir.path()).args(&full).output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{flag}: {output:?}");
        let envelope: Value = serde_json::from_slice(&output.stderr)
            .unwrap_or_else(|_| panic!("{flag}: stderr is not an envelope: {output:?}"));
        assert_eq!(envelope["ok"], false);
        let error = envelope["error"].as_str().unwrap();
        assert!(
            error.contains(flag) && error.contains("at most 3650 days"),
            "{flag}: {error}"
        );
    }
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
    assert_eq!(envelope["data"]["shadow_file"], Value::Null);
    assert_eq!(envelope["data"]["expires_at"], "2030-01-01T00:00:00Z");
    assert_eq!(envelope["data"]["expired"], false);
}

/// Off macOS there is no keychain in the build, so the *default* backend
/// (AIKIDO_TOKEN_STORE unset) must be the file, and a fresh install must
/// read as "not authenticated" rather than as a build-configuration error.
/// On macOS the default backend would touch the real keychain, so this runs
/// only where the file is the whole story.
#[cfg(not(target_os = "macos"))]
#[tokio::test]
async fn default_store_is_the_file_where_no_keychain_is_built() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let output = bare_aikido(&server, dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], false);
    assert!(
        envelope["summary"]
            .as_str()
            .unwrap()
            .contains("Not authenticated"),
        "{envelope}"
    );

    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");
    let output = bare_aikido(&server, dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], true, "{envelope}");
    assert_eq!(envelope["data"]["source"], "file");
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
// Credential-store failures must be loud, and must not take down runs that
// never needed the store. (The keychain equivalent — an unanswerable ACL
// prompt — is bounded by a deadline in core; these exercise the same
// propagation paths via a file store that errors on read.)
// ---------------------------------------------------------------------------

/// A config dir whose credentials.json cannot be read (it is a directory).
fn broken_store_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("credentials.json")).unwrap();
    dir
}

#[tokio::test]
async fn a_failing_store_reports_its_error_not_bare_unauthenticated() {
    let server = MockServer::start().await;
    let dir = broken_store_dir();

    let output = aikido(&server, dir.path())
        .args(["issues", "list", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["code"], "auth_error");
    let message = envelope["error"].as_str().unwrap();
    assert_ne!(
        message, "not authenticated",
        "store failure must keep its message"
    );
    assert!(
        message.contains("credentials.json"),
        "must name the store problem: {message}"
    );
}

#[tokio::test]
async fn env_token_survives_a_failing_store_with_a_warning() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(header("authorization", "Bearer env-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let dir = broken_store_dir();
    let output = aikido(&server, dir.path())
        .env("AIKIDO_TOKEN", "env-token")
        .args(["issues", "list", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "env token must not die on store failure"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("could not read stored credentials"),
        "degradation must be announced: {stderr}"
    );
}

#[tokio::test]
async fn fully_env_configured_runs_never_touch_the_store() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let dir = broken_store_dir();
    let output = aikido(&server, dir.path())
        .env("AIKIDO_TOKEN", "env-token")
        .env("AIKIDO_CLIENT_ID", "env-id")
        .env("AIKIDO_CLIENT_SECRET", "env-secret")
        .args(["issues", "list", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("could not read"),
        "store must be skipped entirely, not read-and-warned: {stderr}"
    );
}

#[tokio::test]
async fn auth_status_reports_a_failing_store_as_unreadable_not_unauthenticated() {
    let server = MockServer::start().await;
    let dir = broken_store_dir();

    let output = aikido(&server, dir.path())
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["data"]["authenticated"], false);
    assert!(
        envelope["summary"]
            .as_str()
            .unwrap()
            .contains("Cannot read credentials"),
        "status must distinguish unreadable from absent: {envelope}"
    );
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
        .stdout(predicate::str::contains("Authenticated successfully"))
        // Login names the backend that received the secret, so a keychain
        // that silently fell through to the file can never look like success.
        .stdout(predicate::str::contains("\"store\": \"file\""))
        .stdout(predicate::str::contains("\"keychain_fallback\": false"))
        .stdout(predicate::str::contains("Credentials stored in"));

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
async fn auth_login_announces_env_credential_source_on_stderr() {
    // A stale exported secret silently re-exchanged is the footgun this
    // guards against: env-sourced credentials must be announced.
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;

    let dir = tempfile::tempdir().unwrap();
    aikido(&server, dir.path())
        .env("AIKIDO_CLIENT_ID", "test-client-id")
        .env("AIKIDO_CLIENT_SECRET", "test-client-secret")
        .args(["auth", "login", "--json"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using client credentials from AIKIDO_CLIENT_ID/AIKIDO_CLIENT_SECRET",
        ));
}

/// Non-TTY stdin: two piped lines (client ID, then secret) log in without
/// any interactivity. The Go CLI could not be scripted this way reliably.
#[tokio::test]
async fn auth_login_accepts_two_lines_piped_on_stdin() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;

    let dir = tempfile::tempdir().unwrap();
    aikido(&server, dir.path())
        .args(["auth", "login", "--json"])
        .write_stdin("test-client-id\ntest-client-secret\n")
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
}

/// Non-TTY stdin with no input: a clear auth_error naming the alternatives,
/// not the Go CLI's bare "EOF".
#[tokio::test]
async fn auth_login_with_empty_stdin_names_the_alternatives() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    let output = aikido(&server, dir.path())
        .args(["auth", "login", "--json"])
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));

    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["code"], "auth_error");
    let message = envelope["error"].as_str().unwrap();
    assert!(
        message.contains("AIKIDO_CLIENT_ID"),
        "must name the env vars: {message}"
    );
    assert!(
        message.contains("pipe two lines"),
        "must name the stdin option: {message}"
    );
    assert!(!message.contains("EOF"), "no bare EOF: {message}");
    assert!(!dir.path().join("credentials.json").exists());
}

/// Only one line piped (secret missing) is the same clear failure.
#[tokio::test]
async fn auth_login_with_missing_secret_line_fails_clearly() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();

    let output = aikido(&server, dir.path())
        .args(["auth", "login", "--json"])
        .write_stdin("only-a-client-id\n")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["code"], "auth_error");
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
    // stderr carries the env-source announcement line, then the envelope.
    let stderr = String::from_utf8(output.stderr).unwrap();
    let envelope: Value =
        serde_json::from_str(&stderr[stderr.find('{').expect("envelope on stderr")..]).unwrap();
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
// api get — raw read-only passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_get_hits_the_path_with_query_params_and_wraps_the_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/openapi/spec"))
        .and(query_param("version", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "openapi": "3.0.0",
            "info": { "title": "Aikido API", "version": "1.0" }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args([
            "api",
            "get",
            "/openapi/spec",
            "--query",
            "version=3",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["openapi"], "3.0.0");
}

#[tokio::test]
async fn api_get_inherits_auth_refresh_from_the_shared_client() {
    let server = MockServer::start().await;
    mount_token_endpoint(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/openapi/spec"))
        .and(header("authorization", "Bearer expired-stored-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/openapi/spec"))
        .and(header("authorization", "Bearer fresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "openapi": "3.0.0" })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "expired-stored-token", "2020-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .args(["api", "get", "/openapi/spec", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ok\": true"));
}

#[tokio::test]
async fn api_get_rejects_paths_that_escape_the_base() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    for bad in [
        "https://evil.example/x",
        "//evil.example/x",
        "/issues/../../oauth/token",
        // The URL parser normalises these into the traversal above, so they
        // must be refused before a request is ever built.
        "/%2e%2e/%2e%2e/oauth/token",
        "/issues\\..\\..\\oauth\\token",
        "relative/path",
        "/spec?inline=1",
    ] {
        let output = aikido(&server, dir.path())
            .args(["api", "get", bad, "--json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "must reject {bad:?}");
        let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(envelope["ok"], false);
        assert!(
            envelope["error"].as_str().unwrap().contains("invalid path"),
            "unexpected error for {bad:?}: {envelope}"
        );
    }
}

#[tokio::test]
async fn api_get_works_with_jq() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/openapi/spec"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "paths": { "/issues/export": {}, "/containers": {} }
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args([
            "api",
            "get",
            "/openapi/spec",
            "--jq",
            ".paths | keys | length",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "2");
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
async fn containers_scan_queues_and_reports_async() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/containers/7/scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": 1 })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["containers", "scan", "7", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    let summary = envelope["summary"].as_str().unwrap();
    assert!(
        summary.contains("queued") || summary.contains("asynchronously"),
        "summary must not imply completion: {summary}"
    );
}

#[tokio::test]
async fn containers_scan_surfaces_inactive_container_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/containers/7/scan"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "The container must be active before it can be scanned."
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["containers", "scan", "7", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["ok"], false);
    assert!(envelope["error"]
        .as_str()
        .unwrap()
        .contains("must be active"));
}

#[tokio::test]
async fn containers_list_stale_days_filters_and_annotates() {
    let now = chrono::Utc::now().timestamp();
    let day = 86_400;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            // Fresh: scanned yesterday, pushed before that.
            { "id": 1, "name": "fresh", "is_active": true,
              "last_scanned_at": now - day, "last_pushed_at": now - 2 * day },
            // Stale: pushed after the last scan (the pushed-after-scan failure mode).
            { "id": 2, "name": "stale-pushed", "is_active": true,
              "last_scanned_at": now - 30 * day, "last_pushed_at": now - day,
              "tag": "sha-abc", "last_scanned_tag": "latest" },
            // Inactive: deliberately off, excluded from staleness.
            { "id": 3, "name": "inactive", "is_active": false,
              "last_scanned_at": -1, "last_pushed_at": -1 }
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    let output = aikido(&server, dir.path())
        .args(["containers", "list", "--stale-days", "7", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    let data = envelope["data"].as_array().unwrap();
    assert_eq!(data.len(), 1, "only the stale container: {envelope}");
    assert_eq!(data[0]["name"], "stale-pushed");

    // The comparison is explicit — no operator arithmetic required.
    let staleness = &data[0]["scan_staleness"];
    assert_eq!(staleness["scan_age_days"], 30);
    assert_eq!(staleness["pushed_after_scan"], true);
    assert_eq!(staleness["tag_drift"], true);
    let reasons: Vec<&str> = staleness["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"scan_older_than_limit"));
    assert!(reasons.contains(&"pushed_after_scan"));

    let summary = envelope["summary"].as_str().unwrap();
    assert!(
        summary.contains("1 of 2 active containers scan-stale"),
        "summary must state the comparison: {summary}"
    );
}

// The zone is pinned through TZ, which chrono honours on Unix only; Windows
// takes the zone from the system, so these two run where the pin holds.
#[cfg(unix)]
#[tokio::test]
async fn containers_list_shows_scan_freshness_in_the_table() {
    let now = chrono::Utc::now().timestamp();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "name": "registry/app", "tag": "latest", "provider": "ecr",
              "is_active": true, "last_scanned_at": now - 86_400, "last_pushed_at": -1 }
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    // Pin the subprocess zone so the expected date is deterministic.
    let expected_date = chrono::DateTime::from_timestamp(now - 86_400, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();
    aikido(&server, dir.path())
        .env("TZ", "UTC")
        .args(["containers", "list", "--md"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "| Name | Tag | Provider | Status | Scanned | Pushed |",
        ))
        .stdout(predicate::str::contains(&expected_date))
        .stdout(predicate::str::contains("never"));
}

/// Derived dates render in the operator's local zone, pinned via the TZ env
/// var on the subprocess so the test is deterministic on any machine:
/// 1785196041 is 2026-07-27 23:47 UTC but already 2026-07-28 in Copenhagen.
#[cfg(unix)]
#[tokio::test]
async fn derived_dates_render_in_the_local_zone_not_utc() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "name": "registry/crm", "tag": "latest", "provider": "ecr",
              "is_active": true, "last_scanned_at": 1_785_196_041i64, "last_pushed_at": -1 }
        ])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token", "2030-01-01T00:00:00Z");

    aikido(&server, dir.path())
        .env("TZ", "Europe/Copenhagen")
        .args(["containers", "list", "--md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2026-07-28"));

    aikido(&server, dir.path())
        .env("TZ", "UTC")
        .args(["containers", "list", "--md"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2026-07-27"));
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
