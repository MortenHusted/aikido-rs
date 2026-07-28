//! Wiremock contract tests for every API path the CLI and MCP server use.

use aikido_core::api::{self, IssueFilters};
use aikido_core::client::Client;
use aikido_core::error::ApiError;
use serde_json::json;
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn issue(id: u64, severity: &str) -> serde_json::Value {
    json!({
        "id": id,
        "severity": severity,
        "cve_id": format!("CVE-2026-{id:04}"),
        "affected_package": "left-pad",
        "code_repo_name": "acme/api",
        "status": "open"
    })
}

#[tokio::test]
async fn list_issues_passes_filters_verbatim_and_truncates_client_side() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(query_param("filter_severities", "critical,high"))
        .and(query_param("filter_status", "open"))
        .and(query_param("filter_code_repo_name", "acme/api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            issue(1, "critical"),
            issue(2, "high"),
            issue(3, "high")
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let filters = IssueFilters {
        severity: Some("critical,high".into()),
        status: Some("open".into()),
        code_repo_name: Some("acme/api".into()),
        container_repo_name: None,
    };
    let issues = api::list_issues(&client, &filters, Some(2)).await.unwrap();
    assert_eq!(issues.len(), 2, "limit must truncate client-side");
    assert_eq!(issues[0]["id"], 1);
}

#[tokio::test]
async fn get_issue_group_hits_the_group_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "title": "Vulnerable dependency",
            "severity": "high"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let group = api::get_issue_group(&client, 42).await.unwrap();
    assert_eq!(group["title"], "Vulnerable dependency");
}

#[tokio::test]
async fn ignore_issue_puts_reason_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/ignore"))
        .and(body_json(json!({ "reason": "false positive" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::ignore_issue(&client, 7, Some("false positive"))
        .await
        .unwrap();
}

#[tokio::test]
async fn ignore_issue_sends_empty_object_without_reason() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/ignore"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::ignore_issue(&client, 7, None).await.unwrap();
}

#[tokio::test]
async fn snooze_issue_puts_unix_timestamp_and_reason() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/9/snooze"))
        .and(body_json(
            json!({ "snooze_until": 1790000000i64, "reason": "sprint" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::snooze_issue(&client, 9, 1790000000, Some("sprint"))
        .await
        .unwrap();
}

#[tokio::test]
async fn adjust_severity_posts_level_and_reason() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/5/severity/adjust"))
        .and(body_json(
            json!({ "adjusted_severity": "low", "reason": "not reachable" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::adjust_severity(&client, 5, "low", "not reachable")
        .await
        .unwrap();
}

#[tokio::test]
async fn list_code_repos_requests_one_page_when_limit_is_satisfied() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code"))
        .and(query_param("per_page", "3"))
        .and(query_param("page", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "name": "a" }, { "id": 2, "name": "b" }, { "id": 3, "name": "c" }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let repos = api::list_code_repos(&client, 3, None, false).await.unwrap();
    assert_eq!(repos.len(), 3);
}

#[tokio::test]
async fn list_containers_caps_page_size_at_20_and_fetches_next_pages() {
    let server = MockServer::start().await;
    let full_page: Vec<serde_json::Value> =
        (0..20).map(|i| json!({ "id": i, "name": "c" })).collect();
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers"))
        .and(query_param("per_page", "20"))
        .and(query_param("page", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(full_page)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers"))
        .and(query_param("per_page", "20"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{ "id": 20, "name": "tail" }])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let containers = api::list_containers(&client, 25, None, None).await.unwrap();
    assert_eq!(containers.len(), 21);
    assert_eq!(containers[20]["name"], "tail");
}

#[tokio::test]
async fn scan_repo_posts_scan_flags_and_accepts_204() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/repositories/code/12/scan"))
        .and(query_param("include_sast_scan", "true"))
        .and(query_param("include_secrets_scan", "true"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::scan_repo(&client, 12, true, false, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn licenses_normalise_single_object_to_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/repositories/code/3/licenses/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            { "name": "left-pad", "license": "MIT", "version": "1.0.0" }
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers/4/licenses/export"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            [{ "name": "openssl", "license": "Apache-2.0", "version": "3.0" }]
        )))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let repo_lics = api::repo_licenses(&client, 3).await.unwrap();
    assert_eq!(repo_lics.len(), 1);
    assert_eq!(repo_lics[0]["license"], "MIT");

    let container_lics = api::container_licenses(&client, 4).await.unwrap();
    assert_eq!(container_lics.len(), 1);
    assert_eq!(container_lics[0]["name"], "openssl");
}

#[tokio::test]
async fn scan_container_posts_the_scan_trigger() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/containers/9/scan"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "success": 1 })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::scan_container(&client, 9).await.unwrap();
}

/// The scan route reports failures as `{"error": ...}` (not
/// `reason_phrase`); the message must still surface.
#[tokio::test]
async fn scan_container_surfaces_the_error_body_on_400() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/containers/9/scan"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "The container must be active before it can be scanned."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let err = api::scan_container(&client, 9).await.unwrap_err();
    assert_eq!(err.code(), "api_error");
    assert_eq!(
        err.to_string(),
        "The container must be active before it can be scanned."
    );
}

#[tokio::test]
async fn get_container_hits_the_show_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/containers/8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "registry/api", "provider": "ecr"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let container = api::get_container(&client, 8).await.unwrap();
    assert_eq!(container["provider"], "ecr");
}

#[tokio::test]
async fn error_statuses_map_to_stable_codes_and_hints() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "reason_phrase": "group not found"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/2"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/groups/3"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "reason_phrase": "boom"
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");

    let not_found = api::get_issue_group(&client, 1).await.unwrap_err();
    assert_eq!(not_found.code(), "not_found");
    assert_eq!(not_found.to_string(), "group not found");
    assert_eq!(not_found.hint(), None);

    let rate_limited = api::get_issue_group(&client, 2).await.unwrap_err();
    assert_eq!(rate_limited.code(), "rate_limit");
    assert_eq!(rate_limited.hint(), Some("Wait and retry"));

    let api_error = api::get_issue_group(&client, 3).await.unwrap_err();
    assert_eq!(api_error.code(), "api_error");
    assert_eq!(api_error.to_string(), "boom");
    match api_error {
        ApiError::Api { status, .. } => assert_eq!(status, 500),
        other => panic!("expected Api, got {other:?}"),
    }
}

#[tokio::test]
async fn unauthorized_without_refresh_credentials_is_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "reason_phrase": "token revoked"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "revoked");
    let err = api::list_issues(&client, &IssueFilters::default(), None)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "auth_error");
    assert_eq!(err.hint(), Some("Run: aikido auth login"));
    assert_eq!(err.to_string(), "token revoked");
}
