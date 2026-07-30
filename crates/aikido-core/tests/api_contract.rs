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
        issue_group_id: None,
    };
    let issues = api::list_issues(&client, &filters, Some(2)).await.unwrap();
    assert_eq!(issues.len(), 2, "limit must truncate client-side");
    assert_eq!(issues[0]["id"], 1);
}

#[tokio::test]
async fn issue_counts_passes_every_documented_filter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/counts"))
        .and(query_param("filter_code_repo_name", "acme/api"))
        .and(query_param("filter_container_repo_id", "9"))
        .and(query_param("filter_team_id", "4"))
        .and(query_param("since_timestamp", "1750000000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issue_groups": { "all": 25, "critical": 3, "high": 12, "medium": 7, "low": 3 },
            "issues": { "all": 168, "critical": 5, "high": 35, "medium": 52, "low": 76 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let filters = api::CountFilters {
        code_repo_id: None,
        external_code_repo_id: None,
        code_repo_name: Some("acme/api".into()),
        container_repo_id: Some(9),
        team_id: Some(4),
        since_timestamp: Some(1_750_000_000),
    };
    let counts = api::issue_counts(&client, &filters).await.unwrap();
    assert_eq!(counts["issue_groups"]["all"], 25);
    assert_eq!(counts["issues"]["all"], 168);
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

// ---------------------------------------------------------------------------
// Issue groups
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_open_issue_groups_passes_filters_and_paginates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/open-issue-groups"))
        .and(query_param("filter_code_repo_name", "acme/api"))
        .and(query_param("filter_issue_type", "open_source"))
        .and(query_param("filter_status", "open"))
        .and(query_param("page", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "severity": "critical", "title": "left-pad", "group_status": "new",
              "locations": [
                  { "id": 1, "name": "acme/api", "type": "code_repo" },
                  { "id": 2, "name": "registry/api", "type": "container_repo" }
              ]}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let filters = api::GroupFilters {
        code_repo_name: Some("acme/api".into()),
        issue_type: Some("open_source".into()),
        status: Some("open".into()),
        ..api::GroupFilters::default()
    };
    let groups = api::list_open_issue_groups(&client, &filters, 50)
        .await
        .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["locations"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn group_blast_radius_combines_locations_and_open_issue_count() {
    let server = MockServer::start().await;
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
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(query_param("filter_issue_group_id", "42"))
        .and(query_param("filter_status", "open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 100 }, { "id": 101 }, { "id": 102 }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    let blast = api::group_blast_radius(&client, 42).await.unwrap();
    assert_eq!(blast.locations.len(), 3);
    assert_eq!(blast.expected_issues, 3);
}

#[test]
fn group_mutation_count_verifier_accepts_matching_or_missing_counts_and_rejects_mismatch() {
    let blast = api::GroupBlastRadius {
        locations: vec![],
        expected_issues: 3,
    };

    api::verify_group_mutation_count(42, &blast, Some(3), "ignored").unwrap();
    api::verify_group_mutation_count(42, &blast, None, "severity adjusted").unwrap();

    let error = api::verify_group_mutation_count(42, &blast, Some(7), "ignored").unwrap_err();
    assert_eq!(error.code(), "api_error");
    let message = error.to_string();
    assert!(
        message.contains("affected 7 issues but 3 open issues were expected"),
        "{message}"
    );
    assert!(message.contains("MUTATION WAS APPLIED"), "{message}");
}

#[tokio::test]
async fn group_ignore_and_snooze_report_affected_amounts() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/ignore"))
        .and(body_json(json!({ "reason": "false positive" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "ignored_single_issues_amount": 3
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/43/snooze"))
        .and(body_json(
            json!({ "snooze_until": 1790000000i64, "reason": "sprint" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "snoozed_single_issues_amount": 5
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    assert_eq!(
        api::ignore_issue_group(&client, 42, Some("false positive"))
            .await
            .unwrap(),
        Some(3)
    );
    assert_eq!(
        api::snooze_issue_group(&client, 43, 1_790_000_000, Some("sprint"))
            .await
            .unwrap(),
        Some(5)
    );
}

#[tokio::test]
async fn group_severity_and_undo_verbs_send_the_documented_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/groups/42/severity/adjust"))
        .and(body_json(
            json!({ "adjusted_severity": "low", "reason": "unreachable" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/unignore"))
        .and(body_json(json!({ "reason": "re-triaging" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/groups/42/unsnooze"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::adjust_group_severity(&client, 42, "low", "unreachable")
        .await
        .unwrap();
    api::unignore_issue_group(&client, 42, Some("re-triaging"))
        .await
        .unwrap();
    api::unsnooze_issue_group(&client, 42).await.unwrap();
}

#[tokio::test]
async fn issue_level_undo_verbs_send_apply_for_all_tags_only_when_set() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/7/unignore"))
        .and(body_json(
            json!({ "reason": "still relevant", "apply_for_all_tags": true }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/public/v1/issues/8/unsnooze"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "tok");
    api::unignore_issue(&client, 7, Some("still relevant"), true)
        .await
        .unwrap();
    api::unsnooze_issue(&client, 8, false).await.unwrap();
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
