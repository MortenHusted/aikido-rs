//! Typed operations over the Aikido public API, shared verbatim by the CLI
//! and the MCP server. All responses are passed through as `serde_json::Value`
//! — the CLI's `--json` contract exposes the raw API objects.

use serde_json::{json, Value};

use crate::client::Client;
use crate::error::ApiError;

/// Filters for `GET /issues/export`. Severity is passed through verbatim as
/// a comma-separated list (`filter_severities`).
#[derive(Debug, Clone, Default)]
pub struct IssueFilters {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub code_repo_name: Option<String>,
    pub container_repo_name: Option<String>,
}

/// `GET /issues/export`, truncated client-side to `limit` when given.
pub async fn list_issues(
    client: &Client,
    filters: &IssueFilters,
    limit: Option<usize>,
) -> Result<Vec<Value>, ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(severity) = &filters.severity {
        query.push(("filter_severities", severity.clone()));
    }
    if let Some(status) = &filters.status {
        query.push(("filter_status", status.clone()));
    }
    if let Some(repo) = &filters.code_repo_name {
        query.push(("filter_code_repo_name", repo.clone()));
    }
    if let Some(container) = &filters.container_repo_name {
        query.push(("filter_container_repo_name", container.clone()));
    }

    let raw = client.get("/issues/export", &query).await?;
    let mut issues = expect_array(raw, "/issues/export")?;
    if let Some(limit) = limit {
        issues.truncate(limit);
    }
    Ok(issues)
}

/// Filters for `GET /issues/counts` — every filter the spec documents.
#[derive(Debug, Clone, Default)]
pub struct CountFilters {
    pub code_repo_id: Option<u64>,
    pub external_code_repo_id: Option<String>,
    pub code_repo_name: Option<String>,
    pub container_repo_id: Option<u64>,
    pub team_id: Option<u64>,
    /// Unix seconds; only issues created after this are counted.
    pub since_timestamp: Option<i64>,
}

/// `GET /issues/counts` — severity-bucketed counts on BOTH axes:
/// `issue_groups` (the unit behind the Aikido dashboard's "Open Issues"
/// figure) and `issues` (individual findings, the rows `/issues/export`
/// returns). Same data, different units — callers must never compare one
/// axis to the other.
pub async fn issue_counts(client: &Client, filters: &CountFilters) -> Result<Value, ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if let Some(id) = filters.code_repo_id {
        query.push(("filter_code_repo_id", id.to_string()));
    }
    if let Some(id) = &filters.external_code_repo_id {
        query.push(("filter_external_code_repo_id", id.clone()));
    }
    if let Some(name) = &filters.code_repo_name {
        query.push(("filter_code_repo_name", name.clone()));
    }
    if let Some(id) = filters.container_repo_id {
        query.push(("filter_container_repo_id", id.to_string()));
    }
    if let Some(id) = filters.team_id {
        query.push(("filter_team_id", id.to_string()));
    }
    if let Some(ts) = filters.since_timestamp {
        query.push(("since_timestamp", ts.to_string()));
    }
    client.get("/issues/counts", &query).await
}

/// `GET /issues/groups/{group_id}`.
pub async fn get_issue_group(client: &Client, group_id: u64) -> Result<Value, ApiError> {
    client.get(&format!("/issues/groups/{group_id}"), &[]).await
}

/// `PUT /issues/{id}/ignore`.
pub async fn ignore_issue(
    client: &Client,
    issue_id: u64,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = json!({});
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    client
        .put(&format!("/issues/{issue_id}/ignore"), body)
        .await?;
    Ok(())
}

/// `PUT /issues/{id}/snooze`. `snooze_until` is a unix timestamp.
pub async fn snooze_issue(
    client: &Client,
    issue_id: u64,
    snooze_until: i64,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut body = json!({ "snooze_until": snooze_until });
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    client
        .put(&format!("/issues/{issue_id}/snooze"), body)
        .await?;
    Ok(())
}

/// `POST /issues/{id}/severity/adjust`.
pub async fn adjust_severity(
    client: &Client,
    issue_id: u64,
    level: &str,
    reason: &str,
) -> Result<(), ApiError> {
    client
        .post(
            &format!("/issues/{issue_id}/severity/adjust"),
            json!({ "adjusted_severity": level, "reason": reason }),
        )
        .await?;
    Ok(())
}

/// `GET /repositories/code`, paginated server-side (per_page ≤ 200) and
/// truncated client-side to `limit`.
pub async fn list_code_repos(
    client: &Client,
    limit: usize,
    name: Option<&str>,
    include_inactive: bool,
) -> Result<Vec<Value>, ApiError> {
    let mut base_query: Vec<(&str, String)> = Vec::new();
    if let Some(name) = name {
        base_query.push(("filter_name", name.to_string()));
    }
    if include_inactive {
        base_query.push(("include_inactive", "true".to_string()));
    }
    paginate(client, "/repositories/code", base_query, limit, 200).await
}

/// `POST /repositories/code/{id}/scan` — expects 204 No Content.
pub async fn scan_repo(
    client: &Client,
    repo_id: u64,
    sast: bool,
    iac: bool,
    secrets: bool,
) -> Result<(), ApiError> {
    let mut query: Vec<(&str, String)> = Vec::new();
    if sast {
        query.push(("include_sast_scan", "true".to_string()));
    }
    if iac {
        query.push(("include_iac_scan", "true".to_string()));
    }
    if secrets {
        query.push(("include_secrets_scan", "true".to_string()));
    }
    client
        .post_no_content(&format!("/repositories/code/{repo_id}/scan"), &query)
        .await
}

/// `GET /repositories/code/{id}/licenses/export`, normalised to a list.
pub async fn repo_licenses(client: &Client, repo_id: u64) -> Result<Vec<Value>, ApiError> {
    let raw = client
        .get(
            &format!("/repositories/code/{repo_id}/licenses/export"),
            &[],
        )
        .await?;
    Ok(normalise_to_list(raw))
}

/// `GET /containers`, paginated server-side (per_page ≤ 20) and truncated
/// client-side to `limit`.
pub async fn list_containers(
    client: &Client,
    limit: usize,
    name: Option<&str>,
    tag: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let mut base_query: Vec<(&str, String)> = Vec::new();
    if let Some(name) = name {
        base_query.push(("filter_name", name.to_string()));
    }
    if let Some(tag) = tag {
        base_query.push(("filter_tag", tag.to_string()));
    }
    paginate(client, "/containers", base_query, limit, 20).await
}

/// `POST /containers/{id}/scan` — queue a container scan. Fire-and-forget:
/// a 200 `{"success": 1}` means the scan was *started*; the API returns no
/// job handle to await completion.
pub async fn scan_container(client: &Client, container_id: u64) -> Result<(), ApiError> {
    client
        .post_no_content(&format!("/containers/{container_id}/scan"), &[])
        .await
}

/// `GET /containers/{id}`.
pub async fn get_container(client: &Client, container_id: u64) -> Result<Value, ApiError> {
    client
        .get(&format!("/containers/{container_id}"), &[])
        .await
}

/// `GET /containers/{id}/licenses/export`, normalised to a list.
pub async fn container_licenses(
    client: &Client,
    container_id: u64,
) -> Result<Vec<Value>, ApiError> {
    let raw = client
        .get(&format!("/containers/{container_id}/licenses/export"), &[])
        .await?;
    Ok(normalise_to_list(raw))
}

/// Page through a list endpoint (`page` starts at 0) until `limit` items are
/// collected or the server returns a short page.
async fn paginate(
    client: &Client,
    path: &str,
    base_query: Vec<(&str, String)>,
    limit: usize,
    max_per_page: usize,
) -> Result<Vec<Value>, ApiError> {
    let per_page = limit.clamp(1, max_per_page);
    let mut all: Vec<Value> = Vec::new();
    let mut page = 0usize;

    loop {
        let mut query = base_query.clone();
        query.push(("per_page", per_page.to_string()));
        query.push(("page", page.to_string()));

        let raw = client.get(path, &query).await?;
        let page_items = expect_array(raw, path)?;
        let short_page = page_items.len() < per_page;
        all.extend(page_items);

        if all.len() >= limit || short_page {
            break;
        }
        page += 1;
    }

    all.truncate(limit);
    Ok(all)
}

fn expect_array(value: Value, path: &str) -> Result<Vec<Value>, ApiError> {
    match value {
        Value::Array(items) => Ok(items),
        other => Err(ApiError::Api {
            status: 200,
            message: format!("parse response: {path} returned non-array: {other}"),
        }),
    }
}

/// License exports may return a single object; table rendering wants a list.
fn normalise_to_list(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        other => vec![other],
    }
}
