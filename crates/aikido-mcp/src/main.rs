//! `aikido-mcp` — MCP server exposing the Aikido Security API over stdio.
//!
//! Every tool goes through `aikido-core`, the same client/auth code the
//! `aikido` CLI uses, so token refresh and persistence behave identically.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_router, ErrorData, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use aikido_core::api::{self, IssueFilters};
use aikido_core::client::Client;
use aikido_core::credentials::CredentialStore;
use aikido_core::error::ApiError;
use aikido_core::session;
use aikido_core::until;

/// Render a JSON value as the tool result (pretty text content).
fn json_result(value: &Value) -> Result<CallToolResult, ErrorData> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| ErrorData::internal_error(format!("serializing result: {err}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn to_error_data(err: ApiError) -> ErrorData {
    ErrorData::internal_error(
        format!("{} ({})", err, err.code()),
        err.hint().map(|hint| json!({ "hint": hint })),
    )
}

/// Resolve the shared-core client (env token / stored credentials, with
/// 401 auto-refresh and persistence).
fn client() -> Result<Client, ErrorData> {
    session::resolve(&CredentialStore::default(), false)
        .map(|session| session.client)
        .map_err(to_error_data)
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ListIssuesParams {
    /// Severity filter, comma-separated: critical|high|medium|low
    severity: Option<String>,
    /// Status filter: open|ignored|snoozed|closed (default: open)
    status: Option<String>,
    /// Maximum number of issues to return (default: 100)
    limit: Option<usize>,
    /// Filter by code repository name
    repo: Option<String>,
    /// Filter by container repository name
    container: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IssueGroupParams {
    /// Issue group id (from list results)
    group_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IgnoreIssueParams {
    /// Issue id
    issue_id: u64,
    /// Reason for ignoring the issue (recommended — it is recorded in the audit log)
    reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SnoozeIssueParams {
    /// Issue id
    issue_id: u64,
    /// Snooze duration in days, e.g. "7d", "30d", "90d"
    until: String,
    /// Reason for snoozing (recommended — it is recorded in the audit log)
    reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct AdjustSeverityParams {
    /// Issue id
    issue_id: u64,
    /// New severity level: critical|high|medium|low
    level: String,
    /// Reason for the adjustment (required — it is recorded in the audit log)
    reason: String,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ListReposParams {
    /// Maximum number of repositories to return (default: 100)
    limit: Option<usize>,
    /// Filter by repository name
    name: Option<String>,
    /// Include inactive repositories
    inactive: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScanRepoParams {
    /// Code repository id
    repo_id: u64,
    /// Include SAST scan
    sast: Option<bool>,
    /// Include IaC scan
    iac: Option<bool>,
    /// Include secrets scan
    secrets: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RepoIdParams {
    /// Code repository id
    repo_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ListContainersParams {
    /// Maximum number of containers to return (default: 100)
    limit: Option<usize>,
    /// Filter by container name
    name: Option<String>,
    /// Filter by container tag
    tag: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ContainerIdParams {
    /// Container repository id
    container_id: u64,
}

#[derive(Clone)]
struct AikidoServer;

#[tool_router(server_handler)]
impl AikidoServer {
    #[tool(
        name = "aikido_list_issues",
        description = "List Aikido security issues, filterable by severity, status, code repo, and container repo.",
        annotations(read_only_hint = true)
    )]
    async fn list_issues(
        &self,
        Parameters(params): Parameters<ListIssuesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let filters = IssueFilters {
            severity: params.severity,
            status: Some(params.status.unwrap_or_else(|| "open".to_string())),
            code_repo_name: params.repo,
            container_repo_name: params.container,
        };
        let issues = api::list_issues(&client()?, &filters, Some(params.limit.unwrap_or(100)))
            .await
            .map_err(to_error_data)?;
        json_result(&Value::Array(issues))
    }

    #[tool(
        name = "aikido_get_issue_group",
        description = "Get full details for an Aikido issue group: description, how to fix, CVEs, and affected locations.",
        annotations(read_only_hint = true)
    )]
    async fn get_issue_group(
        &self,
        Parameters(params): Parameters<IssueGroupParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let group = api::get_issue_group(&client()?, params.group_id)
            .await
            .map_err(to_error_data)?;
        json_result(&group)
    }

    #[tool(
        name = "aikido_ignore_issue",
        description = "Ignore an Aikido security issue. This is an audited, reversible mutation: the issue stops appearing in open listings, the action is recorded with your reason, and it can be undone from the Aikido dashboard."
    )]
    async fn ignore_issue(
        &self,
        Parameters(params): Parameters<IgnoreIssueParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::ignore_issue(&client()?, params.issue_id, params.reason.as_deref())
            .await
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Issue {} ignored.", params.issue_id)
        }))
    }

    #[tool(
        name = "aikido_snooze_issue",
        description = "Snooze an Aikido security issue for a number of days (e.g. until: \"7d\"). Audited and reversible: the issue reopens automatically when the snooze expires."
    )]
    async fn snooze_issue(
        &self,
        Parameters(params): Parameters<SnoozeIssueParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let (snooze_until, date) =
            until::parse_days(&params.until).map_err(|msg| ErrorData::invalid_params(msg, None))?;
        api::snooze_issue(
            &client()?,
            params.issue_id,
            snooze_until,
            params.reason.as_deref(),
        )
        .await
        .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Issue {} snoozed until {date}.", params.issue_id)
        }))
    }

    #[tool(
        name = "aikido_adjust_severity",
        description = "Adjust the severity of an Aikido security issue. This is an audited, reversible mutation: the adjustment and reason are recorded, and the original severity can be restored from the Aikido dashboard."
    )]
    async fn adjust_severity(
        &self,
        Parameters(params): Parameters<AdjustSeverityParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::adjust_severity(&client()?, params.issue_id, &params.level, &params.reason)
            .await
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Issue {} severity adjusted to {}.", params.issue_id, params.level)
        }))
    }

    #[tool(
        name = "aikido_list_repos",
        description = "List code repositories connected to Aikido.",
        annotations(read_only_hint = true)
    )]
    async fn list_repos(
        &self,
        Parameters(params): Parameters<ListReposParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::list_code_repos(
            &client()?,
            params.limit.unwrap_or(100),
            params.name.as_deref(),
            params.inactive.unwrap_or(false),
        )
        .await
        .map_err(to_error_data)
        .and_then(|repos| json_result(&Value::Array(repos)))
    }

    #[tool(
        name = "aikido_scan_repo",
        description = "Trigger an Aikido scan for a code repository, optionally including SAST, IaC, and secrets scans."
    )]
    async fn scan_repo(
        &self,
        Parameters(params): Parameters<ScanRepoParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::scan_repo(
            &client()?,
            params.repo_id,
            params.sast.unwrap_or(false),
            params.iac.unwrap_or(false),
            params.secrets.unwrap_or(false),
        )
        .await
        .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Scan initiated for repository {}.", params.repo_id)
        }))
    }

    #[tool(
        name = "aikido_repo_licenses",
        description = "Export license information for a code repository's dependencies.",
        annotations(read_only_hint = true)
    )]
    async fn repo_licenses(
        &self,
        Parameters(params): Parameters<RepoIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::repo_licenses(&client()?, params.repo_id)
            .await
            .map_err(to_error_data)
            .and_then(|packages| json_result(&Value::Array(packages)))
    }

    #[tool(
        name = "aikido_list_containers",
        description = "List container repositories monitored by Aikido.",
        annotations(read_only_hint = true)
    )]
    async fn list_containers(
        &self,
        Parameters(params): Parameters<ListContainersParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::list_containers(
            &client()?,
            params.limit.unwrap_or(100),
            params.name.as_deref(),
            params.tag.as_deref(),
        )
        .await
        .map_err(to_error_data)
        .and_then(|containers| json_result(&Value::Array(containers)))
    }

    #[tool(
        name = "aikido_get_container",
        description = "Get details for a container repository.",
        annotations(read_only_hint = true)
    )]
    async fn get_container(
        &self,
        Parameters(params): Parameters<ContainerIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let container = api::get_container(&client()?, params.container_id)
            .await
            .map_err(to_error_data)?;
        json_result(&container)
    }

    #[tool(
        name = "aikido_container_licenses",
        description = "Export license information for a container repository.",
        annotations(read_only_hint = true)
    )]
    async fn container_licenses(
        &self,
        Parameters(params): Parameters<ContainerIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::container_licenses(&client()?, params.container_id)
            .await
            .map_err(to_error_data)
            .and_then(|packages| json_result(&Value::Array(packages)))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = AikidoServer.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
