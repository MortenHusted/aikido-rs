//! `aikido-mcp` — MCP server exposing the Aikido Security API over stdio.
//!
//! Every tool goes through `aikido-core`, the same client/auth code the
//! `aikido` CLI uses, so token refresh and persistence behave identically.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CacheScope, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler, ServiceExt};
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

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct IssueCountsParams {
    /// Filter by code repository name
    repo: Option<String>,
    /// Filter by Aikido code repository id
    repo_id: Option<u64>,
    /// Filter by container repository id
    container_id: Option<u64>,
    /// Filter by team id
    team_id: Option<u64>,
    /// Only count issues created after this: "7d" (last 7 days) or a
    /// unix-seconds timestamp
    since: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IssueGroupParams {
    /// Issue group id (from list results)
    group_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema, Default)]
struct ListGroupsParams {
    /// Filter by code repository name (returns groups TOUCHING it; they may span other locations)
    repo: Option<String>,
    /// Filter by Aikido code repository id
    repo_id: Option<u64>,
    /// Filter by container repository id
    container_id: Option<u64>,
    /// Filter by team id
    team_id: Option<u64>,
    /// Filter by issue type
    issue_type: Option<String>,
    /// Filter by status (server default: open)
    status: Option<String>,
    /// Maximum number of groups to return (default: 100)
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GroupIgnoreParams {
    /// Issue group id
    group_id: u64,
    /// Reason (recorded in the audit log)
    reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GroupSnoozeParams {
    /// Issue group id
    group_id: u64,
    /// Snooze duration in days, e.g. "7d", "30d", "90d"
    until: String,
    /// Reason (recorded in the audit log)
    reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GroupSeverityParams {
    /// Issue group id
    group_id: u64,
    /// New severity level: critical|high|medium|low
    level: String,
    /// Reason (recorded in the audit log)
    reason: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GroupIdParams {
    /// Issue group id
    group_id: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UnignoreIssueParams {
    /// Issue id
    issue_id: u64,
    /// Reason for unignoring
    reason: Option<String>,
    /// Apply across all tags of the affected image
    apply_for_all_tags: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct UnsnoozeIssueParams {
    /// Issue id
    issue_id: u64,
    /// Apply across all tags of the affected image
    apply_for_all_tags: Option<bool>,
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
    /// Return only active containers whose scan coverage is stale: last scan
    /// older than this many days, never scanned, or image pushed after the
    /// last scan. Each result gains a scan_staleness object.
    stale_days: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ContainerIdParams {
    /// Container repository id
    container_id: u64,
}

#[derive(Clone)]
struct AikidoServer;

#[tool_router]
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
            issue_group_id: None,
        };
        let issues = api::list_issues(&client()?, &filters, Some(params.limit.unwrap_or(100)))
            .await
            .map_err(to_error_data)?;
        json_result(&Value::Array(issues))
    }

    #[tool(
        name = "aikido_issue_counts",
        description = "Severity-bucketed counts on BOTH axes: issue_groups is the unit behind the Aikido dashboard's 'Open Issues' figure; issues counts individual findings — the rows aikido_list_issues returns. One group can contain many issues (and can span code repos, containers, and clouds), so the two numbers are different units: never compare a group count to an issue count.",
        annotations(read_only_hint = true)
    )]
    async fn issue_counts(
        &self,
        Parameters(params): Parameters<IssueCountsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let since_timestamp = params
            .since
            .as_deref()
            .map(until::parse_since)
            .transpose()
            .map_err(|msg| ErrorData::invalid_params(msg, None))?;
        let filters = api::CountFilters {
            code_repo_id: params.repo_id,
            external_code_repo_id: None,
            code_repo_name: params.repo,
            container_repo_id: params.container_id,
            team_id: params.team_id,
            since_timestamp,
        };
        let counts = api::issue_counts(&client()?, &filters)
            .await
            .map_err(to_error_data)?;
        json_result(&counts)
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
        name = "aikido_list_issue_groups",
        description = "List open issue groups — the unit the Aikido dashboard's 'Open Issues' figure counts. Location filters (repo/container) return groups that TOUCH that location; a group is keyed by the vulnerability and its locations may also span other repos, containers, and clouds.",
        annotations(read_only_hint = true)
    )]
    async fn list_issue_groups(
        &self,
        Parameters(params): Parameters<ListGroupsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let filters = api::GroupFilters {
            code_repo_id: params.repo_id,
            external_code_repo_id: None,
            code_repo_name: params.repo,
            container_repo_id: params.container_id,
            team_id: params.team_id,
            issue_type: params.issue_type,
            status: params.status,
        };
        let groups = api::list_open_issue_groups(&client()?, &filters, params.limit.unwrap_or(100))
            .await
            .map_err(to_error_data)?;
        json_result(&Value::Array(groups))
    }

    /// Shared adapter tail for guarded forward group mutations. Core owns
    /// affected-count verification; this adapter owns the MCP result shape.
    fn group_mutation_result(
        group_id: u64,
        blast: api::GroupBlastRadius,
        affected: Option<u64>,
        verb: &str,
    ) -> Result<CallToolResult, ErrorData> {
        api::verify_group_mutation_count(group_id, &blast, affected, verb)
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "group_id": group_id,
            "locations": blast.locations,
            "expected_issues": blast.expected_issues,
            "affected_issues": affected,
            "summary": format!("Group {group_id} {verb}."),
        }))
    }

    #[tool(
        name = "aikido_ignore_issue_group",
        description = "Ignore a whole issue group. WORKSPACE-WIDE: this acts on the vulnerability across EVERY repo, container, and cloud in the group's locations — it is NOT scoped to one repo, even if the group was found via a repo filter. Audited and reversible via aikido_unignore_issue_group. The result reports the locations touched and asserts the affected-issue count against a preflight expectation."
    )]
    async fn ignore_issue_group(
        &self,
        Parameters(params): Parameters<GroupIgnoreParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = client()?;
        let blast = api::group_blast_radius(&client, params.group_id)
            .await
            .map_err(to_error_data)?;
        let affected = api::ignore_issue_group(&client, params.group_id, params.reason.as_deref())
            .await
            .map_err(to_error_data)?;
        Self::group_mutation_result(params.group_id, blast, affected, "ignored")
    }

    #[tool(
        name = "aikido_snooze_issue_group",
        description = "Snooze a whole issue group for N days (until: \"7d\"). WORKSPACE-WIDE: acts on the vulnerability across EVERY repo, container, and cloud in the group's locations — NOT scoped to one repo. Reversible via aikido_unsnooze_issue_group."
    )]
    async fn snooze_issue_group(
        &self,
        Parameters(params): Parameters<GroupSnoozeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let (snooze_until, date) =
            until::parse_days(&params.until).map_err(|msg| ErrorData::invalid_params(msg, None))?;
        let client = client()?;
        let blast = api::group_blast_radius(&client, params.group_id)
            .await
            .map_err(to_error_data)?;
        let affected = api::snooze_issue_group(
            &client,
            params.group_id,
            snooze_until,
            params.reason.as_deref(),
        )
        .await
        .map_err(to_error_data)?;
        Self::group_mutation_result(
            params.group_id,
            blast,
            affected,
            &format!("snoozed until {date}"),
        )
    }

    #[tool(
        name = "aikido_adjust_group_severity",
        description = "Adjust a whole issue group's severity. WORKSPACE-WIDE: acts on the vulnerability across EVERY repo, container, and cloud in the group's locations — NOT scoped to one repo. Audited and reversible. The API reports no per-issue count for this operation; the result carries the preflight expectation instead."
    )]
    async fn adjust_group_severity(
        &self,
        Parameters(params): Parameters<GroupSeverityParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let client = client()?;
        let blast = api::group_blast_radius(&client, params.group_id)
            .await
            .map_err(to_error_data)?;
        api::adjust_group_severity(&client, params.group_id, &params.level, &params.reason)
            .await
            .map_err(to_error_data)?;
        Self::group_mutation_result(
            params.group_id,
            blast,
            None,
            &format!("severity adjusted to {}", params.level),
        )
    }

    #[tool(
        name = "aikido_unignore_issue_group",
        description = "Reverse an ignore on a whole issue group. WORKSPACE-WIDE, like the ignore it reverses."
    )]
    async fn unignore_issue_group(
        &self,
        Parameters(params): Parameters<GroupIgnoreParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::unignore_issue_group(&client()?, params.group_id, params.reason.as_deref())
            .await
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Group {} unignored.", params.group_id)
        }))
    }

    #[tool(
        name = "aikido_unsnooze_issue_group",
        description = "Reverse a snooze on a whole issue group. WORKSPACE-WIDE, like the snooze it reverses."
    )]
    async fn unsnooze_issue_group(
        &self,
        Parameters(params): Parameters<GroupIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::unsnooze_issue_group(&client()?, params.group_id)
            .await
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Group {} unsnoozed.", params.group_id)
        }))
    }

    #[tool(
        name = "aikido_unignore_issue",
        description = "Reverse an ignore on a single issue (one instance, one location — the per-issue counterpart of the group verb)."
    )]
    async fn unignore_issue(
        &self,
        Parameters(params): Parameters<UnignoreIssueParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::unignore_issue(
            &client()?,
            params.issue_id,
            params.reason.as_deref(),
            params.apply_for_all_tags.unwrap_or(false),
        )
        .await
        .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Issue {} unignored.", params.issue_id)
        }))
    }

    #[tool(
        name = "aikido_unsnooze_issue",
        description = "Reverse a snooze on a single issue (one instance, one location)."
    )]
    async fn unsnooze_issue(
        &self,
        Parameters(params): Parameters<UnsnoozeIssueParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::unsnooze_issue(
            &client()?,
            params.issue_id,
            params.apply_for_all_tags.unwrap_or(false),
        )
        .await
        .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Issue {} unsnoozed.", params.issue_id)
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
        description = "List container repositories monitored by Aikido, including scan freshness (last_scanned_at, last_pushed_at; unix seconds, -1 = never). Pass stale_days to get only containers whose scan coverage is stale.",
        annotations(read_only_hint = true)
    )]
    async fn list_containers(
        &self,
        Parameters(params): Parameters<ListContainersParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let containers = api::list_containers(
            &client()?,
            params.limit.unwrap_or(100),
            params.name.as_deref(),
            params.tag.as_deref(),
        )
        .await
        .map_err(to_error_data)?;
        let containers = match params.stale_days {
            Some(days) => {
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock before 1970")
                    .as_secs() as i64;
                aikido_core::staleness::filter_stale(containers, now_ts, days).0
            }
            None => containers,
        };
        json_result(&Value::Array(containers))
    }

    #[tool(
        name = "aikido_scan_container",
        description = "Queue an Aikido scan for a container. Fire-and-forget: the call returns once the scan is accepted, with no job handle — completion shows up later as a new last_scanned_at on the container."
    )]
    async fn scan_container(
        &self,
        Parameters(params): Parameters<ContainerIdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        api::scan_container(&client()?, params.container_id)
            .await
            .map_err(to_error_data)?;
        json_result(&json!({
            "ok": true,
            "summary": format!("Scan queued for container {}.", params.container_id)
        }))
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

#[tool_handler]
impl ServerHandler for AikidoServer {
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = ListToolsResult::with_all_items(Self::tool_router().list_all());
        if context
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28)
        {
            // The catalog is compiled into the binary and identical for every
            // caller. A finite public TTL keeps prompt caches stable while
            // still allowing an installed update to refresh promptly.
            Ok(tools
                .with_ttl_ms(300_000)
                .with_cache_scope(CacheScope::Public))
        } else {
            // Legacy clients receive only fields defined by their negotiated
            // protocol, including clients that reject unknown result fields.
            Ok(tools)
        }
    }

    fn get_info(&self) -> ServerConfig {
        // rmcp's build-environment default identifies the SDK crate, not this
        // binary. Expose the application name and version alongside its
        // capabilities and modern cache hints.
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = AikidoServer.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
