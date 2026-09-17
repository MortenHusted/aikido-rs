//! `aikido` — Aikido Security from the terminal.
//!
//! Thin shell: clap parsing and the single exit-code mapping. Behaviour
//! lives in the library; auth and API logic live in `aikido-core`, shared
//! with the MCP server.
//!
//! Exit codes:
//!   0  success
//!   1  runtime / API error (envelope on stderr)
//!   2  usage error (clap)
//!   4  authentication required or invalid

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use aikido_cli::commands::{api, auth, containers, issues, repos};
use aikido_cli::output::{render_err, GlobalFlags};
use aikido_core::error::ApiError;

#[derive(Debug, Parser)]
#[command(
    name = "aikido",
    version,
    about = "Unofficial Aikido Security CLI",
    long_about = "An unofficial command-line interface for the Aikido Security public API \
        (not affiliated with Aikido Security).\n\n\
        Credentials: `aikido auth login` (stored in the OS keychain, service \
        'aikido-cli', or credentials.json in the platform config dir — \
        ~/Library/Application Support/aikido on macOS, ~/.config/aikido on \
        Linux; override with AIKIDO_CONFIG_DIR), or the env vars \
        AIKIDO_TOKEN / AIKIDO_CLIENT_ID / AIKIDO_CLIENT_SECRET."
)]
struct Cli {
    #[command(flatten)]
    global: CliGlobalArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct CliGlobalArgs {
    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,

    /// Filter JSON output with a jq expression
    #[arg(long, global = true, value_name = "EXPR")]
    jq: Option<String>,

    /// Output as Markdown
    #[arg(long, short = 'm', global = true)]
    md: bool,

    /// Suppress the envelope; print only the data
    #[arg(long, global = true)]
    quiet: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', global = true)]
    verbose: bool,
}

impl CliGlobalArgs {
    fn flags(&self) -> GlobalFlags {
        GlobalFlags {
            json: self.json,
            jq: self.jq.clone(),
            md: self.md,
            quiet: self.quiet,
            verbose: self.verbose,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage authentication credentials
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Manage Aikido security issues
    Issues {
        #[command(subcommand)]
        command: IssuesCommand,
    },
    /// Manage Aikido code repositories
    Repos {
        #[command(subcommand)]
        command: ReposCommand,
    },
    /// Manage Aikido container repositories
    Containers {
        #[command(subcommand)]
        command: ContainersCommand,
    },
    /// Raw read-only access to the Aikido public API
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ApiCommand {
    /// GET a path relative to the API base (e.g. /openapi/spec)
    Get {
        /// Path relative to https://app.aikido.dev/api/public/v1
        path: String,
        /// Query parameter as k=v (repeatable)
        #[arg(long = "query", value_name = "K=V")]
        query: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Authenticate with Aikido using client credentials
    Login,
    /// Show current authentication status (validated with a live API call)
    Status,
    /// Remove stored authentication credentials
    Logout,
}

#[derive(Debug, Subcommand)]
enum IssuesCommand {
    /// List security issues
    List {
        /// Filter by severity: critical|high|medium|low (comma-separated)
        #[arg(long)]
        severity: Option<String>,
        /// Filter by status: open|ignored|snoozed|closed
        #[arg(long, default_value = "open")]
        status: String,
        /// Maximum number of issues to display
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Filter by code repository name
        #[arg(long)]
        repo: Option<String>,
        /// Filter by container repository name
        #[arg(long)]
        container: Option<String>,
    },
    /// Severity counts on both axes: issue groups (the dashboard's "Open
    /// Issues" unit) and individual issues (the rows `issues list` returns).
    /// These are different units — this command exists to keep them apart.
    Counts {
        /// Filter by code repository name
        #[arg(long)]
        repo: Option<String>,
        /// Filter by Aikido code repository id
        #[arg(long)]
        repo_id: Option<u64>,
        /// Filter by the provider's repository id
        #[arg(long)]
        external_repo_id: Option<String>,
        /// Filter by container repository id
        #[arg(long)]
        container_id: Option<u64>,
        /// Filter by team id
        #[arg(long)]
        team_id: Option<u64>,
        /// Only count issues created after this: '7d' (last 7 days) or a
        /// unix-seconds timestamp
        #[arg(long)]
        since: Option<String>,
    },
    /// Show details for a specific issue group
    Show { group_id: u64 },
    /// Issue groups — the unit the Aikido dashboard counts. Group mutations
    /// act on the vulnerability across EVERY repo, container, and cloud in
    /// the group, not just one repo.
    Groups {
        #[command(subcommand)]
        command: GroupsCommand,
    },
    /// Ignore a security issue (audited, reversible via `issues unignore`)
    Ignore {
        issue_id: u64,
        /// Reason for ignoring the issue
        #[arg(long)]
        reason: Option<String>,
    },
    /// Reverse an ignore on a single issue
    Unignore {
        issue_id: u64,
        /// Reason for unignoring
        #[arg(long)]
        reason: Option<String>,
        /// Apply across all tags of the affected image
        #[arg(long)]
        all_tags: bool,
    },
    /// Reverse a snooze on a single issue
    Unsnooze {
        issue_id: u64,
        /// Apply across all tags of the affected image
        #[arg(long)]
        all_tags: bool,
    },
    /// Snooze a security issue until a future date
    Snooze {
        issue_id: u64,
        /// Duration to snooze (e.g. 7d, 30d, 90d)
        #[arg(long)]
        until: String,
        /// Reason for snoozing the issue
        #[arg(long)]
        reason: Option<String>,
    },
    /// Adjust the severity of a security issue (audited, reversible)
    Severity {
        issue_id: u64,
        /// New severity level: critical|high|medium|low
        #[arg(long)]
        level: String,
        /// Reason for severity adjustment
        #[arg(long)]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
enum GroupsCommand {
    /// List open issue groups (the dashboard's "Open Issues" listing).
    /// Location filters return groups that TOUCH the location — results may
    /// span other repos, containers, and clouds.
    List {
        /// Filter by code repository name (groups touching it)
        #[arg(long)]
        repo: Option<String>,
        /// Filter by Aikido code repository id
        #[arg(long)]
        repo_id: Option<u64>,
        /// Filter by the provider's repository id
        #[arg(long)]
        external_repo_id: Option<String>,
        /// Filter by container repository id
        #[arg(long)]
        container_id: Option<u64>,
        /// Filter by team id
        #[arg(long)]
        team_id: Option<u64>,
        /// Filter by issue type
        #[arg(long = "type")]
        issue_type: Option<String>,
        /// Filter by status (server default: open)
        #[arg(long)]
        status: Option<String>,
        /// Maximum number of groups to fetch
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Ignore a whole group — acts on the vulnerability across EVERY repo,
    /// container, and cloud in the group. Audited, reversible via
    /// `issues groups unignore`.
    Ignore {
        group_id: u64,
        /// Reason for ignoring (recorded in the audit log)
        #[arg(long)]
        reason: Option<String>,
    },
    /// Snooze a whole group — acts across EVERY location in the group.
    Snooze {
        group_id: u64,
        /// Duration to snooze (e.g. 7d, 30d, 90d)
        #[arg(long)]
        until: String,
        /// Reason for snoozing (recorded in the audit log)
        #[arg(long)]
        reason: Option<String>,
    },
    /// Adjust a whole group's severity — acts across EVERY location in the
    /// group. Audited, reversible.
    Severity {
        group_id: u64,
        /// New severity level: critical|high|medium|low
        #[arg(long)]
        level: String,
        /// Reason for the adjustment (recorded in the audit log)
        #[arg(long)]
        reason: String,
    },
    /// Reverse an ignore on a whole group
    Unignore {
        group_id: u64,
        /// Reason for unignoring
        #[arg(long)]
        reason: Option<String>,
    },
    /// Reverse a snooze on a whole group
    Unsnooze { group_id: u64 },
}

#[derive(Debug, Subcommand)]
enum ReposCommand {
    /// List code repositories
    List {
        /// Maximum number of repositories to fetch
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Filter by repository name
        #[arg(long)]
        name: Option<String>,
        /// Include inactive repositories
        #[arg(long)]
        inactive: bool,
    },
    /// Trigger a scan for a code repository
    Scan {
        repo_id: u64,
        /// Include SAST scan
        #[arg(long)]
        sast: bool,
        /// Include IaC scan
        #[arg(long)]
        iac: bool,
        /// Include secrets scan
        #[arg(long)]
        secrets: bool,
    },
    /// Export license information for a code repository
    Licenses { repo_id: u64 },
}

#[derive(Debug, Subcommand)]
enum ContainersCommand {
    /// List container repositories with scan/push freshness
    List {
        /// Maximum number of containers to fetch
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Filter by container name
        #[arg(long)]
        name: Option<String>,
        /// Filter by container tag
        #[arg(long)]
        tag: Option<String>,
        /// Show only active containers whose scan coverage is stale: last
        /// scan older than N days, never scanned, or image pushed after the
        /// last scan. Each result gains a `scan_staleness` object with the
        /// derived facts.
        #[arg(long, value_name = "N")]
        stale_days: Option<i64>,
    },
    /// Show details for a container repository
    Show { container_id: u64 },
    /// Queue a scan for a container. Returns as soon as the scan is
    /// accepted — the API provides no job handle, so completion must be
    /// observed via last_scanned_at.
    Scan { container_id: u64 },
    /// Export license information for a container repository
    Licenses { container_id: u64 },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let flags = cli.global.flags();

    match run(cli.command, &flags).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            render_err(&flags.format(), &err);
            match err {
                ApiError::Auth { .. } => ExitCode::from(4),
                _ => ExitCode::from(1),
            }
        }
    }
}

async fn run(command: Command, flags: &GlobalFlags) -> Result<(), ApiError> {
    match command {
        Command::Auth { command } => match command {
            AuthCommand::Login => auth::login(flags).await,
            AuthCommand::Status => auth::status(flags).await,
            AuthCommand::Logout => auth::logout(flags),
        },
        Command::Issues { command } => match command {
            IssuesCommand::List {
                severity,
                status,
                limit,
                repo,
                container,
            } => issues::list(flags, severity, Some(status), limit, repo, container).await,
            IssuesCommand::Counts {
                repo,
                repo_id,
                external_repo_id,
                container_id,
                team_id,
                since,
            } => {
                let since_timestamp = since
                    .as_deref()
                    .map(aikido_core::until::parse_since)
                    .transpose()
                    .map_err(|msg| ApiError::Api {
                        status: 400,
                        message: format!("invalid --since value: {msg}"),
                    })?;
                let filters = aikido_core::api::CountFilters {
                    code_repo_id: repo_id,
                    external_code_repo_id: external_repo_id,
                    code_repo_name: repo,
                    container_repo_id: container_id,
                    team_id,
                    since_timestamp,
                };
                issues::counts(flags, &filters).await
            }
            IssuesCommand::Show { group_id } => issues::show(flags, group_id).await,
            IssuesCommand::Groups { command } => match command {
                GroupsCommand::List {
                    repo,
                    repo_id,
                    external_repo_id,
                    container_id,
                    team_id,
                    issue_type,
                    status,
                    limit,
                } => {
                    let filters = aikido_core::api::GroupFilters {
                        code_repo_id: repo_id,
                        external_code_repo_id: external_repo_id,
                        code_repo_name: repo,
                        container_repo_id: container_id,
                        team_id,
                        issue_type,
                        status,
                    };
                    issues::groups_list(flags, &filters, limit).await
                }
                GroupsCommand::Ignore { group_id, reason } => {
                    issues::groups_ignore(flags, group_id, reason).await
                }
                GroupsCommand::Snooze {
                    group_id,
                    until,
                    reason,
                } => issues::groups_snooze(flags, group_id, &until, reason).await,
                GroupsCommand::Severity {
                    group_id,
                    level,
                    reason,
                } => issues::groups_severity(flags, group_id, &level, &reason).await,
                GroupsCommand::Unignore { group_id, reason } => {
                    issues::groups_unignore(flags, group_id, reason).await
                }
                GroupsCommand::Unsnooze { group_id } => {
                    issues::groups_unsnooze(flags, group_id).await
                }
            },
            IssuesCommand::Ignore { issue_id, reason } => {
                issues::ignore(flags, issue_id, reason).await
            }
            IssuesCommand::Unignore {
                issue_id,
                reason,
                all_tags,
            } => issues::unignore(flags, issue_id, reason, all_tags).await,
            IssuesCommand::Unsnooze { issue_id, all_tags } => {
                issues::unsnooze(flags, issue_id, all_tags).await
            }
            IssuesCommand::Snooze {
                issue_id,
                until,
                reason,
            } => issues::snooze(flags, issue_id, &until, reason).await,
            IssuesCommand::Severity {
                issue_id,
                level,
                reason,
            } => issues::severity(flags, issue_id, &level, &reason).await,
        },
        Command::Repos { command } => match command {
            ReposCommand::List {
                limit,
                name,
                inactive,
            } => repos::list(flags, limit, name, inactive).await,
            ReposCommand::Scan {
                repo_id,
                sast,
                iac,
                secrets,
            } => repos::scan(flags, repo_id, sast, iac, secrets).await,
            ReposCommand::Licenses { repo_id } => repos::licenses(flags, repo_id).await,
        },
        Command::Containers { command } => match command {
            ContainersCommand::List {
                limit,
                name,
                tag,
                stale_days,
            } => containers::list(flags, limit, name, tag, stale_days).await,
            ContainersCommand::Show { container_id } => containers::show(flags, container_id).await,
            ContainersCommand::Scan { container_id } => containers::scan(flags, container_id).await,
            ContainersCommand::Licenses { container_id } => {
                containers::licenses(flags, container_id).await
            }
        },
        Command::Api { command } => match command {
            ApiCommand::Get { path, query } => api::get(flags, &path, &query).await,
        },
    }
}
