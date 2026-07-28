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
    about = "Aikido Security CLI",
    long_about = "A command-line interface for the Aikido Security API.\n\n\
        Credentials: `aikido auth login` (stored in the OS keychain, service \
        'aikido-cli', or ~/.config/aikido/credentials.json), or the env vars \
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
    /// Show details for a specific issue group
    Show { group_id: u64 },
    /// Ignore a security issue (audited, reversible)
    Ignore {
        issue_id: u64,
        /// Reason for ignoring the issue
        #[arg(long)]
        reason: Option<String>,
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
            IssuesCommand::Show { group_id } => issues::show(flags, group_id).await,
            IssuesCommand::Ignore { issue_id, reason } => {
                issues::ignore(flags, issue_id, reason).await
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
