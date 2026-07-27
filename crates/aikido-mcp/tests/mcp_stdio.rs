//! End-to-end MCP tests: spawn the real `aikido-mcp` binary, speak JSON-RPC
//! over stdio, and point it at a wiremock API via the same env knobs the
//! CLI tests use — the real keychain and live API are never touched.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct McpServer {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpServer {
    /// Spawn `aikido-mcp` against `base_url` with credentials stored in
    /// `config_dir`, and complete the MCP initialize handshake.
    fn start(base_url: &str, config_dir: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_aikido-mcp"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("AIKIDO_BASE_URL", base_url)
            .env("AIKIDO_TOKEN_STORE", "file")
            .env("AIKIDO_CONFIG_DIR", config_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning aikido-mcp");
        let reader = BufReader::new(child.stdout.take().expect("child stdout"));
        let mut server = Self { child, reader };

        let init = server.request(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "0" }
            }
        }));
        assert!(init["result"]["capabilities"]["tools"].is_object());
        server.notify(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        server
    }

    fn notify(&mut self, message: Value) {
        let stdin = self.child.stdin.as_mut().expect("child stdin");
        writeln!(stdin, "{message}").expect("writing to aikido-mcp");
    }

    /// Send a request and read messages until its response arrives.
    fn request(&mut self, message: Value) -> Value {
        let id = message["id"].clone();
        self.notify(message);
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).expect("reading response");
            assert!(read > 0, "aikido-mcp closed stdout before responding");
            let response: Value = serde_json::from_str(&line).expect("JSON-RPC line");
            if response["id"] == id {
                return response;
            }
        }
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_credentials(dir: &std::path::Path, access_token: &str) {
    std::fs::write(
        dir.join("credentials.json"),
        json!({
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "access_token": access_token,
            "expires_at": "2030-01-01T00:00:00Z",
        })
        .to_string(),
    )
    .unwrap();
}

/// The text content of a successful tool result, parsed as JSON.
fn tool_json(response: &Value) -> Value {
    assert_eq!(
        response["result"]["isError"], false,
        "tool errored: {response}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).expect("tool text content is JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_all_eleven_tools_with_descriptions() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut mcp = McpServer::start(&server.uri(), dir.path());

    let response = mcp.request(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 11);
    for expected in [
        "aikido_list_issues",
        "aikido_get_issue_group",
        "aikido_ignore_issue",
        "aikido_snooze_issue",
        "aikido_adjust_severity",
        "aikido_list_repos",
        "aikido_scan_repo",
        "aikido_repo_licenses",
        "aikido_list_containers",
        "aikido_get_container",
        "aikido_container_licenses",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }

    // Mutating tools must say they are audited, reversible mutations.
    for mutating in ["aikido_ignore_issue", "aikido_adjust_severity"] {
        let tool = tools.iter().find(|t| t["name"] == mutating).unwrap();
        let description = tool["description"].as_str().unwrap();
        assert!(
            description.contains("audited") && description.contains("reversible"),
            "{mutating} description must flag the mutation: {description}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn list_issues_passes_filters_and_returns_the_api_payload() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(query_param("filter_severities", "critical"))
        .and(query_param("filter_status", "open"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "id": 1, "severity": "critical", "cve_id": "CVE-2026-0001", "status": "open" }
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token");
    let mut mcp = McpServer::start(&server.uri(), dir.path());

    let response = mcp.call_tool(2, "aikido_list_issues", json!({ "severity": "critical" }));
    let issues = tool_json(&response);
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["cve_id"], "CVE-2026-0001");
}

#[tokio::test(flavor = "multi_thread")]
async fn adjust_severity_posts_the_mutation_through_shared_core() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/public/v1/issues/5/severity/adjust"))
        .and(body_json(
            json!({ "adjusted_severity": "low", "reason": "test env" }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true})))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "valid-token");
    let mut mcp = McpServer::start(&server.uri(), dir.path());

    let response = mcp.call_tool(
        2,
        "aikido_adjust_severity",
        json!({ "issue_id": 5, "level": "low", "reason": "test env" }),
    );
    let result = tool_json(&response);
    assert_eq!(result["ok"], true);
    assert_eq!(result["summary"], "Issue 5 severity adjusted to low.");
}

/// Same 401-refresh behaviour as the CLI — the shared core is the point.
#[tokio::test(flavor = "multi_thread")]
async fn expired_token_refreshes_and_persists_like_the_cli() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer stale-token",
        ))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/public/v1/issues/export"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer fresh-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    write_credentials(dir.path(), "stale-token");
    let mut mcp = McpServer::start(&server.uri(), dir.path());

    let response = mcp.call_tool(2, "aikido_list_issues", json!({}));
    assert!(tool_json(&response).as_array().unwrap().is_empty());

    let creds: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("credentials.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(creds["access_token"], "fresh-token");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_credentials_is_a_tool_error_with_the_auth_hint() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap(); // no credentials
    let mut mcp = McpServer::start(&server.uri(), dir.path());

    let response = mcp.call_tool(2, "aikido_list_issues", json!({}));
    let error = &response["error"];
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("not authenticated"),
        "unexpected error: {response}"
    );
    assert_eq!(error["data"]["hint"], "Run: aikido auth login");
}
