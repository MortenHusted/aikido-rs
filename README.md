# aikido-rs

Rust rewrite of the Go `aikido-cli`: a CLI (`aikido`) and an MCP server
(`aikido-mcp`) for the [Aikido Security](https://app.aikido.dev) REST API,
built on one shared core so auth and API behaviour cannot drift between them.

```
crates/aikido-core/   API client, OAuth auth, credential store, session resolution
crates/aikido-cli/    binary `aikido`
crates/aikido-mcp/    binary `aikido-mcp` (MCP server over stdio)
```

## Install

```sh
cargo install --path crates/aikido-cli --root ~/.local
cargo install --path crates/aikido-mcp --root ~/.local
```

This puts the binaries in `~/.local/bin`. Note: with `--root ~/.local` the
install location is explicit and independent of `CARGO_HOME` — relevant on
machines where mise sets `GOBIN`/`CARGO_HOME` to tool-managed directories, so
a bare `cargo install` would land the binary somewhere surprising.

## Authentication

```sh
aikido auth login     # prompts for the OAuth client ID + secret
aikido auth status    # validated with a live API call — see below
aikido auth logout
```

`auth login` picks up credentials from the first available source:

1. **Env vars** — when `AIKIDO_CLIENT_ID` and `AIKIDO_CLIENT_SECRET` are both
   set, they are used and no prompt appears. **Footgun**: a stale secret still
   exported in your shell (e.g. after a rotation) gets silently re-exchanged.
   Env-first precedence is kept because it matches how every other command
   resolves credentials and keeps CI scriptable — but login announces the
   source on stderr (`Using client credentials from AIKIDO_CLIENT_ID/...`)
   so it is never silent. Unset the vars to be prompted.
2. **Interactive prompt** — when stdin is a TTY. The client secret is read
   without echoing (via `rpassword`).
3. **Piped stdin** — when stdin is not a TTY, two lines are read: client ID,
   then client secret (`printf '%s\n%s\n' "$ID" "$SECRET" | aikido auth login`).
   Empty stdin fails with an `auth_error` envelope naming these alternatives
   (the Go CLI died with a bare `EOF` here).

Credentials (client id, client secret, current access token, expiry) are
stored in the OS keychain under service `aikido-cli` (user `default`), with a
plaintext fallback at `~/.config/aikido/credentials.json` (mode 0600). The
stored format is identical to the Go CLI's — including go-keyring's payload
encoding — so existing logins keep working, in both directions.

On Linux the OS keychain backend is not built — the `keyring` dependency is
scoped to macOS and Windows, so credentials always live in the 0600 file at
`~/.config/aikido/credentials.json` and `AIKIDO_TOKEN_STORE=keychain` is
rejected. This is deliberate: Linux secret-service support drags in a D-Bus
dependency stack for a platform where this CLI runs headless anyway.

> Interop note: the Go CLI's keychain library (zalando/go-keyring) stores
> every value as `go-keyring-base64:` + base64(JSON), not raw JSON. This CLI
> decodes that prefix (and the legacy `go-keyring-encoded:` hex prefix) on
> read and writes the same base64-prefixed format, so entries stay readable
> whichever binary wrote them last.

Environment variables:

| Variable | Effect |
|---|---|
| `AIKIDO_TOKEN` | Access-token override (wins over the store) |
| `AIKIDO_CLIENT_ID` / `AIKIDO_CLIENT_SECRET` | OAuth client credentials (win over stored ones) |
| `AIKIDO_TOKEN_STORE` | `file` or `keychain`; default: keychain with file fallback |
| `AIKIDO_CONFIG_DIR` | Config dir override (default `~/.config/aikido`) |
| `AIKIDO_BASE_URL` | API base override (tests/dev; default `https://app.aikido.dev`) |

Auth semantics — deliberate fixes over the Go CLI:

- **Refresh always works.** Any client carries the OAuth client credentials
  when they are available, whatever the token source. A revoked or expired
  `AIKIDO_TOKEN` recovers via a transparent 401 → token-exchange → retry
  instead of failing hard.
- **Refreshed tokens are persisted.** After a 401 refresh the new access
  token and its expiry are written back to the credential store, so the next
  invocation authenticates on the first try. (Env-provided secrets are never
  written to disk as a side effect.)
- **`auth status` validates.** When a token exists, status makes one cheap
  authenticated call. `authenticated: true` means the token *worked* just
  now; a failed check reports `authenticated: false`; if the check cannot run
  (network down) the output says plainly that validity is unchecked
  (`checked: false`). Presence is never reported as validity.

## Commands

```
aikido auth login|status|logout
aikido issues list      [--severity critical,high] [--status open] [--limit 100]
                        [--repo NAME] [--container NAME]
aikido issues show <group_id>
aikido issues ignore <id>   [--reason TEXT]
aikido issues snooze <id>   --until 7d [--reason TEXT]
aikido issues severity <id> --level low --reason TEXT
aikido repos list       [--limit 100] [--name NAME] [--inactive]
aikido repos scan <repo_id> [--sast] [--iac] [--secrets]
aikido repos licenses <repo_id>
aikido containers list  [--limit 100] [--name NAME] [--tag TAG] [--stale-days N]
aikido containers show <id>
aikido containers scan <id>
aikido containers licenses <id>
aikido api get <path>   [--query k=v ...]      # read-only raw passthrough
```

Container scan freshness: `containers list` shows Scanned/Pushed dates in
table output, and `--stale-days N` filters to active containers whose scan
coverage is stale — last scan older than N days, never scanned, or an image
pushed after the last scan (the failure mode where a silently stopped
scanner reports a healthy-looking low finding count). Each stale result
carries a `scan_staleness` object (`scan_age_days`, `pushed_after_scan`,
`tag_drift`, `reasons`) so the comparison is explicit rather than left to
eyeballing timestamps. `containers scan <id>` queues a rescan; the API is
fire-and-forget (no job handle), so completion shows up later as a new
`last_scanned_at`.

Global flags: `--json`, `--jq <expr>` (jq filtering via [jaq]), `--md`/`-m`,
`--quiet` (bare data, no envelope), `--verbose`/`-v`.

Format precedence: `--jq` > `--quiet` > `--json` > `--md` > auto (TTY gets
styled text, pipes get JSON).

[jaq]: https://crates.io/crates/jaq-core

## The JSON envelope contract

`--json` output is a hard interface consumed by scheduled automation:

```json
{"ok": true, "data": <any>, "summary": "...", "meta": {...}}
{"ok": false, "error": "...", "code": "...", "hint": "..."}
```

`data`, `summary`, `meta`, and `hint` are omitted when empty. Error codes:
`api_error`, `auth_error` (hint `Run: aikido auth login`), `not_found`,
`rate_limit` (hint `Wait and retry`).

**Changes from the Go CLI** (shape kept, plumbing fixed):

- Error envelopes go to **stderr** with a **non-zero exit** (1 for API
  errors, 4 for auth errors, 2 for usage errors). The Go CLI printed some
  error envelopes to stdout and exited 0.
- The `code` field carries the real error class. The Go commands hardcoded
  `"api_error"` for every failure; `not_found`, `auth_error`, and
  `rate_limit` (plus their hints) now actually appear.
- Mutation commands (`ignore`, `snooze`, `severity`, `scan`) emit a
  `{"ok": true, "summary": "..."}` envelope on stdout in JSON mode. The Go
  CLI printed nothing to stdout on mutation success.
- JSON output does not HTML-escape `<`, `>`, `&` (Go's encoder wrote
  `<` etc.). Both encodings are equivalent to any JSON parser.

## MCP server

`aikido-mcp` speaks MCP over stdio and uses the same credential store and
refresh logic as the CLI. Register it e.g. in Claude Code:

```sh
claude mcp add aikido -- ~/.local/bin/aikido-mcp
```

Tools:

| Tool | Kind | Description |
|---|---|---|
| `aikido_list_issues` | read | List issues (severity/status/repo/container filters, limit) |
| `aikido_get_issue_group` | read | Full detail for an issue group |
| `aikido_ignore_issue` | mutation | Ignore an issue — audited, reversible |
| `aikido_snooze_issue` | mutation | Snooze an issue for N days (`until: "7d"`) — audited, reversible |
| `aikido_adjust_severity` | mutation | Adjust issue severity — audited, reversible |
| `aikido_list_repos` | read | List code repositories |
| `aikido_scan_repo` | mutation | Trigger a repo scan (SAST/IaC/secrets flags) |
| `aikido_repo_licenses` | read | License export for a repo |
| `aikido_list_containers` | read | List container repositories with scan freshness; `stale_days` filters to stale coverage |
| `aikido_scan_container` | mutation | Queue a container scan (fire-and-forget, no job handle) |
| `aikido_get_container` | read | Container detail |
| `aikido_container_licenses` | read | License export for a container |

## Development

```sh
cargo build --workspace
cargo test --workspace          # wiremock + assert_cmd; never touches the real keychain or API
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Tests pin the credential store to a temp-dir file backend
(`AIKIDO_TOKEN_STORE=file`, `AIKIDO_CONFIG_DIR=<tempdir>`) and point
`AIKIDO_BASE_URL` at a wiremock server. A default `cargo test` is fully
non-interactive.

The exception is the two macOS keychain interop tests, which are `#[ignore]`
because reading a keychain item written by another process pops a modal ACL
prompt (the test binary's signature changes every rebuild, so the approval
can never stick). Run them deliberately when touching credential code:

```sh
cargo test -p aikido-core --test keychain_interop -- --ignored
```

They use throwaway `aikido-cli-interop-check-*` service names and clean up
after themselves; the go-keyring payload codec they guard is also covered by
always-on unit tests. This is the one code path where a default `cargo test`
is not full coverage.
