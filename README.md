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

**The rebuild trap (macOS).** Keychain access is authorised *per binary*:
"Always Allow" grants the exact executable that asked, so every rebuild or
reinstall produces a binary macOS treats as a stranger, and its first
keychain read pops a SecurityAgent prompt. Interactively that is one extra
click. Unattended (launchd/cron) nobody can click — so the credential read
is bounded: 30s when stdin is a TTY (time for a present human to approve),
5s otherwise (a healthy keychain answers in milliseconds; anything longer
is an unanswerable dialog). On expiry the run fails with an error naming
the escapes instead of hanging: set `AIKIDO_TOKEN_STORE=file` or provide
`AIKIDO_TOKEN`. After any rebuild, run one interactive command (e.g.
`aikido auth status`) and approve the prompt before relying on unattended
runs. The symptom without this bound was a silent indefinite hang with no
hint that a GUI dialog was involved.

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
plaintext fallback at `credentials.json` (mode 0600) in the platform config
dir — `~/Library/Application Support/aikido/` on macOS,
`~/.config/aikido/` on Linux; override with `AIKIDO_CONFIG_DIR`. (The Go
CLI resolves the same platform paths via `os.UserConfigDir`.) The
stored format is identical to the Go CLI's — including go-keyring's payload
encoding — so existing logins keep working, in both directions.

The fallback is never silent. `auth login` reports which backend received the
secret (`store: "keychain" | "file"` in the JSON envelope, plus
`keychain_fallback: true` when the keychain refused the write and the file
took it), and a 401 refresh that has to fall back to the file warns on
stderr. The file is created owner-only from its first byte and swapped into
place atomically, so a crash mid-write cannot leave a truncated or
world-readable copy behind; the config directory is created `0700`.

The OS keychain backend is built on macOS only. Everywhere else the
default backend is the file, `AIKIDO_TOKEN_STORE=keychain` is rejected with
a build-configuration error, and a fresh install reads as "not
authenticated" rather than as a keychain failure:

- **Linux** — secret-service support drags in a D-Bus dependency stack for a
  platform where this CLI runs headless anyway. Credentials live in the 0600
  file at `~/.config/aikido/credentials.json`.
- **Windows** — Credential Manager caps a blob at 2560 bytes of UTF-16
  (`CRED_MAX_CREDENTIAL_BLOB_SIZE`). The credential JSON for a real Aikido
  token measured 1643 characters, 3286 bytes as UTF-16, so every keychain
  write would fail and fall through to the file anyway. Credentials live at
  `%APPDATA%\aikido\credentials.json`; there are no mode bits on Windows, so
  the per-user profile ACL is the boundary.

`auth status` reports where the active token was actually read from
(`source: "env" | "keychain" | "file"`). When the keychain was read but a
`credentials.json` also exists, that file is a stale plaintext copy left by
an earlier fallback; status names it in `shadow_file` and in the summary,
and `aikido auth logout` removes both.

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
| `AIKIDO_TOKEN_STORE` | `file` or `keychain`; default: keychain with file fallback on macOS, file elsewhere |
| `AIKIDO_CONFIG_DIR` | Config dir override (default: platform config dir — `~/Library/Application Support/aikido` on macOS, `~/.config/aikido` on Linux, `%APPDATA%\aikido` on Windows) |
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
aikido issues counts    [--repo NAME] [--since 7d|<unix>] [--repo-id N]
                        [--external-repo-id ID] [--container-id N] [--team-id N]
aikido issues show <group_id>
aikido issues ignore <id>   [--reason TEXT]
aikido issues unignore <id> [--reason TEXT] [--all-tags]
aikido issues snooze <id>   --until 7d [--reason TEXT]
aikido issues unsnooze <id> [--all-tags]
aikido issues severity <id> --level low --reason TEXT
aikido issues groups list   [--repo NAME] [--repo-id N] [--container-id N]
                            [--team-id N] [--type T] [--status S] [--limit 100]
aikido issues groups ignore <gid>   [--reason TEXT]      # WORKSPACE-WIDE
aikido issues groups snooze <gid>   --until 7d [--reason] # WORKSPACE-WIDE
aikido issues groups severity <gid> --level low --reason  # WORKSPACE-WIDE
aikido issues groups unignore <gid> [--reason TEXT]
aikido issues groups unsnooze <gid>
aikido repos list       [--limit 100] [--name NAME] [--inactive]
aikido repos scan <repo_id> [--sast] [--iac] [--secrets]
aikido repos licenses <repo_id>
aikido containers list  [--limit 100] [--name NAME] [--tag TAG] [--stale-days N]
aikido containers show <id>
aikido containers scan <id>
aikido containers licenses <id>
aikido api get <path>   [--query k=v ...]      # read-only raw passthrough
```

Issue counting has two units, and `issues counts` exists to keep them apart:
**issue groups** are what the Aikido dashboard's "Open Issues" figure counts,
while **individual issues** are the rows `issues list` / `/issues/export`
return. One group can contain many issues and can span code repos,
containers, and clouds. A dashboard showing 26 and a loop reporting 168 can
both be right — every `issues counts` output names the axis in words so the
two are never conflated.

**Group mutations are workspace-wide.** A location filter on
`issues groups list` returns groups that *touch* that location (verified
against live data: most groups span several repos/containers), so a group
mutation acts on the vulnerability across every repo, container, and cloud
in the group — never just the repo you filtered by. The forward mutations
`ignore`, `snooze`, and `severity` compute the blast radius (locations +
expected open-issue count) before acting; styled CLI output shows it at that
point, while machine CLI formats and MCP results carry it in the final
result. `ignore`/`snooze` assert the API's reported affected-issue count
against the expectation afterwards — a mismatch is an error whose message
states the mutation was still applied. `severity` reports that its endpoint
supplies no affected count. The reversal verbs `unignore` and `unsnooze`
remain workspace-wide but intentionally skip the open-issue guard: they
target non-open issues, so an open-issue preflight cannot express their
expected effect; the CLI and MCP operations expose no affected-count result
to verify.
Per-issue verbs remain the single-instance alternative.

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
refresh logic as the CLI. It supports both protocol eras: legacy clients use
the `initialize` handshake, while MCP `2026-07-28` clients use stateless
`server/discover` and per-request metadata. Register it e.g. in Claude Code:

```sh
claude mcp add aikido -- ~/.local/bin/aikido-mcp
```

Tools:

| Tool | Kind | Description |
|---|---|---|
| `aikido_list_issues` | read | List issues (severity/status/repo/container filters, limit) |
| `aikido_issue_counts` | read | Severity counts on both axes — issue groups (dashboard unit) vs individual issues |
| `aikido_get_issue_group` | read | Full detail for an issue group |
| `aikido_list_issue_groups` | read | List open issue groups (dashboard listing; location filters are touch-semantics) |
| `aikido_ignore_issue_group` | mutation | Ignore a whole group — workspace-wide, blast-radius asserted |
| `aikido_snooze_issue_group` | mutation | Snooze a whole group — workspace-wide, blast-radius asserted |
| `aikido_adjust_group_severity` | mutation | Adjust a whole group's severity — workspace-wide |
| `aikido_unignore_issue_group` | mutation | Reverse a group ignore |
| `aikido_unsnooze_issue_group` | mutation | Reverse a group snooze |
| `aikido_unignore_issue` | mutation | Reverse an ignore on a single issue |
| `aikido_unsnooze_issue` | mutation | Reverse a snooze on a single issue |
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

## Platforms and releases

Supported targets, each built on a native runner by the release workflow
(`.github/workflows/release.yml`, on a `v*` tag) and attached to the GitHub
release with a `SHA256SUMS` file:

| Target | Notes |
|---|---|
| `aarch64-apple-darwin`, `x86_64-apple-darwin` | Keychain backend available |
| `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` | Static; file store only |
| `x86_64-pc-windows-msvc` | File store only (see Authentication) |

TLS is rustls with the `ring` crypto provider and bundled webpki roots, so
no target needs cmake, NASM, or system OpenSSL. CI runs the full test suite
on Linux, macOS, and Windows. From a Mac, `make cross-check` type-checks the
Linux musl and Windows targets through zig (`brew install zig && cargo
install cargo-zigbuild`, then `rustup target add` the targets the Makefile
lists).

## Development

```sh
cargo build --workspace
cargo test --workspace          # wiremock + assert_cmd; never touches the real keychain or API
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo audit                     # RustSec advisories against Cargo.lock
make cross-check                # cargo zigbuild check for the Linux and Windows targets
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
