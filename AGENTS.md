# AGENTS.md

Guidance for coding agents working in this repository. Agent-agnostic — `CLAUDE.md`
is a pointer to this file.

## Commands

```sh
make check                 # the four gates below, in order — run this before calling work done
cargo build --workspace
cargo test --workspace     # wiremock + assert_cmd; never touches the real keychain or live API
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

`make build` / `make release` also codesign the binary with a stable identity
(`dev.aikido.cli`) so the macOS keychain ACL approval survives rebuilds; a missing
signing identity is a warning, not a failure. `make install` puts `aikido` in
`~/.local/bin`.

Single test:

```sh
cargo test -p aikido-cli --test cli -- envelope        # by name substring
cargo test -p aikido-core --test api_contract
cargo test -p aikido-core --test keychain_interop -- --ignored   # macOS only, pops a keychain dialog
```

The two `keychain_interop` tests are `#[ignore]` on purpose: reading a keychain item
written by another process pops a modal ACL prompt the approval can never stick to.
Run them deliberately when touching `credentials.rs`. Everything else is fully
non-interactive.

## Architecture

Three crates, one shared core so the CLI and the MCP server cannot drift:

```
crates/aikido-core/   API client, OAuth auth, credential store, session resolution
crates/aikido-cli/    binary `aikido` (clap)  — src/lib.rs holds the behaviour, main.rs is a shell
crates/aikido-mcp/    binary `aikido-mcp` (rmcp, stdio)
```

The load-bearing invariant: **anything that touches auth, HTTP, or the API belongs in
`aikido-core`.** The CLI and MCP server both call `session::resolve()` → `Client` →
`api::*`, so token-source precedence, 401 refresh, retry policy, and endpoint shapes
are defined exactly once. Adding a capability to one surface without the other is the
main way this repo regresses.

Request path, end to end:

1. `session::resolve(&CredentialStore::default(), verbose)` — precedence is
   `AIKIDO_TOKEN` > stored access token, and OAuth client credentials
   (`AIKIDO_CLIENT_ID`/`_SECRET` > stored) are attached to the client *whatever* the
   token source, so refresh always works. The store is consulted only when the env
   does not fully configure the run — a hanging keychain must not take down a run
   that did not need it.
2. `client::Client` — `{base}/api/public/v1{path}`. On 401 it exchanges credentials
   for a fresh token, **persists** it plus the new expiry to the store, and retries
   once. Timeouts: 10s connect / 30s request, max 2 retries. GETs retry on connect
   errors, 429 (honouring `Retry-After`, capped at 10s), and 502/503/504; mutations
   retry only where replay is provably safe (429 and connect errors) — an ambiguous
   502/504 on a mutation is surfaced, never replayed.
3. `api::*` — typed operations returning raw `serde_json::Value`. The `--json`
   contract exposes the API objects as-is; do not reshape them here.
4. CLI: `commands/<noun>.rs` renders via `output::render_ok`; MCP: `main.rs` returns
   pretty JSON text content. `main.rs` (CLI) is the single place errors are rendered
   and exit codes are mapped.

Cross-cutting core modules: `credentials.rs` (keychain + 0600 file backends),
`staleness.rs` (container scan-freshness scoring), `until.rs` (`7d` → unix timestamp),
`error.rs` (`ApiError` → stable `code` + `hint`).

## Contracts that must not be broken casually

- **JSON envelope.** `{"ok":true,"data","summary","meta"}` on stdout;
  `{"ok":false,"error","code","hint"}` on **stderr** with a non-zero exit. Field order
  in `output::Response` is part of the byte-level contract. Exit codes: 0 ok, 1 API/runtime,
  2 usage (clap), 4 auth. Codes: `api_error`, `auth_error`, `not_found`, `rate_limit`.
- **Credential wire format.** `Credentials` field names are shared with the Go CLI, and
  keychain values are stored go-keyring-style (`go-keyring-base64:` + base64(JSON), with
  the legacy `go-keyring-encoded:` hex prefix read too). Both binaries must stay readable
  by either implementation — don't rename fields or drop the prefix codec.
- **Format precedence.** `--jq` > `--quiet` > `--json` > `--md` > auto (TTY → styled,
  pipe → JSON). Lives in `GlobalFlags::format()`.
- **Two counting units.** *Issue groups* (what the dashboard's "Open Issues" counts)
  and *individual issues* (`/issues/export` rows) are different units — one group spans
  many repos/containers/clouds. Any output that reports a count must name its axis in
  words. Never compare one to the other.
- **Group mutations are workspace-wide.** A location filter returns groups that merely
  *touch* that location. So every group mutation calls `api::group_blast_radius()` first,
  prints locations + expected open-issue count, and asserts the API's reported affected
  count against that expectation afterwards — a mismatch is an error whose message states
  the mutation *was* applied. Keep this preflight/assert pair on any new group verb.
- **Human-facing dates render in local time**, via `output::local_date_from_epoch` /
  `date_in_zone`. A UTC date shifts a calendar day near midnight, which defeats
  "scanned yesterday, pushed today" eyeballing. Route all timestamp→date rendering there.
- **Presence is never reported as validity.** `auth status` makes a live call;
  `authenticated: true` means the token worked just now, and an unreachable API reports
  `checked: false` rather than guessing.

## Test conventions

Integration tests spawn the **real binaries** (`assert_cmd` / `CARGO_BIN_EXE_aikido-mcp`)
with `env_clear()` plus `AIKIDO_BASE_URL=<wiremock>`, `AIKIDO_TOKEN_STORE=file`,
`AIKIDO_CONFIG_DIR=<tempdir>`. New behaviour that crosses the process boundary (envelope
shape, exit codes, MCP tool wiring) gets a test at that level, not just a unit test.
`crates/aikido-core/tests/api_contract.rs` asserts query params and request bodies
verbatim — extend it whenever you add an endpoint.

## Adding an endpoint

1. `aikido-core/src/api.rs` — the typed operation, `Value` in / `Value` out.
2. `api_contract.rs` — wiremock test pinning path, query params, and body.
3. CLI command in `commands/<noun>.rs` (+ clap wiring in `main.rs`, + `Column` set for
   `--md`) **and** MCP tool in `aikido-mcp/src/main.rs`. Both surfaces, same change.
4. `docs/api-coverage.md` — regenerate context with `aikido api get /openapi/spec`
   (the ~660 KB spec itself is deliberately not committed) and update the coverage row
   **and the totals line at the top**.
5. `README.md` — the `## Commands` usage block (CLI) and the `## MCP server` tool table
   (MCP). These duplicate the surface by design, for readers who never open the code;
   that makes them the first thing to drift.

The four places a new endpoint must land, as a matrix — a change that fills fewer than
all four columns is incomplete, not in progress:

| Surface | Code | Test | Docs |
|---|---|---|---|
| core | `api.rs` operation | `api_contract.rs` wiremock case | `docs/api-coverage.md` row + totals |
| CLI | `commands/<noun>.rs` + clap wiring in `main.rs` + `Column` set for `--md` | `crates/aikido-cli/tests/cli.rs` | `README.md` `## Commands` block |
| MCP | tool in `aikido-mcp/src/main.rs` (+ `JsonSchema` params struct) | `crates/aikido-mcp/tests/mcp_stdio.rs` | `README.md` `## MCP server` table |

Removing or renaming a command or tool runs the same matrix in reverse — the tables are
where a deleted verb survives longest.

## Style

The comments in this codebase explain *why* a decision was made — the Go CLI bug it
fixes, the failure mode it prevents, the measurement that is still missing. Match that:
when you encode a policy (a timeout, a retry rule, a precedence), say what breaks
without it. Do not add comments that restate the code.
