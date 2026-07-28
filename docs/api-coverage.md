# Aikido public API coverage

Generated from `GET /openapi/spec` (fetched 2026-07-28 via `aikido api get /openapi/spec`).
Spec: OpenAPI 3.1.0, "Aikido Security API documentation", version 1.0.0.
The spec itself is not committed (~660 KB); regenerate any time with the command above.

Every dedicated read route is also reachable ad hoc through `aikido api get <path>`;
the **CLI** column below lists dedicated commands only.

Totals: **168 operations** across **147 paths**; **13 covered**
by dedicated commands/tools (12 in both CLI and MCP, plus `/openapi/spec` via the passthrough).

## access-tokens (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| POST | `/access-tokens/code-scanning` | Update Code Scanning Access Token | `access_tokens:write` | — | — |

## autofix (0/2 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/autofix/history` | List autofix history | `autofix:read` | — | — |
| GET | `/autofix/history/{autofix_task_id}/issues` | List issues addressed by a task | `autofix:read` | — | — |

## bug_bounty (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| POST | `/bug_bounty/program/{program_id}/report` | Validate Bug Bounty Report | `bug_bounty:write` | — | — |

## changelog-summary (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/changelog-summary` | Get changelog summary | `research:read` | — | — |

## clouds (0/9 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/clouds` | List connected clouds | `clouds:read` | — | — |
| GET | `/clouds/assets` | Get cloud assets | `clouds:read` | — | — |
| POST | `/clouds/aws` | Connect AWS cloud | `clouds:write` | — | — |
| POST | `/clouds/azure` | Connect Azure cloud | `clouds:write` | — | — |
| PUT | `/clouds/azure/{cloud_id}/credentials` | Update Azure cloud | `clouds:write` | — | — |
| POST | `/clouds/gcp` | Connect GCP cloud | `clouds:write` | — | — |
| POST | `/clouds/kubernetes` | Create Kubernetes cloud | `clouds:write` | — | — |
| GET | `/clouds/rules` | List cloud rules | `clouds:read` | — | — |
| DELETE | `/clouds/{cloud_id}` | Remove cloud | `clouds:write` | — | — |

## code-quality (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/code-quality/findings` | List code quality findings for a pull request | `code_quality:read` | — | — |

## containers (4/25 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/containers` | List containers | `repositories:read` | `containers list` | `aikido_list_containers` |
| POST | `/containers/activate` | Activate container | `containers:write` | — | — |
| POST | `/containers/clone` | Clone container | `containers:write` | — | — |
| POST | `/containers/deactivate` | Deactivate container | `containers:write` | — | — |
| POST | `/containers/linkCodeRepo` | Link code repository to container | `containers:write` | — | — |
| POST | `/containers/public` | Add public container | `containers:write` | — | — |
| POST | `/containers/registries/acr` | Add Azure container registry | `containers:write` | — | — |
| POST | `/containers/registries/gcp-artifact-registry` | Add GCP Artifact Registry | `containers:write` | — | — |
| POST | `/containers/registries/gitlab-self` | Add GitLab Self-Managed container registry | `containers:write` | — | — |
| GET | `/containers/registries/{registry_id}` | Get container registry | `containers:read` | — | — |
| POST | `/containers/sbom` | Upload container SBOM | `containers:write` | — | — |
| POST | `/containers/sbom/generate` | Generate bulk SBOM | `repositories:write` | — | — |
| POST | `/containers/unlinkCodeRepo` | Unlink code repository from container | `containers:write` | — | — |
| POST | `/containers/updateTagFilter` | Update container tag filter | `containers:write` | — | — |
| DELETE | `/containers/{container_repo_id}` | Delete container | `containers:write` | — | — |
| GET | `/containers/{container_repo_id}` | Get container | `containers:read` | `containers show` | `aikido_get_container` |
| PUT | `/containers/{container_repo_id}/internetConnection` | Update connectivity | `container:write` | — | — |
| POST | `/containers/{container_repo_id}/labels` | Add container label | `containers:write` | — | — |
| DELETE | `/containers/{container_repo_id}/labels/{label_id}` | Remove container label | `containers:write` | — | — |
| POST | `/containers/{container_repo_id}/labels/{label_id}` | Update container label | `containers:write` | — | — |
| GET | `/containers/{container_repo_id}/licenses/export` | Export SBOM | `repositories:read` | `containers licenses` | `aikido_container_licenses` |
| GET | `/containers/{container_repo_id}/runners` | List container runners | `containers:read` | — | — |
| GET | `/containers/{container_repo_id}/sbom/exportRaw` | Export Raw SBOM | `containers:read` | — | — |
| POST | `/containers/{container_repo_id}/scan` | Scan container | `containers:write` | `containers scan` | `aikido_scan_container` |
| PUT | `/containers/{container_repo_id}/sensitivity` | Update sensitivity | `container:write` | — | — |

## cve (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/cve/{cve_id}` | Get CVE details | `research:read` | — | — |

## domains (0/9 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/domains` | List domains | `domains:read` | — | — |
| POST | `/domains` | Create domain | `domains:write` | — | — |
| POST | `/domains/scan` | Start scan for a domain | `domains:write` | — | — |
| DELETE | `/domains/{domain_id}` | Remove domain | `domains:write` | — | — |
| POST | `/domains/{domain_id}/custom-headers` | Update Custom Scan Headers | `domains:write` | — | — |
| POST | `/domains/{domain_id}/headers` | Update Auth Headers | `domains:write` | — | — |
| GET | `/domains/{domain_id}/subdomains` | List Subdomains | `domains:read` | — | — |
| POST | `/domains/{domain_id}/subdomains` | Add Subdomain | `domains:write` | — | — |
| PUT | `/domains/{domain_id}/update/openapi-spec` | Update OpenAPI spec | `domains:write` | — | — |

## endpoint-protection (0/7 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/endpoint-protection/activityLogs` | List endpoint activity logs | `endpoint_protection:read` | — | — |
| GET | `/endpoint-protection/devices` | List endpoint devices | `endpoint_protection:read` | — | — |
| DELETE | `/endpoint-protection/exceptions/{package_exception_id}` | Remove an endpoint exception | `endpoint_protection:write` | — | — |
| GET | `/endpoint-protection/installed-packages` | List installed packages | `endpoint_protection:read` | — | — |
| GET | `/endpoint-protection/permission-groups` | List endpoint permission groups | `endpoint_protection:read` | — | — |
| GET | `/endpoint-protection/{ecosystem}/exceptions` | List endpoint exceptions | `endpoint_protection:read` | — | — |
| POST | `/endpoint-protection/{ecosystem}/exceptions` | Add an endpoint exception | `endpoint_protection:write` | — | — |

## firewall (0/17 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/firewall/apps` | List apps | `firewall:read` | — | — |
| POST | `/firewall/apps` | Create app | `firewall:write` | — | — |
| DELETE | `/firewall/apps/{app_id}` | Delete app | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}` | Get app | `firewall:read` | — | — |
| PUT | `/firewall/apps/{app_id}` | Update app | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}/bot-lists` | Get bot lists | `firewall:read` | — | — |
| PUT | `/firewall/apps/{app_id}/bot-lists` | Update bot lists | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}/countries` | Get countries | `firewall:read` | — | — |
| PUT | `/firewall/apps/{app_id}/countries` | Update countries | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}/events/{event_id}` | Get event | `firewall:read` | — | — |
| PUT | `/firewall/apps/{app_id}/ip-blocklist` | Update IP blocklist | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}/ip-lists` | Get threat lists | `firewall:read` | — | — |
| PUT | `/firewall/apps/{app_id}/ip-lists` | Update threat lists | `firewall:write` | — | — |
| POST | `/firewall/apps/{app_id}/token` | Rotate app token | `firewall:write` | — | — |
| GET | `/firewall/apps/{app_id}/users` | List users | `firewall:read` | — | — |
| PUT | `/firewall/apps/{service_id}/blocking` | Update blocking mode | `firewall:write` | — | — |
| PUT | `/firewall/{app_id}/users/{user_id}` | Update user | `firewall:write` | — | — |

## issues (5/20 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/issues/counts` | Get issue counts | `issues:read` | — | — |
| GET | `/issues/detail/bulk` | Get issue details bulk | `issues:read` | — | — |
| GET | `/issues/export` | Export all issues | `issues:read` | `issues list` | `aikido_list_issues` |
| GET | `/issues/groups/{issue_group_id}` | Get issue group detail | `issues:read` | `issues show` | `aikido_get_issue_group` |
| PUT | `/issues/groups/{issue_group_id}/ignore` | Ignore an issue group | `issues:write` | — | — |
| GET | `/issues/groups/{issue_group_id}/notes` | List notes for issue group | `issues:read` | — | — |
| POST | `/issues/groups/{issue_group_id}/notes` | Add note to issue group | `issues:write` | — | — |
| POST | `/issues/groups/{issue_group_id}/severity/adjust` | Adjust severity of an issue group | `issues:write` | — | — |
| PUT | `/issues/groups/{issue_group_id}/snooze` | Snooze an issue group | `issues:write` | — | — |
| GET | `/issues/groups/{issue_group_id}/tasks` | Get issue group tasks | `issues:read` | — | — |
| PUT | `/issues/groups/{issue_group_id}/unignore` | Unignore an issue group | `issues:write` | — | — |
| PUT | `/issues/groups/{issue_group_id}/unsnooze` | Unsnooze an issue group | `issues:write` | — | — |
| GET | `/issues/{issue_id}` | Get issue detail | `issues:read` | — | — |
| PUT | `/issues/{issue_id}/ignore` | Ignore an issue | `issues:write` | `issues ignore` | `aikido_ignore_issue` |
| GET | `/issues/{issue_id}/reachability` | Get issue reachability | `issues:read` | — | — |
| POST | `/issues/{issue_id}/severity/adjust` | Adjust severity of an issue | `issues:write` | `issues severity` | `aikido_adjust_severity` |
| PUT | `/issues/{issue_id}/snooze` | Snooze an issue | `issues:write` | `issues snooze` | `aikido_snooze_issue` |
| PUT | `/issues/{issue_id}/solve` | Solve an issue | `issues:write` | — | — |
| PUT | `/issues/{issue_id}/unignore` | Unignore an issue | `issues:write` | — | — |
| PUT | `/issues/{issue_id}/unsnooze` | Unsnooze an issue | `issues:write` | — | — |

## licenses (0/2 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/licenses` | List & Search SBOM | `licenses:read` | — | — |
| POST | `/licenses/overwrite` | Overwrite License | `licenses:write` | — | — |

## localscan (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/localscan/latest` | Get latest local scanner version | `—` | — | — |

## open-issue-groups (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/open-issue-groups` | List open issue groups | `issues:read` | — | — |

## openapi (1/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/openapi/spec` | Get OpenAPI spec | `basics:read` | `api get /openapi/spec` | — |

## pentests (0/3 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| POST | `/pentests/assessments/createDraft` | Create pentest draft | `pentests:write` | — | — |
| GET | `/pentests/assessments/{assessment_id}/detail` | Get pentest assessment | `pentests:read` | — | — |
| GET | `/pentests/issues/{issue_id}/attackAnalysis` | Get attack analysis | `pentests:read` | — | — |

## report (0/10 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/report/activityLog` | List activity log | `reports:read` | — | — |
| GET | `/report/ciScans` | List PR Checks | `reports:read` | — | — |
| GET | `/report/ciScans/issueActions` | List PR Check Manual Actions | `reports:read` | — | — |
| GET | `/report/cis/overview` | CIS compliance | `reports:read` | — | — |
| GET | `/report/cis_aws/overview` | CIS AWS compliance | `reports:read` | — | — |
| GET | `/report/export/pdf` | Export PDF report | `reports:read` | — | — |
| GET | `/report/gdpr/overview` | GDPR compliance | `reports:read` | — | — |
| GET | `/report/iso/overview` | ISO 27001 compliance | `reports:read` | — | — |
| GET | `/report/nis2/overview` | NIS2 compliance | `reports:read` | — | — |
| GET | `/report/soc2/overview` | SOC2 compliance | `reports:read` | — | — |

## repositories (3/29 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/repositories/code` | List code repositories | `repositories:read` | `repos list` | `aikido_list_repos` |
| POST | `/repositories/code/activate` | Activate code repo | `repositories:write` | — | — |
| POST | `/repositories/code/clone` | Clone code repo | `repositories:write` | — | — |
| GET | `/repositories/code/continuous_integration/checks` | List PR Checks configurations | `repositories:read` | — | — |
| POST | `/repositories/code/continuous_integration/checks` | Configure PR Checks | `repositories:write` | — | — |
| POST | `/repositories/code/deactivate` | Deactivate code repo | `repositories:write` | — | — |
| GET | `/repositories/code/iac/rules` | List IaC rules | `repositories:read` | — | — |
| GET | `/repositories/code/mobile/rules` | List Mobile rules | `repositories:read` | — | — |
| POST | `/repositories/code/private-registries` | Manage private registry | `repositories:write` | — | — |
| GET | `/repositories/code/sast/rules` | List SAST rules | `repositories:read` | — | — |
| GET | `/repositories/code/team/{team_id}/licenses/export` | Export SBOM For Team | `repositories:read` | — | — |
| DELETE | `/repositories/code/{code_repo_id}` | Delete code repo | `repositories:write` | — | — |
| GET | `/repositories/code/{code_repo_id}` | Get code repository detail | `repositories:read` | — | — |
| PUT | `/repositories/code/{code_repo_id}/connectivity` | Update connectivity | `repositories:write` | — | — |
| PUT | `/repositories/code/{code_repo_id}/devdep-scan` | Manage dev dep scanning | `repositories:write` | — | — |
| POST | `/repositories/code/{code_repo_id}/exclude-path` | Add an exclude path to a code repo | `repositories:write` | — | — |
| POST | `/repositories/code/{code_repo_id}/exclude-path/remove` | Remove an exclude path from a code repo | `repositories:write` | — | — |
| POST | `/repositories/code/{code_repo_id}/labels` | Add code repo label | `repositories:write` | — | — |
| DELETE | `/repositories/code/{code_repo_id}/labels/{label_id}` | Remove code repo label | `repositories:write` | — | — |
| POST | `/repositories/code/{code_repo_id}/labels/{label_id}` | Update code repo label | `repositories:write` | — | — |
| GET | `/repositories/code/{code_repo_id}/licenses/export` | Export SBOM | `repositories:read` | `repos licenses` | `aikido_repo_licenses` |
| POST | `/repositories/code/{code_repo_id}/scan` | Scan code repo | `repositories:write` | `repos scan` | `aikido_scan_repo` |
| PUT | `/repositories/code/{code_repo_id}/sensitivity` | Update sensitivity | `repositories:write` | — | — |
| POST | `/repositories/import` | Trigger repositories sync | `repositories:write` | — | — |
| GET | `/repositories/sast/custom-rules` | List custom rules | `custom_sast_rules:read` | — | — |
| POST | `/repositories/sast/custom-rules` | Create custom rule | `custom_sast_rules:write` | — | — |
| DELETE | `/repositories/sast/custom-rules/{rule_id}` | Remove custom rule | `custom_sast_rules:write` | — | — |
| GET | `/repositories/sast/custom-rules/{rule_id}` | Get a custom rule | `custom_sast_rules:read` | — | — |
| PUT | `/repositories/sast/custom-rules/{rule_id}` | Edit custom rule | `custom_sast_rules:write` | — | — |

## research (0/1 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/research/malware/packages` | Get malware packages | `research:read` | — | — |

## task_tracking (0/6 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/task_tracking/integrations` | List task tracking integrations | `task_tracking:read` | — | — |
| POST | `/task_tracking/linkTaskToIssueGroup` | Link existing task to issue | `task_tracking:write` | — | — |
| POST | `/task_tracking/mapCodeReposToProjects` | Map code repo to task tracking projects | `task_tracking:write` | — | — |
| GET | `/task_tracking/projectMapping` | Get project mapping | `task_tracking:read` | — | — |
| GET | `/task_tracking/projects` | List task tracking projects | `task_tracking:read` | — | — |
| GET | `/task_tracking/projects/{project_id}/tasks` | List tasks from project | `task_tracking:read` | — | — |

## teams (0/8 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/teams` | List teams | `teams:read` | — | — |
| POST | `/teams` | Create team | `teams:write` | — | — |
| DELETE | `/teams/{team_id}` | Delete team | `teams:write` | — | — |
| PUT | `/teams/{team_id}` | Update team | `teams:write` | — | — |
| POST | `/teams/{team_id}/addUser` | Add user to team | `teams:write` | — | — |
| POST | `/teams/{team_id}/linkResource` | Link resource to team | `teams:write` | — | — |
| POST | `/teams/{team_id}/removeUser` | Remove user from team | `teams:write` | — | — |
| POST | `/teams/{team_id}/unlinkResource` | Unlink resource from team | `teams:write` | — | — |

## users (0/4 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/users` | List users | `users:read` | — | — |
| GET | `/users/ide/adoption` | List IDE adoption | `users:read` | — | — |
| GET | `/users/{user_id}` | Get user | `users:read` | — | — |
| PUT | `/users/{user_id}/rights` | Update user rights | `users:write` | — | — |

## virtual-machines (0/2 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/virtual-machines` | List virtual machines | `virtual_machines:read` | — | — |
| GET | `/virtual-machines/{virtual_machine_id}/export/{format}` | Export SBOM | `virtual_machines:read` | — | — |

## webhooks (0/3 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/webhooks` | List webhooks | `webhooks:read` | — | — |
| POST | `/webhooks` | Add webhook | `webhooks:write` | — | — |
| DELETE | `/webhooks/{webhook_id}` | Remove webhook | `webhooks:write` | — | — |

## workspace (0/3 covered)

| Method | Path | Summary | Scope | CLI | MCP |
|---|---|---|---|---|---|
| GET | `/workspace` | Get workspace info | `basics:read` | — | — |
| GET | `/workspace/configurationErrors` | Get workspace configuration errors | `basics:read` | — | — |
| GET | `/workspace/slaSettings` | Get SLA settings | `basics:read` | — | — |

---

## Recommendation (proposal only — nothing below is implemented)

Judged by what the daily security loop and its operator actually need, in
priority order. The yardstick: eleven well-chosen commands beat fifty
mechanical ones, and every read below is already reachable today via
`aikido api get` — a dedicated command is only warranted where the loop or
the operator uses it routinely.

### P0 — closes known operational failures

1. **`containers scan <id>`** → `POST /containers/{container_repo_id}/scan`
   (`containers:write`). A silently stale container scan cost this workspace
   three months of unmonitored exposure, and the remediation was a UI click;
   this route makes that click scriptable. Pairs with the freshness check
   below to make the loop self-healing: detect stale → trigger rescan.
2. **Container scan freshness surfaced in `containers list`** — no new route
   needed: `GET /containers` already returns `last_scanned_at`,
   `last_scanned_tag`, `last_pushed_at`, `is_active` per item, and the CLI
   passes raw JSON through in `--json` mode today. The work is a documented
   loop-side check (e.g. `--jq` over `last_scanned_at`) plus adding the field
   to the table/styled output; optionally a `--stale-days N` filter flag.
   `GET /repositories/code` likewise carries `last_scanned_at` for repo scan
   freshness.

### P1 — the issue-group gap

The API has a full lifecycle at *group* level that the loop cannot see:

3. **`issues groups list`** → `GET /open-issue-groups` (`issues:read`) —
   list open groups with repo/container/type/status filters.
4. **Group-level mutations** → `PUT /issues/groups/{id}/ignore`,
   `PUT .../snooze`, `POST .../severity/adjust` (`issues:write`) — the same
   three mutations the loop already performs, but acting on a whole group at
   once (the ignore response even reports `ignored_single_issues_amount`).
   Today the loop adjusts issues one at a time and can leave a group
   half-touched.
5. **Undo verbs** → `PUT /issues/{id}/unignore`, `.../unsnooze` (and the
   group-level equivalents). The MCP tool descriptions promise the mutations
   are "reversible", but the reverse currently requires the UI. Cheap to add
   and completes the audited surface.

### P2 — loop quality-of-life

6. **`issues counts`** → `GET /issues/counts` (`issues:read`) — cheap
   summary (issues + issue_groups, filterable, `since_timestamp`) for the
   loop's morning digest without exporting everything.
7. **Individual issue detail** → `GET /issues/{issue_id}` — includes
   `ignore_reasons`, `snooze_until`, `sla_remediate_by`,
   `reachability_status`; the loop currently only has group detail.
8. **Notes** → `GET`/`POST /issues/groups/{id}/notes` — lets the loop leave
   an audit trail on a group ("auto-snoozed by daily loop because ...")
   visible in the dashboard.

### Explicitly not proposed

- **Clouds, firewall (Zen), domains, endpoint protection, pentests, bug
  bounty, teams/users admin, task-tracking integrations, webhooks, custom
  SAST rules, compliance report PDFs** — unrelated to what this workspace
  runs the loop for, mostly `*:write` admin surface, and all readable ad hoc
  via `api get` if ever needed once.
- **A generic mutation passthrough** (`api post`/`api put`) — the group and
  undo verbs above cover the loop's needs inside the audited command
  surface.

### Notes for whoever implements

- Group mutations reuse the existing body shapes (`reason`,
  `adjusted_severity`); the `until` handling for group snooze matches
  `issues snooze`.
- All proposed routes use the `issues:read`/`issues:write` scopes current
  commands already exercise, except `containers scan`, which needs
  `containers:write` — verify the token grants it before shipping.
