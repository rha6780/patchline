# Patchline

**Track vulnerability fixes from detection to deployment — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development.** The MVP loop works end to end — detection, Slack, Renovate PRs, rescan resolution and a web UI — but APIs, config and data models may still change before `v0.1.0`. APIs, config and data models will change.

Patchline sits on top of [Dependency-Track](https://dependencytrack.org/) and closes the remediation loop: it links findings to services and owners, follows Renovate PRs and deployments as evidence, and keeps a single Slack message up to date until the fix ships.

Patchline does **not** detect vulnerabilities or compare versions itself. Dependency-Track decides *what is vulnerable*; Renovate proposes *how to fix it*; Patchline tracks *whether it actually got fixed, by whom, and by when*.

## Why

Scanners are good at finding vulnerabilities. What usually goes missing is everything after that:

- Who owns this finding, and which Slack channel should hear about it?
- Is there a PR for it? Was it merged? Did the merge actually fix it?
- Is the fix only on `main`, or is it running in `prod`?
- When is it due, and is anyone late?

Patchline answers these with **evidence** (commit SHA → PR → rescan → image digest), not with someone flipping a status by hand.

## How it works

```
Service repos (Gitea) ── CI: SBOM (main) ──┐
Deploy pipeline       ── image SBOM (prod) ┼──▶ Dependency-Track ── webhook ──┐
Inventory (manual)    ── CPE SBOM ─────────┘                                  │
                                                                              ▼
Renovate ── security PRs ── Gitea webhook ───────────────────────────▶  Patchline  ◀── inventory (Git, YAML)
Deploy pipeline ── deploy webhook (SHA, digest) ─────────────────────▶      │
                                                         ┌──────────────────┼──────────────────┐
                                                    Slack (bot)      Gitea issues           Web UI
```

| Tool | Role |
|---|---|
| **Dependency-Track** | Matches SBOM components (purl / CPE) against NVD, GHSA and OSV; stores analysis decisions |
| **Renovate** | Opens fix PRs (dependency bumps, base-image digest updates) |
| **Patchline** | Joins findings with the inventory, computes SLA, notifies, tracks state with evidence |

OpenCVE can be added later as another source for host-installed infrastructure products.

## Features

- **Git as the source of truth** — services, owners, channels and repositories live in YAML
- **Evidence-based resolution** — a finding is resolved only when a new BOM no longer contains it, with the commit as evidence; regressions reopen it; `main` and `prod` are tracked separately
- **Renovate PR linking** — PR opened → *in progress*, merged → *awaiting verification*, with a check that the target version leaves the affected range
- **One message per finding** — Slack messages are updated in place (`chat.update`) with history in the thread
- **SLA as code** — due dates by effective severity; CISA KEV, EPSS and service exposure escalate; reminders before and after the due date
- **Read-only web UI** — overview with overdue counts, per-service environment comparison, evidence timeline, integration health
- **Gitea / Forgejo first** (GitHub webhooks work too)
- **Lightweight** — a single binary or container with SQLite

Planned: risk acceptances that expire; production deploy evidence; Gitea issue mirror; OpenCVE as a source; PostgreSQL.

### Finding states

| State | Trigger |
|---|---|
| `needs_review` | Component version unknown or CPE match uncertain (reserved) |
| `new` | New finding from Dependency-Track |
| `in_progress` | Analysis in triage / exploitable, or a fix PR is linked |
| `awaiting_verification` | Fix PR merged, or analysis marked resolved |
| `resolved` | No longer reported for the project's latest BOM |
| `not_affected` | Analysis `NOT_AFFECTED` / `FALSE_POSITIVE` |
| `risk_accepted` | Finding suppressed in Dependency-Track |
| `reopened` | A resolved finding is reported again |

Human decisions are made in **one place**: Dependency-Track analysis.

## Roadmap

| Milestone | Scope |
|---|---|
| ✅ **M0** Skeleton | Module layout, config, SQLite + migrations, `/healthz`, Compose demo (DT + Patchline) |
| ✅ **M1** Intake | DT webhooks → inbox → findings joined with the inventory |
| ✅ **M2** Notify | Slack first message, in-place updates, thread history; console sink |
| ✅ **M3** Resolve | Rescan diff → resolved / reopened, commit SHA recorded |
| ✅ **M4** Link PRs | Gitea webhooks, Renovate PR ↔ finding, "does this PR fix it?" |
| ✅ **M5** UI | Overview and finding timeline |
| ✅ SLA | Policy-based due dates (KEV, EPSS, exposure) and reminders |
| Later | Exception expiry, `prod` deploy evidence, Gitea issue sink, OpenCVE source |

## Tech stack

| Area | Choice |
|---|---|
| Language | Go |
| HTTP | `net/http` (Go 1.22+ routing) |
| UI | `html/template`, server-rendered, no JavaScript |
| Database | SQLite (`ncruces/go-sqlite3`, pure Go, no cgo), migrations with `goose` |
| Configuration | environment variables, inventory in YAML (`go.yaml.in/yaml/v3`) |
| Background work | in-process workers: inbox processor and notifier (no queue or Redis) |
| Integrations | small standard-library HTTP clients for Dependency-Track and the Slack Web API |
| Versions | built-in best-effort comparison across Maven, npm, PyPI and Go styles |
| Logging | `log/slog` |
| Container | distroless, non-root |

## Repository layout

```
patchline/
├── cmd/patchline/          # main entrypoint
├── internal/
│   ├── config/             # env + YAML settings
│   ├── server/             # HTTP: webhook inbox, internal API, UI routes
│   ├── finding/            # model, state transitions, event log
│   ├── policy/             # severity + SLA rules
│   ├── inventory/          # Git-managed service inventory
│   ├── intake/             # inbox processor: webhook deliveries → findings
│   ├── notify/             # notifier: one message per finding, updates, thread history
│   ├── source/             # inputs: dependencytrack, gitea, jenkins
│   ├── sink/               # outputs: slack, giteaissue, console
│   ├── store/              # persistence + migrations
│   ├── version/            # best-effort cross-ecosystem version comparison
│   ├── job/                # scheduled jobs (reminders, expiry, heartbeat)
│   └── web/                # server-rendered pages + embedded CSS
├── examples/               # sample inventory, policy, SBOM
├── deploy/compose/         # docker compose demo
└── docs/
```

## Getting started

```sh
make build && ./bin/patchline     # :8080
make demo-up                      # Dependency-Track + Patchline via docker compose
```

The demo walkthrough (API key, webhook, sample SBOM) is in [deploy/compose/README.md](deploy/compose/README.md).
Demo ports: Patchline `18080`, Dependency-Track API `18081`, UI `18082` (change them in `deploy/compose/.env`).

### Web UI

Open `http://localhost:8080/` (`:18080` in the demo). The UI has no login: put it behind your authenticating proxy.

| Page | Path |
|---|---|
| Overview: open findings, service × severity, needs attention, recently resolved, MTTR | `/` |
| Findings with filters | `/findings` |
| Finding: facts, fix pull requests, evidence timeline | `/findings/{id}` |
| Service: owners, repositories, findings per environment (highlights fixed-on-`main`-but-open-in-`prod`) | `/services/{name}` |
| Integrations: Dependency-Track projects with last BOM and commit, inventory projects without a BOM, failed webhooks and notifications | `/integrations` |

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (database) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track outbound webhook (`?token=` or `Authorization: Bearer`) |
| `POST` | `/webhooks/gitea` | Gitea / Forgejo / GitHub `pull_request` webhook (HMAC signature, or the token) |
| `GET` | `/api/v1/findings` | Findings with owners; filters `service`, `environment`, `state`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | A finding's timeline |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Pull requests linked to a finding |

### Configuration

| Variable | Default | |
|---|---|---|
| `PATCHLINE_ADDR` | `:8080` | Listen address |
| `PATCHLINE_DB_PATH` | `data/patchline.db` | SQLite file |
| `PATCHLINE_INVENTORY_PATH` | — | Inventory YAML file or directory ([example](examples/inventory/services.yaml)) |
| `PATCHLINE_WEBHOOK_TOKEN` | — | Shared secret for webhooks. Unset = no authentication (development only) |
| `PATCHLINE_DT_URL` | — | Dependency-Track API server URL |
| `PATCHLINE_DT_API_KEY` | — | API key with `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` |
| `PATCHLINE_GITEA_WEBHOOK_SECRET` | — | Secret of the pull request webhook. Unset = use `PATCHLINE_WEBHOOK_TOKEN` |
| `PATCHLINE_DT_UI_URL` | — | Dependency-Track UI URL for links in messages |
| `PATCHLINE_DT_RECONCILE_DELAY` | `2m` | Wait after `BOM_PROCESSED` before comparing findings |
| `PATCHLINE_POLICY_PATH` | — | Remediation policy YAML ([example](examples/policy/policy.yaml)). Unset = built-in defaults |
| `PATCHLINE_KEV_URL` | CISA feed | CISA KEV catalog URL, refreshed daily; `off` disables |
| `PATCHLINE_SLACK_BOT_TOKEN` | — | Slack bot token (`chat:write`, `chat:write.public`). Unset = print to stdout |
| `PATCHLINE_SLACK_DEFAULT_CHANNEL` | — | Channel for services without `slack_channel` and unregistered projects |
| `PATCHLINE_NOTIFY_MIN_SEVERITY` | `medium` | Lowest severity that is posted |
| `PATCHLINE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PATCHLINE_LOG_FORMAT` | `text` | `text` or `json` |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown limit |

### How intake works

1. The webhook handler validates the payload, stores it in an inbox table (de-duplicated by content hash) and returns `202`.
2. A background processor handles inbox entries, retrying failures with backoff (30s → 30m, 5 attempts).
3. `NEW_VULNERABILITY` and `NEW_VULNERABLE_DEPENDENCY` carry the findings directly; `BOM_PROCESSED` schedules a reconciliation of the project (see below).
4. Each Dependency-Track project **name** is resolved to a service through the inventory, and its **version** becomes the environment (`main`, `prod`). Projects not in the inventory are kept as *unregistered*.
5. A finding is one service × environment × component × vulnerability. CVE ids are preferred over GHSA/OSV ids as the canonical id; the others are kept as aliases.
6. `PROJECT_AUDIT_CHANGE` (an analysis decision in Dependency-Track) moves the finding's state: `IN_TRIAGE`/`EXPLOITABLE` → in progress, `NOT_AFFECTED`/`FALSE_POSITIVE` → not affected, suppressed → risk accepted, `RESOLVED` → awaiting verification (a rescan confirms it later).

### How resolution works

A finding is resolved by evidence, not by someone closing it.

1. On `BOM_PROCESSED`, Patchline records the BOM's commit and ref and schedules a reconciliation after `PATCHLINE_DT_RECONCILE_DELAY`. (Dependency-Track 4.x sends `BOM_PROCESSED` before it has finished analyzing new components, so reading findings right away would be incomplete.)
2. The reconciliation reads the project's current findings from the Dependency-Track API. Findings of that project that are no longer reported become **resolved**, with the commit, ref and BOM serial as evidence.
3. A resolved finding that is reported again (by a later BOM or a `NEW_VULNERABILITY` notification) becomes **reopened**.
4. Each Dependency-Track project version is reconciled separately, so `main` and `prod` resolve independently.
5. Findings closed by a decision (not affected, risk accepted) are left as they are.

To attach the commit, add these properties to the BOM's `metadata` before uploading it:

```sh
jq --arg c "$GITHUB_SHA" --arg r "$GITHUB_REF" \
  '.metadata.properties += [{"name":"patchline:git:commit","value":$c},{"name":"patchline:git:ref","value":$r}]' \
  bom.json > bom.patchline.json
```

### How pull requests are linked

1. Add a webhook for **Pull Request** events to the repository (or organization) in Gitea, Forgejo or GitHub, pointing at `/webhooks/gitea` with the secret `PATCHLINE_GITEA_WEBHOOK_SECRET`.
2. When a pull request opens or changes, Patchline reads the updates from Renovate's change table (or the title, `Update dependency X to vY`).
3. Each update is matched to open findings of that repository by package name (Maven `group:artifact` = `group/artifact`), in the environment named after the base branch.
4. The target version is compared with the vulnerability's affected ranges from Dependency-Track: **leaves the affected range**, **still affected**, or **not verified** when no range is known.
5. A linked pull request moves the finding to *in progress*; merging it moves it to *awaiting verification*. Closing without merging is recorded but keeps the state. Only the next rescan resolves the finding.

Base-image updates are not matched to OS-package findings yet; they resolve through the rescan as usual.

### How due dates work

The policy ([example](examples/policy/policy.yaml)) turns risk signals into an **effective severity** and a due date:

1. Start from the scanner's severity.
2. Raise one level when the EPSS score (from Dependency-Track) is at or above `epss_threshold`.
3. Add the service's exposure adjustment (default: `internet` +1).
4. A CVE in the CISA KEV catalog is raised to at least `kev` (default critical).
5. The due date is the SLA for that severity (default critical 7d, high 30d, medium 90d, low 180d), counted from first detection or from reopening.

The SLA job re-evaluates open findings every 5 minutes and right after intake, so a CVE added to KEV escalates findings that are already open (the thread says why and moves the due date). It records one reminder before the due date and repeats while overdue. New findings are posted after their first evaluation, so the first message already shows the due date, and the notification threshold uses the effective severity.

### How notifications work

- Each finding at or above `PATCHLINE_NOTIFY_MIN_SEVERITY` gets **one** message in its service's `slack_channel` (or the default channel).
- When the finding changes (state, severity), the message is edited in place (`chat.update`) and the change is added to its thread.
- Progress is stored per finding, so restarts and Slack outages only delay messages; rate limits (`429`) pause delivery for `Retry-After`.
- Findings closed before they were ever posted (for example marked not affected right away) are not posted.
- Without a Slack token the same messages are printed to stdout.

## Scope

Out of scope: running scanners, version-range matching (delegated to Dependency-Track), SAST for first-party code, configuration audits, multi-tenancy.

## License

[Apache-2.0](LICENSE)

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
