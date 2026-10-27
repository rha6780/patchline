# Patchline

**Track vulnerability fixes from detection to deployment — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development (M0).** Nothing is usable yet. APIs, config and data models will change.

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

## Features (planned)

- **Git as the source of truth** — services, owners, channels and policies live in YAML and change through PRs
- **Evidence-based resolution** — a finding is resolved only when a new SBOM no longer contains it; `main` and `prod` are tracked separately
- **Renovate PR linking** — PR opened → *in progress*, merged → *awaiting verification*, and a check that the PR's target version actually fixes the issue
- **One message per finding** — Slack messages are updated in place (`chat.update`) with history in the thread
- **Policy as code** — severity and due dates from CVSS, CISA KEV, EPSS and service exposure
- **Exceptions with expiry** — risk acceptance re-opens automatically when it expires
- **Gitea / Forgejo first**
- **Lightweight** — a single binary or container, SQLite by default, PostgreSQL optional

### Finding states

| State | Trigger |
|---|---|
| `needs_review` | Component version unknown or CPE match uncertain |
| `new` | New finding from Dependency-Track |
| `in_progress` | Owner triage or a linked fix PR is opened |
| `awaiting_verification` | Fix PR merged |
| `resolved` | Finding gone from a new SBOM (`main`, then `prod`) |
| `not_affected` | Analysis marked `NOT_AFFECTED` / `FALSE_POSITIVE` |
| `risk_accepted` | Suppressed with an approver and an expiry date |
| `reopened` | A resolved finding appears again |

Human decisions are entered in **one place** (Dependency-Track analysis, or Patchline UI calling the DT API). Gitea issues are a write-only mirror.

### Web UI

The UI is read-mostly. Configuration stays in Git, deep analysis stays in Dependency-Track.

| Page | Shows |
|---|---|
| Overview | Service × severity matrix, overdue / due-soon findings, MTTR |
| Service | Tech stack summary, `main` vs `prod` differences, open findings |
| Finding timeline | Detected → notified → PR → merged → rescanned → deployed → resolved |
| Integrations & health | Last SBOM per project, last Renovate run, unregistered repos, delivery failures |
| Exceptions | Risk acceptances and not-affected decisions, upcoming expiries |

## Roadmap

| Milestone | Scope |
|---|---|
| **M0** Skeleton | Module layout, config, SQLite + migrations, `/healthz`, Compose demo (DT + Patchline) |
| **M1** Intake | DT webhooks → inbox → findings joined with the inventory |
| **M2** Notify | Slack first message, in-place updates, thread history; console sink |
| **M3** Resolve | Rescan diff → resolved / reopened, commit SHA recorded |
| **M4** Link PRs | Gitea webhooks, Renovate PR ↔ finding, "does this PR fix it?" |
| **M5** UI | Overview and finding timeline |
| Later | SLA reminders, exception expiry, `prod` deploy evidence, Gitea issue sink, OpenCVE source |

## Tech stack

| Area | Choice |
|---|---|
| Language | Go |
| HTTP | `net/http` (Go 1.22+ routing) |
| UI | `templ` + HTMX |
| Database | SQLite (`ncruces/go-sqlite3`, pure Go) / PostgreSQL (`pgx`), `sqlc`, `goose` |
| Scheduler | `gocron` |
| Integrations | Gitea SDK, `slack-go/slack`, thin Dependency-Track client |
| Identifiers | `packageurl-go`, ecosystem version comparators |
| Logging | `log/slog` |
| Release | GoReleaser |

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
│   ├── source/             # inputs: dependencytrack, gitea, jenkins
│   ├── sink/               # outputs: slack, giteaissue, console
│   ├── store/              # persistence + migrations
│   ├── job/                # scheduled jobs (reminders, expiry, heartbeat)
│   └── web/                # templ templates + static assets
├── examples/               # sample inventory, policy, SBOM
├── deploy/compose/         # docker compose demo
└── docs/
```

## Getting started

Not usable yet — only the M0 skeleton runs.

```sh
make build && ./bin/patchline     # :8080, GET /healthz and /readyz
make demo-up                      # Dependency-Track + Patchline via docker compose
```

| Variable | Default |
|---|---|
| `PATCHLINE_ADDR` | `:8080` |
| `PATCHLINE_DB_PATH` | `data/patchline.db` |
| `PATCHLINE_LOG_LEVEL` | `info` |
| `PATCHLINE_LOG_FORMAT` | `text` (`json`) |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` |

The demo serves Dependency-Track on `:8081` (API) and `:8082` (UI). Its API server needs several GB of memory.

## Scope

Out of scope: running scanners, version-range matching (delegated to Dependency-Track), SAST for first-party code, configuration audits, multi-tenancy.

## License

[Apache-2.0](LICENSE)

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
