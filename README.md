# Patchline

**Track vulnerability fixes from detection to deployment — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development (M1).** Findings are collected from Dependency-Track; notifications are not implemented yet. APIs, config and data models will change.

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
| ✅ **M0** Skeleton | Module layout, config, SQLite + migrations, `/healthz`, Compose demo (DT + Patchline) |
| ✅ **M1** Intake | DT webhooks → inbox → findings joined with the inventory |
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
│   ├── intake/             # inbox processor: webhook deliveries → findings
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

```sh
make build && ./bin/patchline     # :8080
make demo-up                      # Dependency-Track + Patchline via docker compose
```

The demo walkthrough (API key, webhook, sample SBOM) is in [deploy/compose/README.md](deploy/compose/README.md).
Demo ports: Patchline `18080`, Dependency-Track API `18081`, UI `18082` (change them in `deploy/compose/.env`).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (database) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track outbound webhook (`?token=` or `Authorization: Bearer`) |
| `GET` | `/api/v1/findings` | Findings with owners; filters `service`, `environment`, `state`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | A finding's timeline |

### Configuration

| Variable | Default | |
|---|---|---|
| `PATCHLINE_ADDR` | `:8080` | Listen address |
| `PATCHLINE_DB_PATH` | `data/patchline.db` | SQLite file |
| `PATCHLINE_INVENTORY_PATH` | — | Inventory YAML file or directory ([example](examples/inventory/services.yaml)) |
| `PATCHLINE_WEBHOOK_TOKEN` | — | Shared secret for webhooks. Unset = no authentication (development only) |
| `PATCHLINE_DT_URL` | — | Dependency-Track API server URL |
| `PATCHLINE_DT_API_KEY` | — | API key with `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` |
| `PATCHLINE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PATCHLINE_LOG_FORMAT` | `text` | `text` or `json` |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown limit |

### How intake works

1. The webhook handler validates the payload, stores it in an inbox table (de-duplicated by content hash) and returns `202`.
2. A background processor handles inbox entries, retrying failures with backoff (30s → 30m, 5 attempts).
3. `NEW_VULNERABILITY` and `NEW_VULNERABLE_DEPENDENCY` carry the findings directly; `BOM_PROCESSED` makes Patchline read the project's current findings from the Dependency-Track API.
4. Each Dependency-Track project **name** is resolved to a service through the inventory, and its **version** becomes the environment (`main`, `prod`). Projects not in the inventory are kept as *unregistered*.
5. A finding is one service × environment × component × vulnerability. CVE ids are preferred over GHSA/OSV ids as the canonical id; the others are kept as aliases.

## Scope

Out of scope: running scanners, version-range matching (delegated to Dependency-Track), SAST for first-party code, configuration audits, multi-tenancy.

## License

[Apache-2.0](LICENSE)

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
