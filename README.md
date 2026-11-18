# Patchline

**Track every vulnerability from detection until the fix is deployed — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development.** Detection, notifications, Renovate PR tracking, resolution by rescan, due dates and the web UI work end to end. APIs, configuration and data models may still change.

Scanners tell you what is vulnerable. Patchline keeps track of what happens next: who owns each finding, which pull request fixes it, whether the fix actually removed the vulnerability, and whether it reached production before the due date.

## What it does

- **Detects** vulnerabilities in the SBOMs your CI uploads for each build, using a local [OSV](https://osv.dev) mirror for language packages and a [Trivy](https://trivy.dev) server for OS packages in images.
- **Assigns** each finding to its service, owners and Slack channel, from an inventory you keep in YAML.
- **Follows the fix**: links Renovate pull requests from Gitea, Forgejo or GitHub, and marks a finding resolved only when a later SBOM no longer contains the vulnerability.
- **Sets due dates** from severity, exposure and the CISA KEV catalog, and reminds people before and after they pass.
- **Notifies** through one Slack message per finding that is kept up to date until the fix ships, or through a signed webhook.
- **Handles exceptions** (not affected, false positive, risk acceptance, a later due date) as requests that someone else approves, and exports the decisions as VEX.
- **Checks itself**: Patchline matches its own dependencies too and tells you when it needs an upgrade.

Renovate proposes *how* to fix a vulnerability; Patchline tracks *whether* it was fixed, *by whom* and *by when*. [Dependency-Track](https://dependencytrack.org/) is optional: when connected, it is a second source of findings, and approved decisions are written back to it.

## Why

Finding vulnerabilities is the easy part. What usually goes missing is everything after that:

- Who owns this finding, and which Slack channel should hear about it?
- Is there a PR for it? Was it merged? Did the merge actually fix it?
- Is the fix only on `main`, or is it running in `prod`?
- When is it due, and is anything overdue?

Patchline answers these from **evidence** (commit SHA → PR → rescan) rather than from someone changing a status by hand.

```
CI ── SBOM + commit ──▶ Patchline ──▶ Slack, webhook, web UI
                          │   ▲
   OSV mirror, Trivy ◀────┘   ├── fix PRs: Renovate → Gitea / Forgejo / GitHub webhook
   (matching)                 ├── inventory (YAML), CISA KEV
                              └── Dependency-Track webhook (optional)
```

If Dependency-Track is connected too, a vulnerability that both report becomes a single finding.

## Getting started

Try it locally in about a minute (requires Docker, `curl` and `jq`):

```sh
make demo-up      # Patchline + a Trivy server
make demo-seed    # uploads sample SBOMs; Patchline matches them against OSV and Trivy
```

Open http://localhost:18080. [deploy/compose/README.md](deploy/compose/README.md) walks you through the findings, component search, a fix being resolved, and adding Dependency-Track (`make demo-up PROFILE=dependency-track && make demo-seed-dt`).

To install it on a server or your own machine, use [deploy/self-hosted](deploy/self-hosted/README.md). It runs Patchline with a Trivy server, reads your inventory and settings from `.env`, and can start Dependency-Track as well.

```sh
cd deploy/self-hosted
cp .env.example .env               # set PATCHLINE_WEBHOOK_TOKEN and TRIVY_TOKEN
docker compose up -d --build
```

You can also run the binary (Go version in [`go.mod`](go.mod)) or the container image directly:

```sh
make build && ./bin/patchline       # http://localhost:8080, SQLite in data/

docker build -t patchline .
docker run -p 8080:8080 -v patchline-data:/data patchline
```

On first start, Patchline prints a one-time password for the `admin` account in its log (with Docker Compose: `docker compose logs patchline | grep one-time`). Sign in with it and choose a new password, then set up single sign-on for everyone else ([Sign-in and permissions](docs/access-control.md)).

Then describe your services and connect your tools:

1. List services, owners, Slack channels and repositories in an inventory ([example](examples/inventory/services.yaml)) and point `PATCHLINE_INVENTORY_PATH` at it ([Registering projects and branches](docs/projects.md)).
2. Have CI [upload an SBOM](docs/integrations/sbom-ci.md) for each build.
3. Connect [Renovate](docs/integrations/renovate.md) through [Git webhooks](docs/integrations/git-webhooks.md), and connect [Slack](docs/integrations/slack.md).
4. Optionally, add [Dependency-Track](docs/integrations/dependency-track.md) as a second source.

## Documentation

- [How it works](docs/how-it-works.md) — finding states, resolution, PR linking, due dates, notifications
- [Registering projects and branches](docs/projects.md) — services, project names, versions as environments, branches and commits
- [Configuration](docs/configuration.md) — environment variables, endpoints, web UI
- [Sign-in and permissions](docs/access-control.md) — OIDC sign-in and which groups may assign findings, request and approve exceptions, or change settings
- [Integration guides](docs/README.md) — SBOMs in CI, detection with OSV and Trivy, Renovate, Gitea / Forgejo / GitHub, Slack, CISA KEV and EPSS, Dependency-Track

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and conventions. Please report security issues privately rather than in a public issue.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
