# Patchline

**Track vulnerability fixes from detection to deployment — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development.** Detection, Slack, Renovate PRs, rescan resolution, due dates and the web UI work end to end. APIs, configuration and data models may still change.

Patchline closes the remediation loop. CI uploads an SBOM per build. Patchline matches it against a local [OSV](https://osv.dev) mirror (language packages) and a [Trivy](https://trivy.dev) server (OS packages in images), links each finding to its service and owners, follows Renovate PRs and rescans as evidence, and keeps a single Slack message up to date until the fix ships. Exceptions (not affected, false positive, risk acceptance, a later due date) are requested and approved in Patchline, and exported as VEX.

Renovate proposes *how to fix it*; Patchline tracks *whether it actually got fixed, by whom, and by when*. [Dependency-Track](https://dependencytrack.org/) is optional: connected, it is a second source of findings, and approved decisions are written back to it.

## Why

Scanners are good at finding vulnerabilities. What usually goes missing is everything after that:

- Who owns this finding, and which Slack channel should hear about it?
- Is there a PR for it? Was it merged? Did the merge actually fix it?
- Is the fix only on `main`, or is it running in `prod`?
- When is it due, and is anyone late?

Patchline answers these with **evidence** (commit SHA → PR → rescan), not with someone flipping a status by hand.

```
CI ── SBOM + commit ──▶ Patchline ──▶ Slack, webhook, web UI
                          │   ▲
   OSV mirror, Trivy ◀────┘   ├── fix PRs: Renovate → Gitea / Forgejo / GitHub webhook
   (matching)                 ├── inventory (YAML), CISA KEV
                              └── Dependency-Track webhook (optional)
```

When Dependency-Track is connected as well, the same vulnerability from both is one finding.

## Getting started

Try it locally in about a minute (Docker, `curl`, `jq`):

```sh
make demo-up      # Patchline + a Trivy server
make demo-seed    # uploads sample SBOMs; Patchline matches them against OSV and Trivy
```

Open http://localhost:18080. [deploy/compose/README.md](deploy/compose/README.md) walks through the findings, component search, a fix that resolves, and adding Dependency-Track (`make demo-up PROFILE=dependency-track && make demo-seed-dt`).

To run it on a server or your own machine, use [deploy/self-hosted](deploy/self-hosted/README.md): Patchline with a Trivy server, your inventory and your settings in `.env`, and optionally Dependency-Track.

```sh
cd deploy/self-hosted
cp .env.example .env               # set PATCHLINE_WEBHOOK_TOKEN and TRIVY_TOKEN
docker compose up -d --build
```

Or run the binary (Go, see [`go.mod`](go.mod)) or the container image directly:

```sh
make build && ./bin/patchline       # http://localhost:8080, SQLite in data/

docker build -t patchline .
docker run -p 8080:8080 -v patchline-data:/data patchline
```

On first start Patchline prints a one-time password for `admin` in its log (`docker compose logs patchline | grep one-time`). Sign in with it and choose a new password, then connect single sign-on for everyone else ([Sign-in and permissions](docs/access-control.md)).

Next, set up the inventory and connect your tools:

1. Describe services, owners, Slack channels and repositories in an inventory ([example](examples/inventory/services.yaml)) and set `PATCHLINE_INVENTORY_PATH` ([Registering projects and branches](docs/projects.md)).
2. Upload [SBOMs from CI](docs/integrations/sbom-ci.md) to Patchline.
3. Connect [Renovate](docs/integrations/renovate.md) with [Git webhooks](docs/integrations/git-webhooks.md), and [Slack](docs/integrations/slack.md).
4. Optionally, add [Dependency-Track](docs/integrations/dependency-track.md) as a second source.

## Documentation

- [How it works](docs/how-it-works.md) — finding states, resolution, PR linking, due dates, notifications
- [Registering projects and branches](docs/projects.md) — services, project names, versions as environments, branch and commit
- [Configuration](docs/configuration.md) — environment variables, endpoints, web UI
- [Sign-in and permissions](docs/access-control.md) — OIDC sign-in, groups mapped to permissions for assigning, requesting and approving exceptions, and webhook settings
- [Integration guides](docs/README.md) — SBOM in CI, detection with OSV and Trivy, Renovate, Gitea / Forgejo / GitHub, Slack, CISA KEV and EPSS, Dependency-Track

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and conventions. Please report security issues privately, not in public issues.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
