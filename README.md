# Patchline

**Track vulnerability fixes from detection to deployment — one timeline, one deadline, one Slack thread.**

English | [한국어](README.ko.md)

> ⚠️ **Status: early development.** Detection, Slack, Renovate PRs, rescan resolution, due dates and the web UI work end to end. APIs, configuration and data models may still change.

Patchline sits on top of [Dependency-Track](https://dependencytrack.org/) and closes the remediation loop: it links findings to services and owners, follows Renovate PRs and rescans as evidence, and keeps a single Slack message up to date until the fix ships.

Patchline does **not** detect vulnerabilities or compare versions itself. Dependency-Track decides *what is vulnerable*; Renovate proposes *how to fix it*; Patchline tracks *whether it actually got fixed, by whom, and by when*.

## Why

Scanners are good at finding vulnerabilities. What usually goes missing is everything after that:

- Who owns this finding, and which Slack channel should hear about it?
- Is there a PR for it? Was it merged? Did the merge actually fix it?
- Is the fix only on `main`, or is it running in `prod`?
- When is it due, and is anyone late?

Patchline answers these with **evidence** (commit SHA → PR → rescan), not with someone flipping a status by hand.

```
CI ── SBOM + commit ──▶ Dependency-Track ── webhook ──▶ Patchline ──▶ Slack, web UI
                                                            ▲   ▲
Renovate ── fix PR ──▶ Gitea / Forgejo / GitHub ── webhook ─┘   └── inventory (YAML), CISA KEV
```

Vulnerabilities come from Dependency-Track, from Patchline's own matching of uploaded SBOMs against [OSV](https://osv.dev), or both; the same vulnerability from both is one finding.

## Getting started

Try it locally in about a minute (Docker, `curl`, `jq`):

```sh
make demo-up      # Patchline + a Trivy server
make demo-seed    # uploads sample SBOMs; Patchline matches them against OSV and Trivy
```

Open http://localhost:18080. [deploy/compose/README.md](deploy/compose/README.md) walks through the findings, component search, a fix that resolves, and adding Dependency-Track (`make demo-up PROFILE=dependency-track && make demo-seed-dt`).

To run it on a server or your own machine, use [deploy/self-hosted](deploy/self-hosted/README.md): Patchline with your existing Dependency-Track, or both together, with your inventory and settings in `.env`.

```sh
cd deploy/self-hosted
cp .env.example .env               # set PATCHLINE_WEBHOOK_TOKEN and the Dependency-Track URL and key
docker compose up -d --build
```

Or run the binary (Go, see [`go.mod`](go.mod)) or the container image directly:

```sh
make build && ./bin/patchline       # http://localhost:8080, SQLite in data/

docker build -t patchline .
docker run -p 8080:8080 -v patchline-data:/data patchline
```

Sign in as `admin` / `admin` and choose a new password; then connect single sign-on for everyone else ([Sign-in and permissions](docs/access-control.md)).

Next, set up the inventory and connect your tools:

1. Describe services, owners, Slack channels and repositories in an inventory ([example](examples/inventory/services.yaml)) and set `PATCHLINE_INVENTORY_PATH`.
2. Connect [Dependency-Track](docs/integrations/dependency-track.md), [SBOMs in CI](docs/integrations/sbom-ci.md), [Renovate](docs/integrations/renovate.md) with [Git webhooks](docs/integrations/git-webhooks.md), and [Slack](docs/integrations/slack.md).

## Documentation

- [How it works](docs/how-it-works.md) — finding states, resolution, PR linking, due dates, notifications
- [Configuration](docs/configuration.md) — environment variables, endpoints, web UI
- [Sign-in and permissions](docs/access-control.md) — OIDC sign-in, groups mapped to permissions for assigning, requesting and approving exceptions, and webhook settings
- [Integration guides](docs/README.md) — Dependency-Track, SBOM in CI, Renovate, Gitea / Forgejo / GitHub, Slack, CISA KEV and EPSS

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, checks and conventions. Please report security issues privately, not in public issues.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

Patchline works with Dependency-Track but is not affiliated with or endorsed by OWASP or the Dependency-Track project.
