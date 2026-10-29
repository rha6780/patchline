# Patchline documentation

English | [한국어](README.ko.md)

## Integrations

Patchline sits between the tools you already run. Each guide covers what to set up in that tool, what to set in Patchline, and how to check that it works.

| Tool | Role | Guide |
|---|---|---|
| Dependency-Track | Vulnerability source: findings, analysis decisions, BOM processing | [dependency-track.md](integrations/dependency-track.md) |
| SBOM in CI (Trivy, CycloneDX) | Produces the BOMs Dependency-Track analyzes, with the commit as evidence | [sbom-ci.md](integrations/sbom-ci.md) |
| Renovate | Opens fix pull requests that Patchline links to findings | [renovate.md](integrations/renovate.md) |
| Gitea / Forgejo / GitHub | Pull request webhooks | [git-webhooks.md](integrations/git-webhooks.md) |
| Slack | One message per finding, updates and thread history | [slack.md](integrations/slack.md) |
| CISA KEV and EPSS | Risk signals that raise severity and shorten due dates | [kev-epss.md](integrations/kev-epss.md) |

Dependency-Track is the vulnerability source today; support for other tools as sources is planned.

## How the pieces connect

```
CI ── SBOM + commit ──▶ Dependency-Track ── webhook ──▶ Patchline ──▶ Slack
                                                            ▲   ▲
Renovate ── fix PR ──▶ Gitea / Forgejo / GitHub ── webhook ─┘   └── CISA KEV
```

Every integration meets in the **inventory** (`PATCHLINE_INVENTORY_PATH`): it maps Dependency-Track project names and repositories to services, owners and Slack channels. See [examples/inventory/services.yaml](../examples/inventory/services.yaml).

| Name in the tool | Must match in the inventory |
|---|---|
| Dependency-Track project name | `repositories[].dependency_track_projects` (default: last segment of `repo`) |
| Dependency-Track project version | Environment, e.g. `main`, `prod` |
| Repository full name (`owner/name`) | `repositories[].repo` |
| Pull request base branch | Environment the PR is matched in |

For a local end-to-end run, see the [compose demo](../deploy/compose/README.md).
