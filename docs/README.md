# Patchline documentation

English | [한국어](README.ko.md)

- [How it works](how-it-works.md): finding states, intake, resolution, PR linking, due dates, notifications
- [Configuration](configuration.md): environment variables, endpoints, web UI
- [Registering projects and branches](projects.md): services in the inventory, project names, versions as environments, branch and commit, retiring them
- [Design: built-in detection](design/native-detection.md): how Patchline matches SBOMs with OSV and Trivy, and what comes next
- [Design: integrations behind ports](design/source-ports.md): how tools plug in as adapters
- [Sign-in and permissions](access-control.md): OIDC (FusionAuth, Keycloak, ...), group → permission mapping, assignment, approvals

## Integrations

Patchline sits between the tools you already run. Each guide covers what to set up in that tool, what to set in Patchline, and how to check that it works.

By default Patchline needs no other scanner: CI uploads SBOMs, Patchline matches them, and decisions are made in Patchline. Dependency-Track can be added as a second source.

| Tool | Role | Guide |
|---|---|---|
| SBOM in CI (Trivy, CycloneDX) | Produces an SBOM per build and uploads it to Patchline, with the commit as evidence | [sbom-ci.md](integrations/sbom-ci.md) |
| Detection: OSV and Trivy | Matches the uploaded SBOMs: a local OSV mirror for language packages, a Trivy server for OS packages; decisions and VEX | [native-detection.md](integrations/native-detection.md), [trivy.md](integrations/trivy.md) |
| Renovate | Opens fix pull requests that Patchline links to findings and checks against the affected ranges | [renovate.md](integrations/renovate.md) |
| Gitea / Forgejo / GitHub | Pull request webhooks | [git-webhooks.md](integrations/git-webhooks.md) |
| Slack | One message per finding, updates and thread history | [slack.md](integrations/slack.md) |
| Webhook notifications | Signed JSON for each finding and change, for other systems | [webhook-notifications.md](integrations/webhook-notifications.md) |
| CISA KEV and EPSS | Risk signals that raise severity and shorten due dates | [kev-epss.md](integrations/kev-epss.md) |
| Dependency-Track (optional) | A second source of findings and analysis decisions; approved decisions are written back | [dependency-track.md](integrations/dependency-track.md) |

## How the pieces connect

```
CI ── SBOM + commit ──▶ Patchline ──▶ Slack, webhook
                          │   ▲
   OSV mirror, Trivy ◀────┘   ├── fix PRs: Renovate → Gitea / Forgejo / GitHub webhook
                              ├── CISA KEV
                              └── Dependency-Track webhook (optional)
```

Every integration meets in the **inventory** (`PATCHLINE_INVENTORY_PATH`): it maps project names and repositories to services, owners and Slack channels. See [examples/inventory/services.yaml](../examples/inventory/services.yaml) and [Registering projects and branches](projects.md).

| Name in the tool | Must match in the inventory |
|---|---|
| Project of an SBOM upload (`project`), or Dependency-Track project name | `repositories[].projects` (default: last segment of `repo`) |
| Version of an upload, or Dependency-Track project version | Environment, e.g. `main`, `prod` |
| Repository full name (`owner/name`) | `repositories[].repo` |
| Pull request base branch | Environment the PR is matched in (and `default`) |

For a local end-to-end run, see the [compose demo](../deploy/compose/README.md). To install Patchline on a server or your machine, see [deploy/self-hosted](../deploy/self-hosted/README.md).
