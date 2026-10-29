# Renovate

English | [한국어](renovate.ko.md)

Renovate proposes *how to fix it*. Patchline does not talk to Renovate directly: it reads Renovate's pull requests through the [Git webhooks](git-webhooks.md) and links them to findings.

## What Patchline reads from a pull request

| From | Used for |
|---|---|
| The change table in the PR body (`| Package | Change |`, `` `2.14.1` -> `2.17.1` ``) | Package names and versions; several rows per PR are fine |
| The title (`Update dependency X to vY`), when there is no table | A single package and its target version |
| Repository full name | Finding's repository (`repo` in the inventory) |
| Base branch | Environment the PR is matched in (`main` → findings of `...@main`, plus `default` for projects without a version) |

Each package is matched to open findings by name (Maven `group:artifact` equals `group/artifact`). The target version is then compared with the vulnerability's affected ranges from Dependency-Track.

| Verdict | Meaning |
|---|---|
| ✅ leaves the affected range | Target version is outside every affected range |
| ⚠️ still affected | Target version is still inside a range: the PR is not enough |
| ❔ not verified | No range known for this package |

A linked PR moves the finding to *in progress*; merging moves it to *awaiting verification*. Only the next BOM resolves it.

## Renovate configuration

Patchline works with Renovate's defaults. Keep the default PR body (do not drop the change table with a custom `prBodyTemplate`).

Self-hosted on Gitea, for example:

```js
// config.js (Renovate runner)
module.exports = {
  platform: 'gitea',
  endpoint: 'https://git.example.com/api/v1/',
  token: process.env.RENOVATE_TOKEN,
  autodiscover: true,
};
```

```jsonc
// renovate.json (repository or shared preset)
{
  "extends": ["config:recommended", "docker:pinDigests"],
  "osvVulnerabilityAlerts": true,
  "vulnerabilityAlerts": { "labels": ["security"] }
}
```

| Option | Why |
|---|---|
| `osvVulnerabilityAlerts` | Opens security PRs from OSV data on platforms without GitHub's alerts |
| `docker:pinDigests` | Pins base images by digest, so rebuilt images (OS package fixes) arrive as PRs |
| `vulnerabilityAlerts.labels` | Optional: makes security PRs easy to spot; Patchline does not need the label |

## Limits

- Base-image updates are not matched to OS-package findings; those resolve through the rescan of the new image.
- Transitive dependencies are matched only when the PR names that package. Upgrading a parent (for example Spring Boot) resolves them through the rescan.

## Check

Open a Renovate PR for a package with an open finding. The finding's page shows the PR with its verdict, and the Slack thread gets "Fix PR opened".
