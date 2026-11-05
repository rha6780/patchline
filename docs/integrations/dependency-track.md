# Dependency-Track

English | [한국어](dependency-track.ko.md)

Optional. Patchline finds vulnerabilities on its own ([Detection](native-detection.md)); if you already run Dependency-Track, connect it as a second source. Patchline receives its notifications and reads findings through its REST API. Decisions stay in Patchline's approvals, and an approved decision on a finding Dependency-Track reports is written back as its analysis, so both tools agree. Analyses made directly in Dependency-Track move the finding in Patchline too.

Findings both report are one finding. Upload the same SBOM to both ([SBOM in CI](sbom-ci.md#uploading-to-dependency-track-as-well)), or only to Dependency-Track for projects Patchline should not match itself.

Tested with Dependency-Track 4.14.

## 1. API key for Patchline

**Administration → Access Management → Teams**: create a team (for example `patchline`) with these permissions, then generate an API key.

| Permission | Used for |
|---|---|
| `VIEW_VULNERABILITY` | Reading a project's current findings after `BOM_PROCESSED` (`GET /api/v1/finding/project/{uuid}`) |
| `VIEW_PORTFOLIO` | Reading vulnerability details, used for the affected version ranges when judging fix PRs (`GET /api/v1/vulnerability/source/{source}/vuln/{id}`) |
| `VULNERABILITY_ANALYSIS` | Writing approved decisions back: risk acceptance, not affected, false positive (`PUT /api/v1/analysis`) |

Keep CI uploads on a separate team (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`). Without `VULNERABILITY_ANALYSIS`, the key Patchline holds cannot change anything, and approving a decision on a finding Dependency-Track reports fails (nothing is approved).

## 2. Notification rule

**Administration → Notifications → Alerts → Create Alert**

| Field | Value |
|---|---|
| Publisher | Outbound Webhook |
| Scope | Portfolio |
| Groups | `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY`, `BOM_PROCESSED`, `PROJECT_AUDIT_CHANGE` |
| Destination | `https://patchline.example.com/webhooks/dependency-track?token=<PATCHLINE_WEBHOOK_TOKEN>` |

Limit the rule to specific projects if only part of the portfolio should be tracked.

| Group | What Patchline does |
|---|---|
| `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY` | Creates findings from the payload |
| `BOM_PROCESSED` | Records the BOM's commit, then after `PATCHLINE_DT_RECONCILE_DELAY` reads the project's findings: new ones are added, missing ones are resolved |
| `PROJECT_AUDIT_CHANGE` | Applies the analysis decision to the finding's state |

## 3. Patchline settings

```sh
PATCHLINE_DT_URL=https://dtrack-api.example.com     # API server, reachable from Patchline
PATCHLINE_DT_API_KEY=odt_...                         # key from step 1
PATCHLINE_DT_UI_URL=https://dtrack.example.com      # frontend, for links in messages and the UI
PATCHLINE_WEBHOOK_TOKEN=<long random string>        # same value as in the destination URL
PATCHLINE_DT_RECONCILE_DELAY=2m                     # raise it if analysis of large BOMs takes longer
```

Without `PATCHLINE_DT_URL` and the key, notifications still create findings, but nothing is resolved by rescans.

## 4. Projects, versions and the inventory

| Dependency-Track | Patchline |
|---|---|
| Project **name** | Looked up in the inventory (`projects`) → service, owners, Slack channel |
| Project **version** | Environment (`main`, `prod`, ...); empty becomes `default` |

Use the same names as for uploads to Patchline ([Registering projects and branches](../projects.md)): one project version per environment, for example `storefront-api@main` from the default branch and `storefront-api@prod` from the deployed image. Each version resolves on its own, which is how the UI shows "fixed on main, still open in prod".

Projects missing from the inventory are kept as *unregistered* and listed on **Integrations** in the UI.

## 5. Analysis decisions

Triage in Dependency-Track (finding → **Analysis**). Patchline maps the decision:

| Dependency-Track | Patchline state |
|---|---|
| `NOT_SET` | new |
| `IN_TRIAGE`, `EXPLOITABLE` | in progress |
| `RESOLVED` | awaiting verification (a rescan confirms it) |
| `NOT_AFFECTED`, `FALSE_POSITIVE` | not affected |
| Suppressed (any other state) | risk accepted |

## Check

1. Upload a BOM to a project listed in the inventory.
2. `GET /api/v1/findings` on Patchline lists the findings with owners.
3. **Integrations** in the UI shows the project with its last BOM time and commit.

| Symptom | Cause |
|---|---|
| Webhook returns `401` | Token in the destination URL differs from `PATCHLINE_WEBHOOK_TOKEN` |
| Findings arrive, but never resolve | `PATCHLINE_DT_URL` / `PATCHLINE_DT_API_KEY` missing, or the key lacks `VIEW_VULNERABILITY` |
| Service shows as unregistered | Project name does not match the inventory |
| Failures listed under **Integrations → Processing failures** | The last error explains it; items are retried with backoff |
