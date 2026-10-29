# Dependency-Track

English | [한국어](dependency-track.ko.md)

Dependency-Track decides *what is vulnerable*. Patchline receives its notifications, reads findings through its REST API, and treats its analysis decisions as the single place where people triage.

Tested with Dependency-Track 4.14.

## 1. API key for Patchline

**Administration → Access Management → Teams**: create a team (for example `patchline`) with these permissions, then generate an API key.

| Permission | Used for |
|---|---|
| `VIEW_PORTFOLIO` | Reading project findings and vulnerability details (affected version ranges) |
| `VIEW_VULNERABILITY` | Reading findings |

Keep CI uploads on a separate team (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`), so the key Patchline holds cannot change anything.

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
| Project **name** | Looked up in the inventory → service, owners, Slack channel |
| Project **version** | Environment (`main`, `prod`, ...); empty becomes `default` |

Use one project version per environment, for example `storefront-api@main` from the default branch and `storefront-api@prod` from the deployed image. Each version resolves on its own, which is how the UI shows "fixed on main, still open in prod".

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
| Findings arrive, but never resolve | `PATCHLINE_DT_URL` / `PATCHLINE_DT_API_KEY` missing, or the key lacks `VIEW_PORTFOLIO` |
| Service shows as unregistered | Project name does not match the inventory |
| Failures listed under **Webhook processing failures** | The last error explains it; items are retried with backoff |
