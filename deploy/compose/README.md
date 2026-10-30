# Compose demo

Runs Dependency-Track 4.14 (API server, frontend, PostgreSQL) and Patchline.

| Service | URL |
|---|---|
| Patchline | http://localhost:18080 (`/readyz`, `/api/v1/findings`) |
| Dependency-Track UI | http://localhost:18082 (first login `admin` / `admin`) |
| Dependency-Track API | http://localhost:18081 |

Ports and secrets can be changed in `.env` (copy `.env.example`).
The Dependency-Track API server needs several GB of memory; give Docker at least 8 GB.
The first start takes a few minutes while it downloads vulnerability data.

## 1. Start

```sh
cp deploy/compose/.env.example deploy/compose/.env
make demo-up
```

Patchline is at http://localhost:18080. The demo lets you read without signing in; sign in as `admin` / `admin` (you will be asked to choose a new password) to assign findings, approve requests or rotate webhook secrets.

### Shortcut: `make demo-seed`

Once Dependency-Track answers (the first start takes a few minutes), `make demo-seed` does steps 2, 3 and 5 for you: it sets Dependency-Track's admin password to `patchline-demo` (or `DT_ADMIN_PASSWORD`), creates Patchline's API key in `.env`, adds the alert, turns on the Trivy analyzer, restarts Patchline and uploads the sample SBOM as `storefront-api@main` and `@prod`.

The compose file runs a Trivy server because out of the box Dependency-Track matches package URLs only through OSS Index (which needs a token) or the OSV and GitHub mirrors (off by default), so the sample SBOM would show no findings. To set it up by hand, see [Trivy](../../docs/integrations/trivy.md). It needs `curl` and `jq` and is safe to run again. Then continue with step 6.

To do it by hand instead:

## 2. Create an API key for Patchline

In the Dependency-Track UI: **Administration → Access Management → Teams → Automation**.

1. Add permissions `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`, `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`.
2. Generate an API key and set it as `PATCHLINE_DT_API_KEY` in `.env`.
3. `make demo-up` again to restart Patchline with the key.

(For a real setup use separate teams: one key for CI uploads, one read-only key for Patchline.)

## 3. Point Dependency-Track at Patchline

**Administration → Notifications → Alerts → Create Alert**

| Field | Value |
|---|---|
| Publisher | Outbound Webhook |
| Scope | Portfolio |
| Groups | `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY`, `BOM_PROCESSED`, `PROJECT_AUDIT_CHANGE` |
| Destination | `http://patchline:8080/webhooks/dependency-track?token=<PATCHLINE_WEBHOOK_TOKEN>` |

The destination uses the in-network name `patchline`, not `localhost`.

## 4. (Optional) Connect Slack

Without a token, notifications are printed to the Patchline log (`make demo-logs`).

1. Create a Slack app at https://api.slack.com/apps, add the bot scopes `chat:write` and `chat:write.public`, and install it to the workspace.
2. Set `PATCHLINE_SLACK_BOT_TOKEN` (the `xoxb-...` token) in `.env`, and optionally `PATCHLINE_SLACK_DEFAULT_CHANNEL`.
3. Edit `slack_channel` in `examples/inventory/services.yaml` to a channel that exists, then `make demo-up`.

## 4b. (Optional) Connect Gitea / Forgejo / GitHub

Add a **Pull Request** webhook to the repository that holds the service code:

| Field | Value |
|---|---|
| URL | `http://<host reachable from Gitea>:18080/webhooks/gitea` |
| Secret | `PATCHLINE_GITEA_WEBHOOK_SECRET` from `.env` |
| Events | Pull request |

The repository must be listed in `examples/inventory/services.yaml` (`repo: owner/name`).
When Renovate opens a fix PR, the finding moves to *in progress* and the thread shows
whether the new version leaves the affected range.

## 5. Upload a sample SBOM

```sh
curl -sS -X POST http://localhost:18081/api/v1/bom \
  -H "X-Api-Key: $PATCHLINE_DT_API_KEY" \
  -F autoCreate=true -F projectName=storefront-api -F projectVersion=main \
  -F bom=@examples/sbom/storefront-api.cdx.json
```

`storefront-api` is mapped to the `storefront` service in `examples/inventory/services.yaml`;
the project version `main` becomes the environment.

## 6. Check the findings

```sh
curl -sS http://localhost:18080/api/v1/findings | jq '.findings[] | {service, environment, vuln_id, severity, owners}'
make demo-logs
```

Each finding is posted once. Change its analysis in Dependency-Track
(for example *In Triage* or *Not Affected*): the same message is updated and the
change is added to its thread.

Findings appear once Dependency-Track has analyzed the BOM. If the mirror
is still downloading on first start, upload the SBOM again later — Patchline
de-duplicates.

## 7. Fix it and watch it resolve

`storefront-api.fixed.cdx.json` has the patched versions and a different commit:

```sh
curl -sS -X POST http://localhost:18081/api/v1/bom \
  -H "X-Api-Key: $PATCHLINE_DT_API_KEY" \
  -F autoCreate=true -F projectName=storefront-api -F projectVersion=main \
  -F bom=@examples/sbom/storefront-api.fixed.cdx.json
```

About two minutes later (`PATCHLINE_DT_RECONCILE_DELAY`) the findings become
*resolved*, the messages are updated, and the thread names commit `3f2a9c1e0b7d`.
Upload the first SBOM again to see them *reopened*.
