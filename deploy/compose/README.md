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
