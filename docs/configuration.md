# Configuration

English | [한국어](configuration.ko.md)

Patchline is configured with environment variables. Services, owners and channels live in the [inventory](../examples/inventory/services.yaml); due dates in the [policy](../examples/policy/policy.yaml).

## Web UI

Open `http://localhost:8080/` (`:18080` in the demo). Without sign-in the UI is open and read-only, so keep it on a trusted network or behind an authenticating proxy. With OIDC, people sign in and their groups decide what they can change; see [Sign-in and permissions](access-control.md).

The header switches between English and Korean and between system, light and dark themes. The choice is kept in a cookie; without one, the language follows the browser.

| Page | Path |
|---|---|
| Overview: open findings, service × severity, needs attention, recently resolved, MTTR | `/` |
| Findings with quick filters (open, overdue, due within 7 days, open critical, awaiting verification) and filters by service, environment, state and severity | `/findings` |
| Finding: facts, fix pull requests, evidence timeline | `/findings/{id}` |
| Service: owners, repositories, findings per environment (highlights fixed-on-`main`-but-open-in-`prod`) | `/services/{name}` |
| Integrations: Dependency-Track projects with last BOM and commit, inventory projects without a BOM, failed webhooks and notifications | `/integrations` |
| Approvals: pending risk acceptances and due date extensions, recent decisions (`exceptions.request` or `exceptions.approve`) | `/approvals` |
| Settings: webhook token and secret rotation (`settings.webhooks`), audit log (`audit.read`) | `/settings` |
| Integrations guide: vulnerability sources Patchline can take alerts from (Dependency-Track supported, OpenCVE planned), how to connect them, and links to the guides in `docs/integrations` | `/docs/integrations` |

Every page has a footer with links to the integrations guide, this documentation, the upstream tools and the project.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (database) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track outbound webhook (`?token=` or `Authorization: Bearer`) |
| `POST` | `/webhooks/gitea` | Gitea / Forgejo / GitHub `pull_request` webhook (HMAC signature, or the token) |
| `GET` | `/api/v1/findings` | Findings with owners and assignee; filters `service`, `environment`, `state`, `assignee`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | A finding's timeline |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Pull requests linked to a finding |
| `GET` | `/auth/login`, `/auth/callback`; `POST /auth/logout` | OIDC sign-in, when configured |

With sign-in configured, `/api/v1/*` needs a session with `findings.read` and answers `401` otherwise.

## Configuration

| Variable | Default | |
|---|---|---|
| `PATCHLINE_ADDR` | `:8080` | Listen address |
| `PATCHLINE_DB_PATH` | `data/patchline.db` | SQLite file |
| `PATCHLINE_INVENTORY_PATH` | — | Inventory YAML file or directory ([example](../examples/inventory/services.yaml)) |
| `PATCHLINE_WEBHOOK_TOKEN` | — | Shared secret for webhooks. Unset = no authentication (development only) |
| `PATCHLINE_DT_URL` | — | Dependency-Track API server URL |
| `PATCHLINE_DT_API_KEY` | — | API key with `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` |
| `PATCHLINE_GITEA_WEBHOOK_SECRET` | — | Secret of the pull request webhook. Unset = use `PATCHLINE_WEBHOOK_TOKEN` |
| `PATCHLINE_DT_UI_URL` | — | Dependency-Track UI URL for links in messages |
| `PATCHLINE_DT_RECONCILE_DELAY` | `2m` | Wait after `BOM_PROCESSED` before comparing findings |
| `PATCHLINE_POLICY_PATH` | — | Remediation policy YAML ([example](../examples/policy/policy.yaml)). Unset = built-in defaults |
| `PATCHLINE_KEV_URL` | CISA feed | CISA KEV catalog URL, refreshed daily; `off` disables |
| `PATCHLINE_SLACK_BOT_TOKEN` | — | Slack bot token (`chat:write`, `chat:write.public`). Unset = print to stdout |
| `PATCHLINE_SLACK_DEFAULT_CHANNEL` | — | Channel for services without `slack_channel` and unregistered projects |
| `PATCHLINE_NOTIFY_MIN_SEVERITY` | `medium` | Lowest severity that is posted |
| `PATCHLINE_NOTIFY_LANG` | `en` | Language of Slack and console messages: `en` or `ko` |
| `PATCHLINE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PATCHLINE_LOG_FORMAT` | `text` | `text` or `json` |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown limit |
| `PATCHLINE_PUBLIC_URL` | — | Where users reach Patchline; required with OIDC (redirect URI `/auth/callback`) |
| `PATCHLINE_OIDC_ISSUER` | — | OIDC issuer URL. Unset = no sign-in, read-only UI |
| `PATCHLINE_OIDC_CLIENT_ID` | — | OIDC client id |
| `PATCHLINE_OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `PATCHLINE_OIDC_SCOPES` | `profile,email` | Scopes besides `openid` |
| `PATCHLINE_OIDC_GROUPS_CLAIM` | `groups` | ID token claim(s) read as groups, comma-separated; dotted names for nested claims (`realm_access.roles`) |
| `PATCHLINE_SESSION_TTL` | `12h` | How long a sign-in lasts |
| `PATCHLINE_ACCESS_POLICY_PATH` | — | Groups → permissions ([example](../examples/access/access-policy.yaml)). Unset = everyone who signs in can read |
