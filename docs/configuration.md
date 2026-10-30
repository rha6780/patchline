# Configuration

English | [한국어](configuration.ko.md)

Patchline is configured with environment variables. Services, owners and channels live in the [inventory](../examples/inventory/services.yaml); due dates in the [policy](../examples/policy/policy.yaml).

## Web UI

Open `http://localhost:8080/` (`:18080` in the demo). Every page and API call needs a sign-in. On first start, sign in as `admin` / `admin` and choose a new password. With OIDC, people sign in with single sign-on and their groups decide what they can do; see [Sign-in and permissions](access-control.md).

The header switches between English and Korean and between system, light and dark themes. The choice is kept in a cookie; without one, the language follows the browser.

| Page | Path |
|---|---|
| Overview: open findings, service × severity, needs attention, recently resolved, MTTR | `/` |
| Findings with quick filters (open, overdue, due within 7 days, open critical, awaiting verification) and filters by service, environment, state and severity | `/findings` |
| Finding: facts, fix pull requests, evidence timeline | `/findings/{id}` |
| Service: owners, repositories, findings per environment (highlights fixed-on-`main`-but-open-in-`prod`) | `/services/{name}` |
| Integrations: Dependency-Track projects with last BOM and commit, inventory projects without a BOM, failed webhooks and notifications | `/integrations` |
| Components: where packages are used, and what a vulnerability affects | `/components`, `/vulnerabilities/{id}` |
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
| `POST` | `/ingest/sbom` | CycloneDX or SPDX (JSON) SBOM upload for built-in detection ([guide](integrations/native-detection.md)). Authenticated with the webhook token |
| `GET` | `/api/v1/findings` | Findings with owners and assignee; filters `service`, `environment`, `state`, `assignee`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | A finding's timeline |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Pull requests linked to a finding |
| `GET` | `/api/v1/components` | Where packages are used in the stored SBOMs. `q`, `ecosystem`, `version` (e.g. `<2.17.0`), `limit` |
| `GET` | `/api/v1/vulnerabilities/{id}` | What a CVE or GHSA affects: affected snapshots, fixed versions, findings from every source |
| `GET` | `/api/v1/vex` | CycloneDX 1.5 VEX of a project version (`project`, `version`, `download=1` for a file) |
| `GET` | `/login` | Sign-in page (local admin, single sign-on) |
| `POST` | `/auth/local`, `/account/password` | Local admin sign-in and password change |
| `GET` | `/auth/login`, `/auth/callback`; `POST /auth/logout` | OIDC sign-in, when configured; sign-out |

`/api/v1/*` needs a session with `findings.read` and answers `401` otherwise (unless `PATCHLINE_ALLOW_ANONYMOUS=true`).

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
| `PATCHLINE_OSV_ECOSYSTEMS` | `Maven,npm,PyPI,Go` | OSV ecosystems for built-in detection (also `crates.io`, `NuGet`, `RubyGems`, `Packagist`). `off` only stores SBOMs |
| `PATCHLINE_OSV_URL` | OSV exports | Where the OSV exports are served, for an internal mirror |
| `PATCHLINE_OSV_REFRESH` | `6h` | How often OSV changes are fetched |
| `PATCHLINE_PUBLIC_URL` | — | Where users reach Patchline; required with OIDC (redirect URI `/auth/callback`). `https://` makes the session cookie Secure |
| `PATCHLINE_LOCAL_ADMIN` | `true` | Built-in `admin` account (starts as `admin` / `admin`, password change forced). `false` needs OIDC |
| `PATCHLINE_ALLOW_ANONYMOUS` | `false` | Let requests without a session read; only behind an authenticating proxy |
| `PATCHLINE_OIDC_ISSUER` | — | OIDC issuer URL. Unset = local admin only |
| `PATCHLINE_OIDC_CLIENT_ID` | — | OIDC client id |
| `PATCHLINE_OIDC_CLIENT_SECRET` | — | OIDC client secret |
| `PATCHLINE_OIDC_SCOPES` | `profile,email` | Scopes besides `openid` |
| `PATCHLINE_OIDC_GROUPS_CLAIM` | `groups` | ID token claim(s) read as groups, comma-separated; dotted names for nested claims (`realm_access.roles`) |
| `PATCHLINE_SESSION_TTL` | `12h` | How long a sign-in lasts |
| `PATCHLINE_ACCESS_POLICY_PATH` | — | Groups → permissions ([example](../examples/access/access-policy.yaml)). Unset = everyone who signs in can read |
