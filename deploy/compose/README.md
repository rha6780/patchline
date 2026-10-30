# Compose demo

Runs Patchline with its own detection: SBOMs uploaded to Patchline are matched against [OSV](https://osv.dev) (language packages) and a Trivy server (OS packages). Dependency-Track is optional (step 6).

| Service | URL |
|---|---|
| Patchline | http://localhost:18080 |
| Dependency-Track UI | http://localhost:18082 (only with `PROFILE=dependency-track`) |

Ports and secrets can be changed in `.env` (copy `.env.example`). The demo needs `curl` and `jq`.

## 1. Start

```sh
make demo-up
```

This builds Patchline and starts it with a Trivy server. On first start Patchline downloads the OSV data for Maven and npm (npm is about 220 MB) and Trivy downloads its database; both take a minute or two.

## 2. Load the samples

```sh
make demo-seed
```

It waits for both databases, then uploads three SBOMs to `/ingest/sbom` (`examples/sbom`):

| Project @ version | SBOM | Matched by |
|---|---|---|
| `storefront-api@main` | log4j-core 2.14.1, jackson-databind 2.9.10.1, lodash 4.17.15 | OSV |
| `storefront-api@prod` | the same | OSV |
| `storefront-api-image@prod` | Debian 11 packages (libssl1.1, zlib1g, libc6, ...) | Trivy |

All three belong to the `storefront` service (`examples/inventory/services.yaml`); the version is the environment.

## 3. Look around

Open http://localhost:18080. The demo lets you read without signing in. Sign in as `admin` / `admin` to change things; you will be asked to choose a new password first.

| Where | What |
|---|---|
| **Overview**, **Findings** | Findings with severity, due date and source (*Reported by: Patchline (OSV)*) |
| **Components** | Search `log4j`, or enter `CVE-2021-44228` to see what it affects, where it is fixed, and the findings |
| **Services → storefront** | `main` and `prod` side by side |
| **Integrations** | Each project with its commit, and a **VEX** download |
| A finding, signed in | Assign it; request *not affected*, *false positive*, *risk acceptance* or a due date extension, and approve as someone else (see [Sign-in and permissions](../../docs/access-control.md)) |

```sh
curl -sS http://localhost:18080/api/v1/findings | jq '.findings[] | {service, environment, vuln_id, severity}'
make demo-logs        # notifications are printed here without Slack
```

## 4. Fix it and watch it resolve

`storefront-api.fixed.cdx.json` has upgraded versions and a different commit:

```sh
curl -sS -X POST "http://localhost:18080/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer change-me" -H "Content-Type: application/json" \
  --data-binary @examples/sbom/storefront-api.fixed.cdx.json
```

The findings of the old versions on `main` become *resolved* with commit `3f2a9c1e0b7d` as evidence. `prod` still runs the old SBOM, so **Services → storefront** highlights "fixed on main, still open in prod". Newer advisories against the upgraded versions show up as new findings. Upload the first SBOM again to see the old ones *reopened*.

(`change-me` is `PATCHLINE_WEBHOOK_TOKEN`; an [API token](../../docs/access-control.md#api-tokens) with `sbom.upload` works too.)

## 5. (Optional) Slack and Git

**Slack**:
1. Create a Slack app at https://api.slack.com/apps with the bot scopes `chat:write` and `chat:write.public`, and install it.
2. Set `PATCHLINE_SLACK_BOT_TOKEN` (and optionally `PATCHLINE_SLACK_DEFAULT_CHANNEL`) in `.env`.
3. Point `slack_channel` in `examples/inventory/services.yaml` at a channel that exists.
4. Run `make demo-up`.

**Gitea / Forgejo / GitHub**: add a **Pull Request** webhook pointing at `http://<host reachable from Gitea>:18080/webhooks/gitea`, with the secret `PATCHLINE_GITEA_WEBHOOK_SECRET` from `.env`. The repository must be listed in the inventory (`repo: owner/name`). When Renovate opens a fix PR, the finding moves to *in progress* and the thread shows whether the new version leaves the affected range.

## 6. (Optional) Add Dependency-Track

```sh
make demo-up PROFILE=dependency-track     # give Docker at least 8 GB of memory
make demo-seed-dt
```

`demo-seed-dt` waits for Dependency-Track (the first start takes a few minutes), then wires it to Patchline:
- sets its admin password to `patchline-demo` (or `DT_ADMIN_PASSWORD`, if you changed it yourself)
- saves Patchline's API key and the Dependency-Track URL in `.env`
- adds the alert that sends findings to Patchline
- turns on its Trivy analyzer
- restarts Patchline and uploads `storefront-api` to Dependency-Track as well

Findings both report merge into one, listing both under *Reported by*. A finding resolves only when neither reports it. Decisions on such findings are written to Dependency-Track. The Dependency-Track UI is at http://localhost:18082 (`admin` / `patchline-demo`).

To do these steps by hand, follow [Dependency-Track](../../docs/integrations/dependency-track.md) and [Trivy](../../docs/integrations/trivy.md).

## Stop

```sh
make demo-down                       # keeps the data
docker compose -f deploy/compose/docker-compose.yml --profile dependency-track down -v   # removes it
```
