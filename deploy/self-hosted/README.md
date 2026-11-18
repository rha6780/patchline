# Self-hosted (Docker Compose)

English | [한국어](README.ko.md)

Runs Patchline on a single server or your own machine, with a Trivy server next to it: SBOMs from CI are matched against Patchline's OSV mirror (language packages) and Trivy (OS packages), and decisions are made in Patchline. Dependency-Track is optional: connect the one you already run, or start one with the `dependency-track` profile (API server, frontend, PostgreSQL).

For a quick tour with sample data, use the [compose demo](../compose/README.md) instead.

| File | |
|---|---|
| `docker-compose.yml` | Patchline and a Trivy server, plus Dependency-Track (`dependency-track` profile) |
| `.env.example` | Settings; copy to `.env` |
| `scripts/enable-trivy.sh` | Turns on the Trivy analyzer in Dependency-Track through its API (only with Dependency-Track) |
| `config/` | Your inventory and policy, mounted read-only at `/etc/patchline` (not committed) |

## 1. Configure

```sh
cd deploy/self-hosted
cp .env.example .env
mkdir -p config
cp -r ../../examples/inventory config/          # then edit config/inventory/*.yaml
cp ../../examples/policy/policy.yaml config/     # optional
```

In `.env`, set at least:

| Variable | |
|---|---|
| `PATCHLINE_WEBHOOK_TOKEN` | Required. `openssl rand -hex 32` |
| `TRIVY_TOKEN` | Required. The Trivy server's token, `openssl rand -hex 32` |
| `PATCHLINE_POLICY_PATH` | `/etc/patchline/policy.yaml` if you copied the policy |
| `PATCHLINE_SLACK_BOT_TOKEN`, `PATCHLINE_SLACK_DEFAULT_CHANNEL` | Optional; without them messages go to the log |
| `PATCHLINE_DT_URL`, `PATCHLINE_DT_API_KEY`, `PATCHLINE_DT_UI_URL` | Only with Dependency-Track: its API server, a key with `VIEW_VULNERABILITY`, `VIEW_PORTFOLIO` (and `VULNERABILITY_ANALYSIS` to write decisions back), and its UI for links |

Every variable is described in [docs/configuration.md](../../docs/configuration.md). Keep `config/` in its own Git repository if you want inventory changes reviewed; point `PATCHLINE_CONFIG_DIR` at its checkout. How to name projects and versions: [Registering projects and branches](../../docs/projects.md).

## 2. Start

```sh
docker compose up -d --build
docker compose ps           # patchline should be "healthy"
curl -s http://127.0.0.1:8080/readyz
```

Open `http://localhost:8080` and sign in as `admin` with the one-time password from the log (`docker compose logs patchline | grep one-time`), then choose a new password. If you lose it, `docker compose run --rm patchline reset-admin-password` prints a new one-time password.

On first start Patchline downloads the OSV data (npm alone is about 220 MB) and Trivy its database; uploads before that are matched but resolve nothing. To run without Trivy, set `PATCHLINE_TRIVY_URL=` (empty) in `.env` and start only Patchline (`docker compose up -d patchline`).

### With Dependency-Track

To connect an existing one, set the `PATCHLINE_DT_*` variables and run `docker compose up -d` again. To start one as well, set `DT_DB_PASSWORD` in `.env`, set `PATCHLINE_DT_URL=http://dtrack-apiserver:8080`, then:

```sh
docker compose --profile dependency-track up -d --build
```

| | URL |
|---|---|
| Patchline | http://localhost:8080 (first sign-in `admin` with the one-time password from the log) |
| Dependency-Track UI | http://localhost:8082 (first login `admin` / `admin`; change it) |
| Dependency-Track API | http://localhost:8081 |

The Dependency-Track API server needs several GB of memory (give Docker at least 8 GB), and the first start takes a few minutes while it downloads vulnerability data. Create Patchline's API key afterwards, put it in `.env`, and run `docker compose up -d` again. Dependency-Track can use the same Trivy server as an analyzer; see [Trivy](../../docs/integrations/trivy.md#optional-analyzer-in-dependency-track) (`scripts/enable-trivy.sh`).

## 3. Connect the tools

Follow the [integration guides](../../docs/README.md), starting with [SBOM in CI](../../docs/integrations/sbom-ci.md). The URLs depend on where the sender runs:

| Sender | Patchline URL |
|---|---|
| CI uploading SBOMs, Gitea, Forgejo or GitHub | `https://<your proxy>/ingest/sbom`, `https://<your proxy>/webhooks/gitea`, or `http://<server>:8080/...` with `PATCHLINE_BIND=0.0.0.0` |
| Dependency-Track from this compose file | `http://patchline:8080/webhooks/dependency-track?token=...` |
| Dependency-Track elsewhere | `https://<your proxy>/webhooks/dependency-track?token=...` |

## Exposing Patchline

Ports are bound to `127.0.0.1` by default. Before setting `PATCHLINE_BIND=0.0.0.0`, either turn on [OIDC sign-in](../../docs/access-control.md), or put Patchline behind a reverse proxy that authenticates users (for example oauth2-proxy). In both cases, terminate TLS in front of it. The webhook paths (`/webhooks/*`) authenticate themselves.

For sign-in, put the access policy in `config/access-policy.yaml` (start from [the example](../../examples/access/access-policy.yaml)) and set the `PATCHLINE_OIDC_*` variables in `.env`.

## Air-gapped servers

Build the image where you have internet access and copy it over:

```sh
make docker                                   # tags patchline:<version>
docker save patchline:<version> | gzip > patchline.tar.gz
# on the server
docker load < patchline.tar.gz
# .env: PATCHLINE_IMAGE=patchline:<version>
docker compose up -d                          # without --build
```

Mirror the OSV exports and set `PATCHLINE_OSV_URL` ([Detection](../../docs/integrations/native-detection.md)), mirror the Trivy databases and set `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY` ([Trivy](../../docs/integrations/trivy.md#air-gapped-servers)), and mirror the CISA KEV feed and set `PATCHLINE_KEV_URL`, or set it to `off` (see [CISA KEV and EPSS](../../docs/integrations/kev-epss.md)).

## Operations

| Task | Command |
|---|---|
| Logs | `docker compose logs -f patchline` |
| Reload the inventory or policy | `docker compose restart patchline` |
| Upgrade | `git pull && docker compose up -d --build` (migrations run on start) |
| Stop | `docker compose down` (data is kept in volumes) |
| Remove everything, including data | `docker compose down -v` |

Back up the SQLite database by copying the `patchline-data` volume while Patchline is stopped:

```sh
docker compose stop patchline
docker run --rm -v patchline_patchline-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/patchline-data.tgz -C /data .
docker compose start patchline
```

The container runs as a non-root user with a read-only root filesystem and no capabilities; only `/data` is writable.
