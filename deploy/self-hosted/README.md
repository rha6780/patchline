# Self-hosted (Docker Compose)

English | [한국어](README.ko.md)

Runs Patchline on a single server or your own machine. Patchline runs on its own and connects to the Dependency-Track you already have; with the `dependency-track` profile it also starts Dependency-Track (API server, frontend, PostgreSQL).

For a quick tour with sample data, use the [compose demo](../compose/README.md) instead.

| File | |
|---|---|
| `docker-compose.yml` | Patchline, plus Dependency-Track (`dependency-track` profile) and a Trivy server (`trivy` profile) |
| `.env.example` | Settings; copy to `.env` |
| `scripts/enable-trivy.sh` | Turns on the Trivy analyzer in Dependency-Track through its API |
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
| `PATCHLINE_DT_URL`, `PATCHLINE_DT_API_KEY` | Your Dependency-Track API server and a key with `VIEW_VULNERABILITY`, `VIEW_PORTFOLIO` |
| `PATCHLINE_DT_UI_URL` | Dependency-Track UI, for links |
| `PATCHLINE_POLICY_PATH` | `/etc/patchline/policy.yaml` if you copied the policy |
| `PATCHLINE_SLACK_BOT_TOKEN`, `PATCHLINE_SLACK_DEFAULT_CHANNEL` | Optional; without them messages go to the log |

Every variable is described in [docs/configuration.md](../../docs/configuration.md). Keep `config/` in its own Git repository if you want inventory changes reviewed; point `PATCHLINE_CONFIG_DIR` at its checkout.

## 2. Start

With an existing Dependency-Track:

```sh
docker compose up -d --build
docker compose ps           # patchline should be "healthy"
curl -s http://127.0.0.1:8080/readyz
```

Open `http://localhost:8080`, sign in as `admin` / `admin` and choose a new password. If you lose it, `docker compose run --rm patchline reset-admin-password` sets it back.

With Dependency-Track as well, set `DT_DB_PASSWORD` in `.env`, set `PATCHLINE_DT_URL=http://dtrack-apiserver:8080`, then:

```sh
docker compose --profile dependency-track up -d --build
```

| | URL |
|---|---|
| Patchline | http://localhost:8080 (first sign-in `admin` / `admin`; change it) |
| Dependency-Track UI | http://localhost:8082 (first login `admin` / `admin`; change it) |
| Dependency-Track API | http://localhost:8081 |

To add the Trivy analyzer, set `TRIVY_TOKEN` and add `--profile trivy`; see [Trivy](../../docs/integrations/trivy.md) for turning it on in Dependency-Track (`scripts/enable-trivy.sh`).

The Dependency-Track API server needs several GB of memory (give Docker at least 8 GB), and the first start takes a few minutes while it downloads vulnerability data. Create Patchline's API key afterwards, put it in `.env`, and run `docker compose up -d` again.

## 3. Connect the tools

Follow the [integration guides](../../docs/README.md). The webhook URLs depend on where the sender runs:

| Sender | Patchline URL |
|---|---|
| Dependency-Track from this compose file | `http://patchline:8080/webhooks/dependency-track?token=...` |
| Dependency-Track, Gitea, Forgejo or GitHub elsewhere | `https://<your proxy>/webhooks/...`, or `http://<server>:8080/...` with `PATCHLINE_BIND=0.0.0.0` |

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

Mirror the CISA KEV feed internally and set `PATCHLINE_KEV_URL`, or set it to `off` (see [CISA KEV and EPSS](../../docs/integrations/kev-epss.md)).

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
