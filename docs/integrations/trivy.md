# Trivy

English | [한국어](trivy.ko.md)

Trivy can be used in two places, and both feed Patchline through Dependency-Track. Patchline itself needs no Trivy settings.

| Use | What it does | Guide |
|---|---|---|
| SBOM generator in CI | `trivy fs` / `trivy image` writes the CycloneDX BOM uploaded to Dependency-Track | [SBOM in CI](sbom-ci.md) |
| Analyzer in Dependency-Track | Dependency-Track sends each BOM's components to a Trivy server and adds Trivy's findings to its own | this page |

As an analyzer, Trivy adds its vulnerability database (including distribution advisories for OS packages) to NVD, GHSA and OSV. Its findings arrive in Patchline like any other: the same notifications, the same resolution by rescan.

## 1. Run the Trivy server

With the [self-hosted compose setup](../../deploy/self-hosted/README.md), set `TRIVY_TOKEN` in `.env` and add the `trivy` profile:

```sh
docker compose --profile dependency-track --profile trivy up -d     # or: make up PROFILE="dependency-track trivy"
```

The server downloads its database on first start (`Listening 0.0.0.0:8080...` in `docker compose logs trivy`) and keeps it in the `trivy-cache` volume. It has no host port; Dependency-Track reaches it as `http://trivy:8080`.

Elsewhere, run the same image as a server:

```sh
docker run -d --name trivy -p 8083:8080 -v trivy-cache:/root/.cache/trivy \
  -e TRIVY_LISTEN=0.0.0.0:8080 -e TRIVY_TOKEN=<token> aquasec/trivy:<version> server
```

Pin the version (`TRIVY_VERSION`) to one you have reviewed. The REST API Dependency-Track uses is not publicly documented, so check the analysis after upgrading Trivy.

## 2. Enable the analyzer in Dependency-Track

**Administration → Analyzers → Trivy**

| Field | Value |
|---|---|
| Enable | on |
| Base URL | `http://trivy:8080` (same compose network) or the server's address |
| API Token | `TRIVY_TOKEN` |
| Ignore Unfixed | Optional: skip vulnerabilities without a fix |

Or set it through the API with a temporary key that has `SYSTEM_CONFIGURATION`:

```sh
cd deploy/self-hosted
DT_URL=http://localhost:8081 DT_ADMIN_KEY=odt_... TRIVY_TOKEN=<token> ./scripts/enable-trivy.sh
```

Delete that key afterwards. Patchline's own key stays read-only (`VIEW_VULNERABILITY`, `VIEW_PORTFOLIO`).

## Air-gapped servers

Mirror the Trivy databases into an internal OCI registry and set `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY` (for example `registry.internal/aquasec/trivy-db:2`, `registry.internal/aquasec/trivy-java-db:1`).

## Check

1. Upload a BOM (see [SBOM in CI](sbom-ci.md)).
2. `docker compose logs dtrack-apiserver | grep Trivy` shows `Trivy vulnerability analysis complete` for the project.
3. New findings reach Patchline as usual; in Dependency-Track their analyzer reads Trivy.

| Symptom | Cause |
|---|---|
| No `TrivyAnalysisTask` lines | Analyzer not enabled, or the BOM was uploaded before enabling it (upload again) |
| Authentication errors in the Dependency-Track log | API Token differs from `TRIVY_TOKEN` |
| Connection refused | Base URL is wrong, or Trivy is still downloading its database |
