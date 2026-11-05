# Trivy

English | [한국어](trivy.ko.md)

Trivy has up to three roles around Patchline:

| Use | What it does | Guide |
|---|---|---|
| Engine in Patchline | Patchline sends the OS packages (deb, rpm, apk) of each uploaded SBOM to a Trivy server and records its matches as findings | this page |
| SBOM generator in CI | `trivy fs` / `trivy image` writes the CycloneDX SBOM that CI uploads | [SBOM in CI](sbom-ci.md) |
| Analyzer in Dependency-Track (optional) | Dependency-Track sends each BOM's components to the same Trivy server | [below](#optional-analyzer-in-dependency-track) |

Language packages are matched against Patchline's OSV mirror; Trivy adds the distribution advisories for OS packages, which OSV does not cover well. See [Detection](native-detection.md) for how matches become findings.

## 1. Run the Trivy server

The [self-hosted compose setup](../../deploy/self-hosted/README.md) starts one next to Patchline. Set `TRIVY_TOKEN` in `.env` (`openssl rand -hex 32`) and run `docker compose up -d`. The [demo](../../deploy/compose/README.md) runs one too.

The server downloads its database on first start (`Listening 0.0.0.0:8080...` in `docker compose logs trivy`) and keeps it in the `trivy-cache` volume. It has no host port; Patchline reaches it as `http://trivy:8080`.

Elsewhere, run the same image as a server:

```sh
docker run -d --name trivy -p 8083:8080 -v trivy-cache:/root/.cache/trivy \
  -e TRIVY_LISTEN=0.0.0.0:8080 -e TRIVY_TOKEN=<token> aquasec/trivy:<version> server
```

Pin the version (`TRIVY_VERSION`) to one you have reviewed. Patchline and Dependency-Track use Trivy's server API, which is not publicly documented, so check that uploads are still matched after upgrading Trivy.

## 2. Connect Patchline

The compose setup sets these for you. Elsewhere:

```sh
PATCHLINE_TRIVY_URL=http://trivy:8080
PATCHLINE_TRIVY_TOKEN=<the server's TRIVY_TOKEN>
PATCHLINE_TRIVY_SCOPE=os        # all: language packages too, merged with OSV's matches
```

To run without Trivy, set `PATCHLINE_TRIVY_URL=` (empty); then only language packages are matched.

- OS packages need the `distro` qualifier in their purl (`pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u4?distro=debian-11.6`), as `trivy image --format cyclonedx` writes it. Packages without it are skipped.
- Debian and Ubuntu advisories name source packages: Patchline reads Trivy's `aquasecurity:trivy:SrcName` properties (or Syft's `upstream` qualifier), so `libssl1.1` is checked as `openssl`.
- One upload is one scan per OS release. If Trivy cannot be reached, the upload is retried and nothing resolves in the meantime.
- Each CVE is its own finding, even when one distribution advisory (`DLA-3942-1`) fixes several; the advisory is kept as an alias.

## Air-gapped servers

Mirror the Trivy databases into an internal OCI registry and set `TRIVY_DB_REPOSITORY` and `TRIVY_JAVA_DB_REPOSITORY` (for example `registry.internal/aquasec/trivy-db:2`, `registry.internal/aquasec/trivy-java-db:1`).

## Check

1. Upload an image SBOM (`trivy image --format cyclonedx`, see [SBOM in CI](sbom-ci.md#deployed-image-jenkins-example)).
2. The Patchline log shows `sbom analyzed … result="N findings (N new), 0 resolved"`.
3. Its findings show *Detected by Patchline (Trivy, CVE-…)* on their timeline.

| Symptom | Cause |
|---|---|
| The upload appears under **Integrations → Processing failures** and is retried | Trivy is unreachable or still downloading its database, or `PATCHLINE_TRIVY_TOKEN` differs from the server's token |
| `0 findings` for an image with old packages | The purls have no `distro` qualifier: generate the SBOM with `trivy image`, or Syft with the distro set |

## (Optional) Analyzer in Dependency-Track

If you also run [Dependency-Track](dependency-track.md), it can use the same Trivy server, which adds Trivy's database to NVD, GHSA and OSV in its analysis. With the self-hosted setup, start it with `docker compose --profile dependency-track up -d`; Dependency-Track reaches Trivy as `http://trivy:8080`.

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

Delete that key afterwards. Patchline's own key stays as it is (`VIEW_VULNERABILITY`, `VIEW_PORTFOLIO`, and `VULNERABILITY_ANALYSIS` for writing decisions back).

`docker compose logs dtrack-apiserver | grep Trivy` then shows `Trivy vulnerability analysis complete` for each project.

| Symptom | Cause |
|---|---|
| No `TrivyAnalysisTask` lines | Analyzer not enabled, or the BOM was uploaded before enabling it (upload again) |
| Authentication errors in the Dependency-Track log | API Token differs from `TRIVY_TOKEN` |
| Connection refused | Base URL is wrong, or Trivy is still downloading its database |
