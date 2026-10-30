# Built-in detection (SBOM upload)

English | [한국어](native-detection.ko.md)

Patchline can find vulnerabilities itself: CI uploads an SBOM to Patchline, which matches its components against a local mirror of [OSV](https://osv.dev) data. Patchline also re-analyzes the stored SBOMs when that data changes. This works with or without Dependency-Track. When both report the same vulnerability, it is **one finding** listing both sources (see [How it works](../design/native-detection.md)).

| | Dependency-Track | Built-in detection |
|---|---|---|
| SBOM goes to | Dependency-Track | Patchline (`/ingest/sbom`) |
| Matching | Dependency-Track's analyzers (NVD, OSS Index, OSV, GitHub, Trivy) | OSV: Maven, npm, PyPI, Go, crates.io, NuGet, RubyGems, Packagist |
| OS packages (deb, rpm, apk) | With the Trivy analyzer | Not yet (planned via Trivy) |
| Analysis decisions | In Dependency-Track | Planned (phase 3) |

## 1. Turn it on

It is on by default for Maven, npm, PyPI and Go:

```sh
PATCHLINE_OSV_ECOSYSTEMS=Maven,npm,PyPI,Go    # or off
PATCHLINE_OSV_REFRESH=6h                       # how often to fetch changes
# PATCHLINE_OSV_URL=https://osv-mirror.internal  # internal mirror (same layout)
```

On first start Patchline downloads each ecosystem's full export once: Maven about 10 MB, npm about 220 MB, PyPI about 40 MB, Go about 13 MB. After that it fetches only the records that changed (`modified_id.csv`). The data lives in the SQLite database, which grows by roughly 80 MB with npm. The startup log shows `osv synced ecosystem=… records=…`.

Until every configured ecosystem has synced once, uploads are analyzed but nothing is resolved, so a half-loaded database never looks like a fix.

## 2. Upload SBOMs from CI

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.patchline.json
```

The Dependency-Track style also works:

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom" -H "Authorization: Bearer $PATCHLINE_WEBHOOK_TOKEN" \
  -F project=storefront-api -F version=main -F bom=@bom.patchline.json
```

| | |
|---|---|
| Formats | CycloneDX JSON, SPDX JSON (XML is not supported yet) |
| Components | Identified by `purl`; components without one are counted (`without_purl`) and skipped |
| `project` | Looked up in the inventory like a Dependency-Track project name (`dependency_track_projects`, default: last segment of `repo`) |
| `version` | The environment, e.g. `main`, `prod` |
| Commit | `patchline:git:commit` / `patchline:git:ref` in the BOM metadata, as in [SBOM in CI](sbom-ci.md). SPDX: an annotation `patchline:git:commit=<sha>` |
| Token | `PATCHLINE_WEBHOOK_TOKEN`, or the value set under **Settings → Webhooks** |

The answer is `202` with `{"format": "CycloneDX", "components": 3, "without_purl": 0}`; matching happens right after.

### Gitea / GitHub Actions

```yaml
      - name: Upload to Patchline
        env:
          PATCHLINE_URL: ${{ vars.PATCHLINE_URL }}
          PATCHLINE_TOKEN: ${{ secrets.PATCHLINE_WEBHOOK_TOKEN }}
        run: |
          curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
            -H "Authorization: Bearer $PATCHLINE_TOKEN" -H "Content-Type: application/json" \
            --data-binary @bom.patchline.json
```

You can upload the same SBOM to Dependency-Track and to Patchline; the findings merge.

## How findings behave

- Each upload replaces the project version's snapshot. Vulnerabilities no longer in it resolve, with the commit as evidence, unless another source (Dependency-Track) still reports them. Vulnerabilities that come back reopen.
- After each OSV update, every stored snapshot is analyzed again. A new advisory creates findings and notifications without a new build; a withdrawn advisory resolves its findings.
- Severity is the advisory's (GitHub's rating, otherwise the CVSS v3 base score). When Dependency-Track also reports the finding, its severity is used.
- Due dates, KEV and EPSS escalation, Renovate PR links, Slack messages and approvals work as for Dependency-Track findings. EPSS comes from Dependency-Track only. Risk acceptance needs a Dependency-Track finding for now.

## Check

1. `osv synced` lines in the log for each ecosystem.
2. Upload an SBOM: the log shows `sbom analyzed … result="N findings (N new), 0 resolved"`.
3. **Integrations** lists the project with source *Patchline (OSV)* and its commit. A finding shows *Reported by: Patchline (OSV)*.

| Symptom | Cause |
|---|---|
| `401` | Token differs from `PATCHLINE_WEBHOOK_TOKEN` (or the one under **Settings → Webhooks**) |
| `400 … XML is not supported` | Generate JSON (`trivy … --format cyclonedx`, `cyclonedxBom` with JSON output) |
| `components: 0` or many `without_purl` | The generator does not write purls; use Trivy or the CycloneDX plugins |
| `… still syncing, nothing resolved` | The first download has not finished; wait for `osv synced` |
| `osv sync failed` | No internet: mirror the exports internally and set `PATCHLINE_OSV_URL` |
