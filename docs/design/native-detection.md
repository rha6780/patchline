# Design: native detection alongside Dependency-Track

English | [한국어](native-detection.ko.md)

Status: phase 1 implemented, phases 2–4 planned.

## Goal

Patchline keeps its Dependency-Track integration and can also detect vulnerabilities itself: CI uploads SBOMs to Patchline, Patchline matches them against a vulnerability database and re-analyzes them when the database changes. Either path, or both, feeds the same findings, due dates, pull request links, notifications and approvals.

| Dependency-Track feature | In Patchline |
|---|---|
| SBOM upload and storage per project version | Phase 1 |
| Matching against vulnerability data | Phase 1 (OSV), phase 4 (Trivy as an optional engine) |
| Re-analysis when the data changes | Phase 1 |
| Component search and impact analysis | Phase 2 |
| Analysis decisions and VEX | Phase 3 |
| License and policy violations | Out of scope for now |

## Architecture

```
                  ┌──────────────────────── sources ────────────────────────┐
Dependency-Track ─┤ dependencytrack: webhooks + API (unchanged)              │
                  │                                                          ├─▶ observations ─▶ findings ─▶ SLA, PRs, Slack, approvals
CI ── SBOM ───────┤ patchline: SBOM inbox → components → matcher ◀── OSV DB  │       (one finding per service × environment
                  └──────────────────────────────────────────────────────────┘        × component × vulnerability, with sightings)
```

### Sources and sightings

A **source** reports **sightings**: "project P of source S contains component C with vulnerability V". Today the only source is `dependencytrack`; phase 1 adds `patchline`.

- A finding is still one service × environment × component (purl) × vulnerability (canonical id, CVE preferred). When Dependency-Track and Patchline see the same thing, they update the **same finding**: one message, one due date.
- `finding_sightings` records which source projects currently report a finding. A reconciliation of one source project (a new BOM, or a re-analysis) replaces that project's sightings.
- A finding is **resolved when no source reports it any more**: it was missing from the latest BOM of every project that reported it. It is **reopened** when any source reports it again.
- Descriptive fields (severity, title) come from the finding's primary source. Dependency-Track wins when it reports the finding, so severities do not flip between sources. The Dependency-Track ids stay as they are for links and analysis write-back.

### SBOM intake (source `patchline`)

- `POST /ingest/sbom?project=<name>&version=<version>` takes a CycloneDX (JSON) or SPDX (JSON) document. It authenticates with the webhook token, and the request may also be multipart with a `bom` field, like Dependency-Track's upload.
- The handler only stores the upload in the inbox (same retries and de-duplication as webhooks). The processor then works through it:
  1. parses the SBOM: components with purls, the serial, and the `patchline:git:commit` / `patchline:git:ref` properties
  2. replaces the project version's component snapshot
  3. matches the components, upserts sightings, and resolves the findings missing from this snapshot
- Project names map to services through the inventory exactly like Dependency-Track project names, and the version is the environment.

### Matching (OSV)

- Data: per-ecosystem OSV exports from `osv-vulnerabilities.storage.googleapis.com`. The first sync downloads `<ecosystem>/all.zip`. Later syncs read `<ecosystem>/modified_id.csv` and fetch only records changed since the last sync, so npm's ~220 MB export is downloaded once.
- Ecosystems are configurable (default Maven, npm, PyPI, Go). An internal mirror of the same layout works for air-gapped servers.
- A component matches when its purl maps to an OSV package (Maven `group:artifact`, npm `@scope/name`, PyPI normalized names, Go module paths, …) and its version is in an affected range (`introduced` / `fixed` / `last_affected` events) or in the explicit `versions` list.
- Severity: `database_specific.severity` (GitHub advisories) when present, otherwise the CVSS v3 base score from the vector. Without either, the severity is *unassigned*. Aliases (CVE, GHSA) make the canonical id match Dependency-Track's.
- After each sync, every stored snapshot is re-analyzed. New matches create findings and notifications; withdrawn advisories resolve theirs.

### Phase 2: component search and impact analysis

The component snapshots are already stored in phase 1. Phase 2 adds a page and API: which services and environments contain a package (optionally a version range), and for a CVE, which snapshots are affected, including those whose findings are closed.

### Phase 3: analysis decisions and VEX

- For findings only Patchline reports, the decision (not affected with a justification, false positive, risk accepted) lives in Patchline. Risk acceptance reuses today's request/approve flow; "not affected" gets the same flow.
- For findings Dependency-Track also reports, decisions keep going to Dependency-Track as today.
- `GET /api/v1/projects/{name}/{version}/vex` exports CycloneDX VEX for the snapshot.

### Phase 4: Trivy as an optional engine

The engine is an interface: OSV is built in; a Trivy server can be added for OS packages and images. Trivy's server API is undocumented, so it stays optional.

## Risks

| Risk | Mitigation |
|---|---|
| Version comparison differs from the ecosystem's rules | Reuse `internal/version` (Maven, SemVer, PyPI, Go shapes). Explicit `versions` lists take precedence. Every match records the range it matched. On the sample SBOMs the counts equal the OSV API's in all six cases |
| Duplicate findings when ids differ (GHSA vs CVE) | Canonical id from aliases, the same rule Dependency-Track findings use |
| Large downloads | Full export once, then incremental; configurable ecosystems. npm's 230k records take about 13 s including the download |
| Two sources disagree | Sightings per source; a finding resolves only when every source stops reporting it |
