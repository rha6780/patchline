# Design: integrations behind ports

English | [한국어](source-ports.ko.md)

Status: phase 1 implemented.

## Goal

Every vulnerability integration plugs in through the same small interfaces, so the core (intake, findings, approvals, notifications, API) does not know which tools are connected. Dependency-Track becomes one adapter among others. Adding OpenCVE, Grype or a commercial scanner then means writing one package under `internal/source/`, not changing intake, the store and the UI.

Non-goals:

- No change in behavior, in webhook URLs or in the `/api/v1` JSON (the `dt_*` fields stay, filled from the new tables).
- No separate Go modules and no runtime plugins: adapters are compiled in and registered in `main`.
- Gitea / GitHub pull request webhooks are not a vulnerability source. They keep their own handler and only use the new advisory port.

## Where Dependency-Track leaks today

| Place | What depends on Dependency-Track |
|---|---|
| `server/server.go` | Parses Dependency-Track notifications to validate webhooks |
| `intake/intake.go` | Notification groups, `Project`/`Sighting`/`BOMInfo` types, the delayed reconciliation, `FindingsFetcher` |
| `intake/pullrequest.go` | Fix PR verdicts read affected ranges **only** from Dependency-Track. Findings from OSV get *unknown*, although the ranges are in the local OSV mirror |
| `store/findings.go` | `DTKey`, `ApplyState(DTKey)`, `ResolveMissing(dtProjectUUID)`, five `dt_*` columns on `findings` |
| `finding.Observation` | `DTProjectUUID`, `DTComponentUUID`, `DTVulnerabilityUUID`, `DTVulnSource`, `DTVulnID` |
| `app/app.go` | `InDT`, `AnalysisWriter` with `dependencytrack.AnalysisUpdate` |
| `web`, `notify`, `api` | Links built from `DTUIURL` + `DTProjectUUID`; "decision recorded in Dependency-Track" text |

## Design

```
                 internal/source (ports)                    core
 ┌─────────────────────────────────────────────┐
 │ Receiver      webhook → inbox item          │──▶ server  /webhooks/{name}
 │ Reporter      inbox item → Outcome          │──▶ intake  (upsert, resolve, apply state, schedule)
 │ Detector      components → matches          │──▶ intake  (SBOM uploads; today detect.Engine)
 │ Advisories    vuln id + package → ranges    │──▶ intake  (fix PR verdicts)
 │ DecisionWriter approved decision → tool     │──▶ app     (approvals)
 │ Linker        ref → URL in the tool's UI    │──▶ web, notify, api
 └─────────────────────────────────────────────┘
   adapters: dependencytrack (Receiver, Reporter, Advisories, DecisionWriter, Linker)
             osv (Detector, Advisories) · trivy (Detector) · patchline SBOM (Reporter)
```

An adapter implements the ports it can; `main` registers it in a `source.Registry`, and the core asks the registry ("who receives `/webhooks/dependency-track`", "who can write a decision for this finding").

### Identity: source refs

A finding's identifiers in each tool move from `findings.dt_*` to a new table:

```sql
CREATE TABLE finding_refs (
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    source      TEXT    NOT NULL,   -- dependencytrack, patchline, ...
    project     TEXT    NOT NULL,   -- the tool's project id
    component   TEXT    NOT NULL DEFAULT '',
    vuln        TEXT    NOT NULL DEFAULT '',   -- the tool's vulnerability id or uuid
    vuln_source TEXT    NOT NULL DEFAULT '',   -- NVD, GITHUB, OSV, ...
    vuln_name   TEXT    NOT NULL DEFAULT '',   -- e.g. CVE-2021-44228 as the tool names it
    PRIMARY KEY (finding_id, source, project)
);
CREATE INDEX finding_refs_by_key ON finding_refs (source, project, component, vuln);
```

`finding_sightings` says whether a project **currently** reports a finding. `finding_refs` says how a tool **names** it, and is kept after the finding is resolved, so links and decisions still work. The migration copies the `dt_*` columns into `finding_refs`. The columns are still written during phases 1–3 (so a downgrade works) and dropped in phase 4.

`finding.Observation` gets one `Ref` field instead of the five `DT*` fields:

```go
type Ref struct {
    Source, Project, Component, Vuln, VulnSource, VulnName string
}
```

### Ports

```go
package source

// Receiver accepts a tool's webhook and turns it into an inbox item.
type Receiver interface {
    Name() string                         // path segment: /webhooks/{name}
    Accept(r *http.Request, body []byte, secrets Secrets) (eventType, dedupKey string, err error)
}

// Reporter turns an inbox item of its source into an Outcome.
type Reporter interface {
    Name() string
    Handle(ctx context.Context, item store.InboxItem) (Outcome, error)
}

// Outcome is what intake applies, in one transaction per item.
type Outcome struct {
    Projects     []Project            // touched source projects (with commit, ref, BOM serial)
    Observations []finding.Observation
    Snapshot     *Snapshot            // complete set for a project: resolve the rest
    StateChanges []StateChange        // by Ref (an analysis changed in the tool)
    Later        []Followup           // inbox items to schedule, e.g. a reconciliation in 2m
    Note         string               // shown on the inbox item
}

// Advisories returns the affected ranges of a vulnerability for a package.
type Advisories interface {
    Affected(ctx context.Context, f store.Finding) (ranges []version.Range, fixed string, err error)
}

// DecisionWriter records an approved decision in the tool that reports it.
type DecisionWriter interface {
    Name() string
    Write(ctx context.Context, ref finding.Ref, d Decision) error
}

// Linker links a ref to the tool's UI.
type Linker interface {
    Link(ref finding.Ref) (label, url string)
}
```

What moves where:

- **intake** keeps the inbox loop, retries and applying an `Outcome`. The Dependency-Track groups, the delayed reconciliation and the type mapping move into `source/dependencytrack`. The Patchline SBOM path becomes the `patchline` reporter, using the `Detector`s.
- **server** serves `POST /webhooks/{name}` for every registered `Receiver`, so `/webhooks/dependency-track` keeps its URL. Gitea stays a separate route.
- **Fix PR verdicts** ask every `Advisories` in order: the OSV mirror first (local, no network), then Dependency-Track. This is the one visible change: PRs on OSV and Trivy findings get *fixes* / *insufficient* instead of *unknown*.
- **app**: approving a decision asks the registry for a `DecisionWriter` matching one of the finding's refs. With one, it writes there first, as today. Without one, the decision stays in Patchline. "Can this be decided here" becomes "every ref of a source that has a writer is writable", which replaces `InDT` and the `no_dt` case.
- **web / notify / api** show one link per ref that a `Linker` resolves. The API keeps `dt_project_uuid`, `dt_vuln_source`, `dt_vuln_id`, filled from the Dependency-Track ref, and adds a `refs` array.
- **store** loses `DTKey`, `ApplyState(DTKey)` and `ResolveMissing(dtProjectUUID)`. In their place: `ApplyStateByRef(Ref, …)` and the existing `ResolveMissingIn(source, project, …)`.

## Phases

Each phase is one commit or more, keeps every existing test passing, and can ship alone.

| Phase | Change | Done when |
|---|---|---|
| 1. Refs in the store | Migration `00014_finding_refs` with backfill; `Observation.Ref`; `UpsertFinding` writes refs (and still the `dt_*` columns); `ApplyStateByRef`. Callers unchanged otherwise | Store tests for backfill, merge of two sources, refs kept after resolution |
| 2. Ports and the Dependency-Track adapter | `internal/source` ports and registry; Dependency-Track `Receiver` + `Reporter`; `patchline` reporter; intake applies `Outcome`; generic webhook route | `intake` and `server` no longer import `source/dependencytrack`; webhook and reconciliation tests pass unchanged |
| 3. Advisories, decisions, links | `Advisories` (OSV, Dependency-Track) for PR verdicts; `DecisionWriter`; `Linker`; `app`, `web`, `notify`, `api` use refs | Outside `source/` and `main`, nothing imports `source/dependencytrack`; an OSV finding's fix PR gets a verdict |
| 4. Cleanup | Stop writing, then drop, the `findings.dt_*` columns (after one release); remove `DTUIURL` plumbing in favor of the linker | `grep -r DTProjectUUID internal` only finds the adapter |

## Risks

| Risk | Handling |
|---|---|
| Backfill misses or duplicates refs | Backfill is a plain `INSERT … SELECT` from `dt_*`; a test migrates a database with resolved, merged and Patchline-only findings and compares |
| A finding reported by two Dependency-Track projects | Today each upsert overwrites the `dt_*` ids, so an analysis change in the other project matches nothing and is dropped (an existing bug that phase 1 fixes). With one ref per project, a decision is written to every Dependency-Track ref of the finding; it is approved only when all writes succeed |
| Downgrade after phase 1 | The `dt_*` columns are still written until phase 4, so the previous binary keeps working; goose `down` drops the table |
| Generic webhook route changes authentication | `Receiver.Accept` gets the same secrets as today; the webhook tests run against both the old and the new route before the old handler is deleted |
| More indirection | Ports are only added where a second implementation exists or is planned: Advisories (OSV, Dependency-Track), Reporter (Dependency-Track, Patchline). Linker and DecisionWriter start with one implementation each but remove the most `if inDT` branches |

## Open questions

1. When should the `dt_*` columns be dropped: in the release after phase 3, or kept until a 1.0?
2. Should the API mark `dt_*` as deprecated in favor of `refs` now, or keep both in `v1` for good?
3. Which tool should be the first new adapter? It tests the ports. OpenCVE (CVE feed, no components) only fits `Advisories`; Grype or a SaaS scanner would also exercise `Reporter`.
