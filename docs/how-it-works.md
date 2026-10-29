# How Patchline works

English | [한국어](how-it-works.ko.md)

```
Service repos (Gitea) ── CI: SBOM (main) ──┐
Deploy pipeline       ── image SBOM (prod) ┼──▶ Dependency-Track ── webhook ──┐
                                           │                                  ▼
Renovate ── fix PRs ── Gitea / Forgejo / GitHub webhook ─────────────▶  Patchline  ◀── inventory (Git, YAML)
                                                                              │        ◀── CISA KEV
                                                                    ┌─────────┴─────────┐
                                                               Slack (bot)            Web UI
```

| Tool | Role |
|---|---|
| **Dependency-Track** | Matches SBOM components (purl / CPE) against NVD, GHSA and OSV; stores analysis decisions |
| **Renovate** | Opens fix PRs (dependency bumps, base-image digest updates) |
| **Patchline** | Joins findings with the inventory, computes SLA, notifies, tracks state with evidence |

## Finding states

| State | Trigger |
|---|---|
| `new` | New finding from Dependency-Track |
| `in_progress` | Analysis in triage / exploitable, or a fix PR is linked |
| `awaiting_verification` | Fix PR merged, or analysis marked resolved |
| `resolved` | No longer reported for the project's latest BOM |
| `not_affected` | Analysis `NOT_AFFECTED` / `FALSE_POSITIVE` |
| `risk_accepted` | Finding suppressed in Dependency-Track, or a risk acceptance approved in Patchline (which suppresses it there) |
| `reopened` | A resolved finding is reported again |

Human decisions end up in **one place**, the Dependency-Track analysis. Either people triage there, or an approved risk acceptance in Patchline writes the analysis there ([Sign-in and permissions](access-control.md)).

## Intake

1. The webhook handler validates the payload, stores it in an inbox table and returns `202`. Deliveries are de-duplicated by the platform's delivery id when there is one, otherwise by content hash.
2. A background processor handles inbox entries, retrying failures with backoff (30s → 30m, 5 attempts).
3. `NEW_VULNERABILITY` and `NEW_VULNERABLE_DEPENDENCY` carry the findings directly; `BOM_PROCESSED` schedules a reconciliation of the project (see below).
4. Each Dependency-Track project **name** is resolved to a service through the inventory, and its **version** becomes the environment (`main`, `prod`; empty becomes `default`). Projects not in the inventory are kept as *unregistered*.
5. A finding is one service × environment × component × vulnerability. CVE ids are preferred over GHSA/OSV ids as the canonical id; the others are kept as aliases.
6. `PROJECT_AUDIT_CHANGE` (an analysis decision in Dependency-Track) moves the finding's state: `IN_TRIAGE`/`EXPLOITABLE` → in progress, `NOT_AFFECTED`/`FALSE_POSITIVE` → not affected, suppressed → risk accepted, `RESOLVED` → awaiting verification (a rescan confirms it later).

## Resolution

A finding is resolved by evidence, not by someone closing it.

1. On `BOM_PROCESSED`, Patchline records the BOM's commit and ref and schedules a reconciliation after `PATCHLINE_DT_RECONCILE_DELAY`. (Dependency-Track 4.x sends `BOM_PROCESSED` before it has finished analyzing new components, so reading findings right away would be incomplete.)
2. The reconciliation reads the project's current findings from the Dependency-Track API. Findings of that project that are no longer reported become **resolved**, with the commit, ref and BOM serial as evidence.
3. A resolved finding that is reported again (by a later BOM or a `NEW_VULNERABILITY` notification) becomes **reopened**.
4. Each Dependency-Track project version is reconciled separately, so `main` and `prod` resolve independently.
5. Findings closed by a decision (not affected, risk accepted) are left as they are.

The commit comes from the `patchline:git:commit` and `patchline:git:ref` properties in the BOM's metadata; see [SBOM in CI](integrations/sbom-ci.md#attach-the-commit).

## Pull request linking

1. Gitea, Forgejo or GitHub sends **Pull Request** events to `/webhooks/gitea` (see [Git webhooks](integrations/git-webhooks.md)).
2. When a pull request opens or changes, Patchline reads the updates from Renovate's change table (or the title, `Update dependency X to vY`).
3. Each update is matched to open findings of that repository by package name (Maven `group:artifact` = `group/artifact`), in the environment named after the base branch and in `default`.
4. The target version is compared with the vulnerability's affected ranges from Dependency-Track: **leaves the affected range**, **still affected**, or **not verified** when no range is known.
5. A linked pull request moves the finding to *in progress*; merging it moves it to *awaiting verification*. Closing without merging is recorded but keeps the state. Only the next rescan resolves the finding.

Base-image updates are not matched to OS-package findings; those resolve through the rescan.

## Due dates

The policy ([example](../examples/policy/policy.yaml)) turns risk signals into an **effective severity** and a due date:

1. Start from the scanner's severity.
2. Raise one level when the EPSS score (from Dependency-Track) is at or above `epss_threshold`.
3. Add the service's exposure adjustment (default: `internet` +1).
4. A CVE in the CISA KEV catalog is raised to at least `kev` (default critical).
5. The due date is the SLA for that severity (default critical 7d, high 30d, medium 90d, low 180d), counted from first detection or from reopening.
6. An approved due date extension replaces it while the effective severity stays at or below the level it was approved at; an escalation or a reopening drops the extension.

The SLA job re-evaluates open findings every 5 minutes and right after intake, so a CVE added to KEV escalates findings that are already open (the thread says why and moves the due date). It records one reminder before the due date and repeats while overdue. New findings are posted after their first evaluation, so the first message already shows the due date, and the notification threshold uses the effective severity.

## Notifications

- Each finding at or above `PATCHLINE_NOTIFY_MIN_SEVERITY` gets **one** message in its service's `slack_channel` (or the default channel).
- When the finding changes (state, severity), the message is edited in place (`chat.update`) and the change is added to its thread.
- Progress is stored per finding, so restarts and Slack outages only delay messages; rate limits (`429`) pause delivery for `Retry-After`.
- Findings closed before they were ever posted (for example marked not affected right away) are not posted.
- Without a Slack token the same messages are printed to stdout.

## Out of scope

Running scanners, version-range matching (delegated to Dependency-Track), SAST for first-party code, configuration audits, multi-tenancy.
