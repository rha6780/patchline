# How Patchline works

English | [한국어](how-it-works.ko.md)

```
Service repos   ── CI: SBOM (main) ──────┐
Deploy pipeline ── image SBOM (prod) ────┼──▶  Patchline  ◀── inventory (Git, YAML)
Renovate ── fix PRs ── Git webhook ──────┤      │     │    ◀── CISA KEV
Dependency-Track (optional) ── webhook ──┘      │     └──▶ OSV mirror, Trivy server
                                      ┌─────────┴─────────┐
                                 Slack, webhook         Web UI
```

| Tool | Role |
|---|---|
| **Patchline** | Matches uploaded SBOMs against a local OSV mirror and a Trivy server, joins findings with the inventory, computes due dates, notifies, keeps decisions, tracks state with evidence |
| **Trivy server** | Advisories for OS packages (deb, rpm, apk) in container images |
| **Renovate** | Opens fix PRs (dependency bumps, base-image digest updates) |
| **Dependency-Track** (optional) | A second source: its own analyzers, findings and analysis decisions |

## Finding states

| State | Trigger |
|---|---|
| `new` | First reported: by an SBOM uploaded to Patchline, or by Dependency-Track |
| `in_progress` | A fix PR is linked (or, in Dependency-Track, the analysis is in triage / exploitable) |
| `awaiting_verification` | The fix PR is merged (or the Dependency-Track analysis is resolved) |
| `resolved` | No longer reported by the latest SBOM of any project that reported it |
| `not_affected` | A *not affected* or *false positive* request is approved (or Dependency-Track's analysis says so) |
| `risk_accepted` | A risk acceptance is approved (or the finding is suppressed in Dependency-Track) |
| `reopened` | A resolved finding is reported again |

Decisions are made **in Patchline**: someone requests an exception, someone else approves it ([Sign-in and permissions](access-control.md)). The decision stays with the finding (who, when, why), closes it, and is exported as [VEX](integrations/native-detection.md#decisions-and-vex). When Dependency-Track also reports the finding, the approved decision is written there first, so both tools agree.

## Intake

1. SBOM uploads (`/ingest/sbom`) and webhooks are validated, stored in an inbox table, and answered with `202`. Webhook deliveries are de-duplicated by the platform's delivery id when there is one, otherwise by content hash.
2. A background processor handles inbox entries, retrying failures with backoff (30s → 30m, 5 attempts).
3. An SBOM becomes the **snapshot** of its project version. Its components are matched: language packages against the OSV mirror, OS packages by the Trivy server. Every match is recorded as a finding with the advisory, the affected range and the fixed version as evidence. When the OSV data changes, every stored snapshot is matched again, so a new advisory creates findings without a new build.
4. The project **name** is resolved to a service through the inventory, and the **version** becomes the environment (`main`, `prod`; empty becomes `default`). Projects not in the inventory are kept as *unregistered*. A project moved to another service keeps its findings, with their history and decisions ([Registering projects and branches](projects.md)).
5. A finding is one service × environment × component × vulnerability. CVE ids are preferred over GHSA/OSV ids as the canonical id; the others are kept as aliases. The same vulnerability reported by OSV and Trivy, or by Patchline and Dependency-Track, is one finding.
6. With Dependency-Track: `NEW_VULNERABILITY` and `NEW_VULNERABLE_DEPENDENCY` carry findings; `BOM_PROCESSED` schedules a reconciliation (see below); `PROJECT_AUDIT_CHANGE` (an analysis decision there) moves the state: `IN_TRIAGE`/`EXPLOITABLE` → in progress, `NOT_AFFECTED`/`FALSE_POSITIVE` → not affected, suppressed → risk accepted, `RESOLVED` → awaiting verification.

## Resolution

A finding is resolved by evidence, not by someone closing it.

1. Each upload replaces its project version's snapshot. Findings of that project version that the new snapshot no longer contains become **resolved**, with the commit and ref as evidence.
2. Until every OSV ecosystem has synced once, uploads are matched but nothing resolves, so a half-loaded database never looks like a fix. If the Trivy server cannot be reached, the upload is retried and nothing resolves in the meantime.
3. A resolved finding that is reported again becomes **reopened**.
4. Each project version resolves on its own, so `main` and `prod` resolve independently.
5. Findings closed by a decision (not affected, risk accepted) are left as they are.
6. A finding reported by several projects or sources resolves only once none of them reports it.
7. With Dependency-Track: on `BOM_PROCESSED`, Patchline records the BOM's commit and waits `PATCHLINE_DT_RECONCILE_DELAY` (Dependency-Track 4.x sends it before it has finished analyzing), then reads the project's current findings and resolves the ones it no longer reports.

The commit comes from the `patchline:git:commit` and `patchline:git:ref` properties in the SBOM's metadata; see [SBOM in CI](integrations/sbom-ci.md#attach-the-commit).

## Pull request linking

1. Gitea, Forgejo or GitHub sends **Pull Request** events to `/webhooks/gitea` (see [Git webhooks](integrations/git-webhooks.md)).
2. When a pull request opens or changes, Patchline reads the updates from Renovate's change table (or the title, `Update dependency X to vY`).
3. Each update is matched to open findings of that repository by package name (Maven `group:artifact` = `group/artifact`), in the environment named after the base branch and in `default`.
4. The target version is compared with the vulnerability's affected ranges, from the local OSV mirror (and from Dependency-Track, when it reports the finding): **leaves the affected range**, **still affected**, or **not verified** when no range is known.
5. A linked pull request moves the finding to *in progress*; merging it moves it to *awaiting verification*. Closing without merging is recorded but keeps the state. Only the next SBOM resolves the finding.

Base-image updates are not matched to OS-package findings; those resolve through the next image SBOM.

## Due dates

The policy ([example](../examples/policy/policy.yaml)) turns risk signals into an **effective severity** and a due date:

1. Start from the scanner's severity.
2. Raise one level when the EPSS score is at or above `epss_threshold` (EPSS comes with Dependency-Track findings; without Dependency-Track this step is skipped).
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
- The [webhook sink](integrations/webhook-notifications.md) gets the same events as signed JSON. Without Slack or a webhook, messages are printed to stdout.

## Out of scope

Generating SBOMs (CI does that, see [SBOM in CI](integrations/sbom-ci.md)), SAST for first-party code, configuration audits, multi-tenancy.
