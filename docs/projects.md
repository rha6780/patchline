# Registering projects and branches

English | [한국어](projects.ko.md)

Patchline groups findings by **service**, and within a service by **environment**. Neither is created in the UI. A service comes from the [inventory](../examples/inventory/services.yaml). An environment is created by the first SBOM uploaded for it. This page explains how to set up both for a repository, and what changes when you rename or retire them later.

## The names involved

| Name | Where it is set | What Patchline does with it |
|---|---|---|
| Service | Inventory: `services[].name` | Owners, Slack channel, exposure, and the unit findings are counted by |
| Repository | Inventory: `repositories[].repo` (`owner/name`) | Matches pull request webhooks to findings |
| Project | Inventory: `dependency_track_projects` (default: last segment of `repo`). Upload: `project`, or the Dependency-Track project name | Finds the service for an SBOM |
| Version | Upload: `version`, or the Dependency-Track project version | Becomes the **environment** (`main`, `prod`; empty becomes `default`). Each environment has its own snapshot and resolves on its own |
| Branch or tag | The `patchline:git:ref` property in the SBOM (`refs/heads/main`, `refs/tags/v1.4.0`) | Evidence on findings, and the `branch` filter on the findings page and in the API |
| Commit | The `patchline:git:commit` property | Evidence: which build reported or fixed a finding |

For example, one repository with an application SBOM and an image SBOM:

```
service storefront
└── repo acme/storefront-api
    ├── project storefront-api         (application dependencies)
    │   ├── version main   ← default branch, every merge
    │   └── version prod   ← what is deployed
    └── project storefront-api-image   (OS packages of the image)
        └── version prod
```

## 1. Add the service to the inventory

```yaml
services:
  - name: storefront
    owners: [alice@example.com, bob@example.com]
    slack_channel: "#team-storefront"
    exposure: internet          # internet | internal (default) | private
    repositories:
      - repo: acme/storefront-api
        dependency_track_projects: [storefront-api, storefront-api-image]
      - repo: acme/storefront-web   # project "storefront-web"
```

- `PATCHLINE_INVENTORY_PATH` is a file or a directory. A directory is read as every `*.yaml` / `*.yml` file in it, merged, so each team can own one file.
- Unknown fields, a duplicate service, and a project claimed by two repositories all stop Patchline from starting. A typo cannot silently send findings to the wrong team.
- The inventory is read at startup. **Restart Patchline after changing it.** Keep it in Git and roll it out like any other configuration change.

## 2. Pick the project names

Leave `dependency_track_projects` out when a repository uploads a single SBOM project named after the repository (`acme/storefront-web` → `storefront-web`). List the projects when there are several, typically the application and its image. A project name belongs to exactly one service.

## 3. Pick the versions (environments)

Use one version per long-lived environment, not one per build:

| Version | Upload when | Why |
|---|---|---|
| The default branch's name (`main`) | Every merge to the default branch | Renovate PRs are matched in the environment named after their **base branch** (and in `default`). With any other name, fix PRs are not linked |
| `prod` (or `staging`, ...) | After a deploy succeeds, from what was deployed | Shows "fixed on main, still open in prod" |

Each version keeps its findings open until a newer SBOM for that version no longer contains them. So:

- Do not use a build number, a commit or a feature branch as the version. Each would become an environment that never gets another SBOM, and its findings would stay open.
- A release line that lives on for a while (`release-1.4`) is fine as its own version, as long as CI keeps uploading it.

## 4. Attach the branch and the commit

Add two properties to the SBOM's metadata ([how, with jq](integrations/sbom-ci.md#attach-the-commit)):

| Property | Example |
|---|---|
| `patchline:git:commit` | `1f0e2d3c…` |
| `patchline:git:ref` | `refs/heads/main`, `refs/tags/v1.4.0` |

The version says *where it runs*, the ref says *what it was built from*. A `prod` image built from tag `v1.4.0` is uploaded as version `prod` with ref `refs/tags/v1.4.0`. `branch=v1.4.0` (or `refs/tags/v1.4.0`) then finds what that release still has open, in every project whose latest SBOM came from it. The filter compares with each project version's **latest** SBOM only.

Without the properties everything still works, only without the commit as evidence and without the branch filter.

## 5. Upload the SBOM

To Patchline ([built-in detection](integrations/native-detection.md)):

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_TOKEN" \
  -H "Content-Type: application/json" --data-binary @bom.patchline.json
```

`PATCHLINE_TOKEN` is the webhook token or an API token with `sbom.upload`.

To Dependency-Track, use the same names as `projectName` and `projectVersion` ([SBOM in CI](integrations/sbom-ci.md)). Both can be used for one project: findings from both sources merge.

## 6. Check

1. **Integrations** lists the project version with its last SBOM time and commit. Projects that are in the inventory but have never sent an SBOM appear under *Inventory projects without a BOM*: there the name in CI and the inventory usually differ.
2. A finding shows the service and its owners. *Not in inventory* means the project name matched no `dependency_track_projects` entry.
3. Open a Renovate PR against the default branch: the finding links it (see [Renovate](integrations/renovate.md)).

## Later changes

| Change | What happens |
|---|---|
| Add a repository or project to a service | Restart. The next SBOM is assigned to the service |
| Move a project to another service | Restart. With the next SBOM, findings are created under the new service and the old service's findings resolve. Their history, assignee and decisions stay with the old findings, so move projects before work on them starts, or re-request the exceptions |
| Remove a project from the inventory | Its findings continue under the project's own name, marked *not in inventory*, and notifications go to `PATCHLINE_SLACK_DEFAULT_CHANNEL` |
| Retire an environment (a branch you no longer build, a decommissioned deploy) | There is no delete. Upload an empty SBOM to that version once; every finding it reported resolves. In Dependency-Track, upload an empty BOM to that project version the same way |

An empty CycloneDX SBOM:

```sh
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}' |
  curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=feature-x" \
    -H "Authorization: Bearer $PATCHLINE_TOKEN" -H "Content-Type: application/json" --data-binary @-
```
