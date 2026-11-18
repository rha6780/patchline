# SBOM in CI

English | [한국어](sbom-ci.ko.md)

Patchline only knows what you upload. CI produces an SBOM per build and uploads it to Patchline, which matches it ([Detection](native-detection.md)) and reads the commit from it, so each resolution points at the commit that fixed it.

## Which SBOM, which project version

| Source | Tool | Version |
|---|---|---|
| Default branch (application dependencies) | Trivy `fs`, or the CycloneDX Gradle / Maven plugin | `main` |
| Image that is deployed | Trivy `image` (includes OS packages) | `prod` |

Use the project names listed in the inventory ([Registering projects and branches](../projects.md)). For Gradle projects, only a build-time plugin records exact versions, because Spring Boot BOMs resolve them at build time; Trivy `fs` reads lockfiles.

## Attach the commit

Add two properties to the BOM's `metadata` before uploading:

| Property | Value |
|---|---|
| `patchline:git:commit` | Commit SHA the BOM was built from |
| `patchline:git:ref` | Branch or tag, e.g. `refs/heads/main` |

```sh
jq --arg c "$COMMIT_SHA" --arg r "$GIT_REF" \
  '.metadata.properties = ((.metadata.properties // []) + [
     {"name":"patchline:git:commit","value":$c},
     {"name":"patchline:git:ref","value":$r}])' \
  bom.json > bom.patchline.json
```

Without them everything still works; resolutions just carry no commit.

## Upload

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.patchline.json
```

`PATCHLINE_TOKEN` is an [API token](../access-control.md#api-tokens) with `sbom.upload`, one per pipeline (or the shared `PATCHLINE_WEBHOOK_TOKEN`). The project version is created by its first upload.

## Gitea Actions (also GitHub Actions)

```yaml
# .gitea/workflows/sbom.yml
name: sbom
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 21 * * *"   # daily, so new advisories are checked even without pushes

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        run: |
          docker run --rm -v "$PWD:/src" aquasec/trivy:<version> \
            fs --format cyclonedx --output /src/bom.json /src
      - name: Add commit
        run: |
          jq --arg c "$GITHUB_SHA" --arg r "$GITHUB_REF" \
            '.metadata.properties = ((.metadata.properties // []) + [
               {"name":"patchline:git:commit","value":$c},
               {"name":"patchline:git:ref","value":$r}])' \
            bom.json > bom.patchline.json
      - name: Upload to Patchline
        env:
          PATCHLINE_URL: ${{ vars.PATCHLINE_URL }}
          PATCHLINE_TOKEN: ${{ secrets.PATCHLINE_TOKEN }}
        run: |
          curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
            -H "Authorization: Bearer $PATCHLINE_TOKEN" -H "Content-Type: application/json" \
            --data-binary @bom.patchline.json
```

Pin `aquasec/trivy` to a version you have reviewed. The daily run matters less than it may seem, because Patchline re-analyzes stored SBOMs whenever its OSV data changes. It still helps for image SBOMs, whose OS packages Trivy checks only at upload time.

## Gradle (Kotlin / Spring Boot)

```kotlin
// build.gradle.kts
plugins {
    id("org.cyclonedx.bom") version "<version>"
}
```

Run `./gradlew cyclonedxBom` in CI and upload the JSON it writes under `build/reports/` (the file name depends on the plugin version). Then add the commit and upload as above.

## Deployed image (Jenkins example)

Upload the image you actually deploy as version `prod`, after the deploy succeeds:

```groovy
stage('SBOM: prod') {
  steps {
    sh '''
      trivy image --format cyclonedx --output bom.json "$IMAGE@$DIGEST"
      jq --arg c "$GIT_COMMIT" --arg r "refs/heads/$BRANCH_NAME" \
        '.metadata.properties = ((.metadata.properties // []) + [
           {"name":"patchline:git:commit","value":$c},
           {"name":"patchline:git:ref","value":$r}])' bom.json > bom.patchline.json
      curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api-image&version=prod" \
        -H "Authorization: Bearer $PATCHLINE_TOKEN" -H "Content-Type: application/json" \
        --data-binary @bom.patchline.json
    '''
  }
}
```

The image is its own project (`storefront-api-image`); list it under the repository's `projects` in the inventory. Its OS packages are matched by [Trivy](trivy.md).

## Check

- **Integrations** in the UI shows the project, the last SBOM time and the commit.
- A fix that removes a vulnerable component resolves its findings right after the upload, and the Slack thread names the commit.

## Uploading to Dependency-Track as well

If you also run [Dependency-Track](dependency-track.md), upload the same file there with the same names:

```sh
curl -sSf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_UPLOAD_KEY" \
  -F autoCreate=true -F projectName=storefront-api -F projectVersion=main \
  -F bom=@bom.patchline.json
```

`DT_UPLOAD_KEY` belongs to a team with `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`, not the key Patchline uses. Findings from both sources are merged. Those that Dependency-Track stops reporting resolve about `PATCHLINE_DT_RECONCILE_DELAY` after the upload.
