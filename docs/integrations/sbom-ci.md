# SBOM in CI

English | [한국어](sbom-ci.ko.md)

Dependency-Track only knows what you upload. CI produces a CycloneDX BOM per build and uploads it; Patchline reads the commit from the BOM, so each resolution points at the commit that fixed it.

## Which BOM, which project version

| Source | Tool | Dependency-Track project version |
|---|---|---|
| Default branch (application dependencies) | Trivy `fs`, or the CycloneDX Gradle / Maven plugin | `main` |
| Image that is deployed | Trivy `image` (includes OS packages) | `prod` |

Use the project names listed in the inventory. Gradle projects get exact versions only from a build-time plugin (Spring Boot BOMs resolve versions at build time); Trivy `fs` reads lockfiles.

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
curl -sSf -X POST "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_UPLOAD_KEY" \
  -F autoCreate=true \
  -F projectName=storefront-api \
  -F projectVersion=main \
  -F bom=@bom.patchline.json
```

`DT_UPLOAD_KEY` belongs to a team with `BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`, not the key Patchline uses.

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
      - name: Upload to Dependency-Track
        env:
          DT_URL: ${{ vars.DT_URL }}
          DT_UPLOAD_KEY: ${{ secrets.DT_UPLOAD_KEY }}
        run: |
          curl -sSf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_UPLOAD_KEY" \
            -F autoCreate=true -F projectName=storefront-api -F projectVersion=main \
            -F bom=@bom.patchline.json
```

Pin `aquasec/trivy` to a version you have reviewed. To also use Trivy's vulnerability database for the analysis itself, see [Trivy analyzer](trivy.md).

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
      curl -sSf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_UPLOAD_KEY" \
        -F autoCreate=true -F projectName=storefront-api-image -F projectVersion=prod \
        -F bom=@bom.patchline.json
    '''
  }
}
```

If the image is a separate Dependency-Track project (`storefront-api-image`), list it under the repository's `dependency_track_projects` in the inventory.

## Check

- **Integrations** in the UI shows the project, the last BOM time and the commit.
- A fix that removes a vulnerable component resolves its findings about `PATCHLINE_DT_RECONCILE_DELAY` after the upload, and the Slack thread names the commit.
