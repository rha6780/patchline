# CI의 SBOM 생성

[English](sbom-ci.md) | 한국어

Patchline은 업로드된 것만 압니다. CI가 빌드마다 SBOM을 만들어 Patchline에 올리면, Patchline이 대조하고([탐지](native-detection.ko.md)) SBOM에서 커밋을 읽어 해결 판정의 근거로 남깁니다.

## 어떤 SBOM을 어떤 프로젝트 버전으로

| 대상 | 도구 | 버전 |
|---|---|---|
| 기본 브랜치(애플리케이션 의존성) | Trivy `fs` 또는 CycloneDX Gradle / Maven 플러그인 | `main` |
| 실제 배포되는 이미지 | Trivy `image`(OS 패키지 포함) | `prod` |

프로젝트 이름은 인벤토리에 적은 이름을 쓰세요([프로젝트와 브랜치 등록](../projects.ko.md)). Gradle 프로젝트는 빌드 시점 플러그인을 써야 정확한 버전이 나옵니다(Spring Boot BOM은 빌드할 때 버전을 정함). Trivy `fs`는 lockfile을 읽습니다.

## 커밋 남기기

업로드하기 전에 BOM의 `metadata`에 속성 두 개를 추가합니다.

| 속성 | 값 |
|---|---|
| `patchline:git:commit` | BOM을 만든 커밋 SHA |
| `patchline:git:ref` | 브랜치나 태그(예: `refs/heads/main`) |

```sh
jq --arg c "$COMMIT_SHA" --arg r "$GIT_REF" \
  '.metadata.properties = ((.metadata.properties // []) + [
     {"name":"patchline:git:commit","value":$c},
     {"name":"patchline:git:ref","value":$r}])' \
  bom.json > bom.patchline.json
```

속성이 없어도 동작합니다. 다만 해결 판정에 커밋이 남지 않습니다.

## 업로드

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.patchline.json
```

`PATCHLINE_TOKEN`은 `sbom.upload` 권한이 있는 [API 토큰](../access-control.ko.md#api-토큰)입니다. 파이프라인마다 하나씩 만드세요(공용 `PATCHLINE_WEBHOOK_TOKEN`도 됨). 프로젝트 버전은 첫 업로드 때 생깁니다.

## Gitea Actions(GitHub Actions도 동일)

```yaml
# .gitea/workflows/sbom.yml
name: sbom
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 21 * * *"   # 매일 실행: push가 없어도 새 취약점 공지를 확인

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

`aquasec/trivy`는 검토한 버전으로 고정하세요. Patchline은 OSV 데이터가 바뀔 때마다 저장된 SBOM을 다시 분석하므로 매일 실행이 필수는 아닙니다. 다만 이미지의 OS 패키지는 업로드할 때 Trivy가 확인하므로, 매일 실행하면 그 결과가 갱신됩니다.

## Gradle(Kotlin / Spring Boot)

```kotlin
// build.gradle.kts
plugins {
    id("org.cyclonedx.bom") version "<version>"
}
```

CI에서 `./gradlew cyclonedxBom`을 실행하고 `build/reports/` 아래에 생성된 JSON을 업로드합니다(파일 이름은 플러그인 버전에 따라 다름). 커밋 추가와 업로드는 위와 같습니다.

## 배포된 이미지(Jenkins 예시)

배포가 성공한 뒤, 실제로 배포한 이미지를 `prod` 버전으로 업로드합니다.

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

이미지는 별도 프로젝트(`storefront-api-image`)입니다. 인벤토리의 해당 저장소 `projects`에 추가하세요. OS 패키지는 [Trivy](trivy.ko.md)가 대조합니다.

## 확인

- UI의 **연동 상태**에 프로젝트, 마지막 SBOM 시각, 커밋이 표시됩니다.
- 취약한 구성요소를 제거한 수정본을 올리면 바로 해당 Finding이 해결되고 Slack 스레드에 커밋이 남습니다.

## Dependency-Track에도 올릴 때

[Dependency-Track](dependency-track.ko.md)도 쓴다면 같은 파일을 같은 이름으로 그곳에도 올립니다.

```sh
curl -sSf -X POST "$DT_URL/api/v1/bom" -H "X-Api-Key: $DT_UPLOAD_KEY" \
  -F autoCreate=true -F projectName=storefront-api -F projectVersion=main \
  -F bom=@bom.patchline.json
```

`DT_UPLOAD_KEY`는 `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` 권한을 가진 팀의 키입니다. Patchline이 쓰는 키와 분리하세요. 두 곳의 Finding은 합쳐지고, Dependency-Track 쪽 해결은 업로드 후 약 `PATCHLINE_DT_RECONCILE_DELAY` 뒤에 반영됩니다.
