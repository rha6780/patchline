# 프로젝트와 브랜치 등록

[English](projects.md) | 한국어

Patchline은 Finding을 **서비스**별로, 서비스 안에서는 **환경**별로 묶습니다. 둘 다 UI에서 만들지 않습니다. 서비스는 [인벤토리](../examples/inventory/services.yaml)에서 오고, 환경은 그 환경으로 SBOM을 처음 올릴 때 생깁니다. 이 문서는 저장소 하나를 등록하는 방법과, 나중에 이름을 바꾸거나 정리할 때 어떻게 되는지를 설명합니다.

## 관련된 이름

| 이름 | 정하는 곳 | Patchline이 쓰는 방식 |
|---|---|---|
| 서비스 | 인벤토리 `services[].name` | 담당자, Slack 채널, 노출도, Finding 집계 단위 |
| 저장소 | 인벤토리 `repositories[].repo`(`owner/name`) | PR Webhook을 Finding에 연결 |
| 프로젝트 | 인벤토리 `dependency_track_projects`(기본값: `repo`의 마지막 부분). 업로드할 때 `project`, 또는 Dependency-Track 프로젝트 이름 | SBOM이 어느 서비스 것인지 찾음 |
| 버전 | 업로드할 때 `version`, 또는 Dependency-Track 프로젝트 버전 | **환경**이 됨(`main`, `prod`, 비우면 `default`). 환경마다 스냅샷이 따로 있고 따로 해결됨 |
| 브랜치·태그 | SBOM의 `patchline:git:ref` 속성(`refs/heads/main`, `refs/tags/v1.4.0`) | Finding의 근거, Finding 화면과 API의 `branch` 필터 |
| 커밋 | `patchline:git:commit` 속성 | 근거: 어느 빌드가 보고했고 어느 빌드가 고쳤는지 |

예를 들어 애플리케이션 SBOM과 이미지 SBOM을 올리는 저장소 하나는 이렇게 됩니다.

```
서비스 storefront
└── 저장소 acme/storefront-api
    ├── 프로젝트 storefront-api         (애플리케이션 의존성)
    │   ├── 버전 main   ← 기본 브랜치, 머지할 때마다
    │   └── 버전 prod   ← 배포된 것
    └── 프로젝트 storefront-api-image   (이미지의 OS 패키지)
        └── 버전 prod
```

## 1. 인벤토리에 서비스 추가

```yaml
services:
  - name: storefront
    owners: [alice@example.com, bob@example.com]
    slack_channel: "#team-storefront"
    exposure: internet          # internet | internal(기본값) | private
    repositories:
      - repo: acme/storefront-api
        dependency_track_projects: [storefront-api, storefront-api-image]
      - repo: acme/storefront-web   # 프로젝트 "storefront-web"
```

- `PATCHLINE_INVENTORY_PATH`는 파일이나 디렉터리입니다. 디렉터리면 안의 `*.yaml`·`*.yml` 파일을 모두 읽어 합치므로 팀마다 파일 하나씩 맡을 수 있습니다.
- 모르는 필드, 중복된 서비스, 두 저장소가 같은 프로젝트를 가진 경우에는 Patchline이 시작하지 않습니다. 오타 때문에 Finding이 엉뚱한 팀으로 가는 일을 막기 위해서입니다.
- 인벤토리는 시작할 때 읽습니다. **바꾼 뒤에는 Patchline을 재시작하세요.** Git으로 관리하고 다른 설정처럼 배포하는 것을 권장합니다.

## 2. 프로젝트 이름 정하기

저장소가 저장소 이름과 같은 SBOM 프로젝트 하나만 올리면 `dependency_track_projects`를 생략합니다(`acme/storefront-web` → `storefront-web`). 애플리케이션과 이미지처럼 여러 개면 모두 적습니다. 프로젝트 이름 하나는 서비스 하나에만 속합니다.

## 3. 버전(환경) 정하기

빌드마다가 아니라 오래 유지되는 환경마다 버전 하나를 씁니다.

| 버전 | 올리는 때 | 이유 |
|---|---|---|
| 기본 브랜치 이름(`main`) | 기본 브랜치에 머지할 때마다 | Renovate PR은 **base 브랜치** 이름과 같은 환경(과 `default`)에서 Finding을 찾습니다. 다른 이름이면 수정 PR이 연결되지 않습니다 |
| `prod`(또는 `staging` 등) | 배포가 성공한 뒤, 배포한 것으로 | "main에서는 고쳤지만 prod에는 남아 있음"을 보여 줍니다 |

버전마다 Finding은 그 버전의 새 SBOM에서 빠질 때까지 열려 있습니다. 그래서 다음을 지켜 주세요.

- 빌드 번호, 커밋, 기능 브랜치를 버전으로 쓰지 마세요. 다시는 SBOM이 오지 않는 환경이 생겨 Finding이 계속 열려 있게 됩니다.
- 한동안 유지되는 릴리스 라인(`release-1.4`)은 CI가 계속 올린다면 별도 버전으로 써도 됩니다.

## 4. 브랜치와 커밋 붙이기

SBOM 메타데이터에 속성 두 개를 넣습니다([jq로 넣는 방법](integrations/sbom-ci.ko.md)).

| 속성 | 예 |
|---|---|
| `patchline:git:commit` | `1f0e2d3c…` |
| `patchline:git:ref` | `refs/heads/main`, `refs/tags/v1.4.0` |

버전은 *어디서 돌아가는지*, ref는 *무엇으로 빌드했는지*입니다. 태그 `v1.4.0`으로 빌드한 `prod` 이미지는 버전 `prod`, ref `refs/tags/v1.4.0`으로 올립니다. 그러면 `branch=v1.4.0`(또는 `refs/tags/v1.4.0`)으로 그 릴리스에 남은 Finding을 볼 수 있습니다. 대상은 최신 SBOM이 그 릴리스에서 나온 모든 프로젝트입니다. 이 필터는 프로젝트 버전마다 **최신** SBOM만 비교합니다.

속성이 없어도 모든 기능이 동작합니다. 다만 근거에 커밋이 남지 않고 브랜치 필터를 쓸 수 없습니다.

## 5. SBOM 올리기

Patchline으로 올리기([자체 탐지](integrations/native-detection.ko.md)):

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_TOKEN" \
  -H "Content-Type: application/json" --data-binary @bom.patchline.json
```

`PATCHLINE_TOKEN`은 Webhook 토큰이나 `sbom.upload` 권한이 있는 API 토큰입니다.

Dependency-Track으로 올릴 때는 같은 이름을 `projectName`, `projectVersion`으로 씁니다([CI에서 SBOM 만들기](integrations/sbom-ci.ko.md)). 한 프로젝트를 두 곳에 모두 올려도 되고, 두 출처의 Finding은 하나로 합쳐집니다.

## 6. 확인

1. **연동 상태**에 프로젝트 버전이 마지막 SBOM 시각과 커밋과 함께 나옵니다. 인벤토리에는 있는데 SBOM을 한 번도 보내지 않은 프로젝트는 *BOM이 없는 인벤토리 프로젝트*에 나옵니다. 대개 CI에서 쓴 이름과 인벤토리 이름이 다른 경우입니다.
2. Finding에 서비스와 담당자가 나옵니다. *인벤토리 미등록*이면 프로젝트 이름이 어떤 `dependency_track_projects`와도 맞지 않은 것입니다.
3. 기본 브랜치로 Renovate PR을 열면 Finding에 연결됩니다([Renovate](integrations/renovate.ko.md) 참고).

## 나중에 바꿀 때

| 변경 | 결과 |
|---|---|
| 서비스에 저장소나 프로젝트 추가 | 재시작하면 다음 SBOM부터 그 서비스로 들어갑니다 |
| 프로젝트를 다른 서비스로 옮김 | 재시작한 뒤 다음 SBOM이 오면 새 서비스 아래에 Finding이 새로 생기고, 기존 서비스의 Finding은 해결됩니다. 기록·담당자·판정은 기존 Finding에 남습니다. 그래서 작업을 시작하기 전에 옮기거나, 예외를 다시 요청하세요 |
| 인벤토리에서 프로젝트 삭제 | Finding은 프로젝트 이름 아래에서 *인벤토리 미등록*으로 계속 추적되고, 알림은 `PATCHLINE_SLACK_DEFAULT_CHANNEL`로 갑니다 |
| 환경 정리(더 빌드하지 않는 브랜치, 내린 배포) | 삭제 기능은 없습니다. 그 버전으로 빈 SBOM을 한 번 올리면 보고된 Finding이 모두 해결됩니다. Dependency-Track도 해당 프로젝트 버전에 빈 BOM을 올리면 같습니다 |

빈 CycloneDX SBOM:

```sh
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}' |
  curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=feature-x" \
    -H "Authorization: Bearer $PATCHLINE_TOKEN" -H "Content-Type: application/json" --data-binary @-
```
