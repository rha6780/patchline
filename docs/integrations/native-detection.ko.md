# 자체 탐지(SBOM 업로드)

[English](native-detection.md) | 한국어

Patchline이 직접 취약점을 찾을 수 있습니다. CI가 SBOM을 Patchline에 올리면, 구성요소를 [OSV](https://osv.dev) 데이터의 로컬 미러와 대조합니다. 데이터가 바뀌면 저장된 SBOM을 다시 분석합니다. Dependency-Track이 있어도 없어도 동작하며, 둘 다 같은 취약점을 찾으면 출처 두 개가 붙은 **Finding 하나**가 됩니다([설계 문서](../design/native-detection.ko.md) 참고).

| | Dependency-Track | 자체 탐지 |
|---|---|---|
| SBOM을 보내는 곳 | Dependency-Track | Patchline(`/ingest/sbom`) |
| 대조 | Dependency-Track 분석기(NVD, OSS Index, OSV, GitHub, Trivy) | OSV: Maven, npm, PyPI, Go, crates.io, NuGet, RubyGems, Packagist |
| OS 패키지(deb, rpm, apk) | Trivy 분석기를 쓰면 가능 | 아직 없음(Trivy로 지원 예정) |
| 분석 판정 | Dependency-Track에서 | 예정(3단계) |

## 1. 켜기

기본으로 Maven, npm, PyPI, Go에 대해 켜져 있습니다.

```sh
PATCHLINE_OSV_ECOSYSTEMS=Maven,npm,PyPI,Go    # 끄려면 off
PATCHLINE_OSV_REFRESH=6h                       # 변경분을 받는 주기
# PATCHLINE_OSV_URL=https://osv-mirror.internal  # 사내 미러(같은 구조)
```

처음 실행하면 생태계별 전체 export를 한 번 받습니다(Maven 약 10MB, npm 약 220MB, PyPI 약 40MB, Go 약 13MB). 이후에는 바뀐 레코드만 받습니다(`modified_id.csv`). 데이터는 SQLite DB에 저장되며, npm을 포함하면 DB가 80MB 정도 늘어납니다. 시작 로그에 `osv synced ecosystem=… records=…`가 남습니다.

설정한 모든 생태계가 한 번씩 동기화되기 전에는 업로드를 분석은 하되 해결 판정은 하지 않습니다. 덜 받은 데이터를 "고쳐졌다"로 오해하지 않기 위해서입니다.

## 2. CI에서 SBOM 올리기

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom?project=storefront-api&version=main" \
  -H "Authorization: Bearer $PATCHLINE_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @bom.patchline.json
```

Dependency-Track과 같은 multipart 방식도 됩니다.

```sh
curl -sSf -X POST "$PATCHLINE_URL/ingest/sbom" -H "Authorization: Bearer $PATCHLINE_WEBHOOK_TOKEN" \
  -F project=storefront-api -F version=main -F bom=@bom.patchline.json
```

| | |
|---|---|
| 형식 | CycloneDX JSON, SPDX JSON(XML은 아직 미지원) |
| 구성요소 | `purl`로 식별. purl이 없는 구성요소는 개수만 세고(`without_purl`) 건너뜀 |
| `project` | Dependency-Track 프로젝트 이름과 똑같이 인벤토리에서 찾음(`dependency_track_projects`, 기본값: `repo`의 마지막 부분) |
| `version` | 환경(예: `main`, `prod`) |
| 커밋 | BOM metadata의 `patchline:git:commit` / `patchline:git:ref`([CI의 SBOM 생성](sbom-ci.ko.md)과 같음). SPDX는 `patchline:git:commit=<sha>` annotation |
| 토큰 | `PATCHLINE_WEBHOOK_TOKEN` 또는 **설정 → Webhook**에서 지정한 값 |

응답은 `202`와 `{"format": "CycloneDX", "components": 3, "without_purl": 0}`이고, 대조는 바로 이어서 실행됩니다.

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

같은 SBOM을 Dependency-Track과 Patchline에 모두 올려도 됩니다. Finding은 하나로 합쳐집니다.

## Finding이 어떻게 바뀌나

- 업로드할 때마다 그 프로젝트 버전의 스냅샷이 바뀝니다. 스냅샷에서 사라진 취약점은 커밋을 근거로 해결됩니다. 단, 다른 출처(Dependency-Track)가 아직 보고 중이면 열린 채로 둡니다. 다시 나타나면 재발로 처리합니다.
- OSV가 갱신될 때마다 저장된 스냅샷을 모두 다시 분석합니다. 새 권고가 나오면 빌드 없이도 Finding과 알림이 생기고, 철회된 권고의 Finding은 해결됩니다.
- 심각도는 권고의 값(GitHub 등급, 없으면 CVSS v3 기본 점수)을 씁니다. Dependency-Track도 보고하면 그쪽 심각도를 씁니다.
- 기한, KEV·EPSS 상향, Renovate PR 연결, Slack 메시지, 승인은 Dependency-Track Finding과 똑같이 동작합니다. EPSS는 Dependency-Track에서만 받습니다. 위험 수용은 아직 Dependency-Track Finding에만 쓸 수 있습니다.

## 확인

1. 로그에 생태계별 `osv synced`가 남습니다.
2. SBOM을 올리면 로그에 `sbom analyzed … result="N findings (N new), 0 resolved"`가 남습니다.
3. **연동** 화면에 출처가 *Patchline (OSV)*인 프로젝트와 커밋이 보이고, Finding 상세에 *탐지한 곳: Patchline (OSV)*가 표시됩니다.

| 증상 | 원인 |
|---|---|
| `401` | 토큰이 `PATCHLINE_WEBHOOK_TOKEN`(또는 **설정 → Webhook**의 값)과 다름 |
| `400 … XML is not supported` | JSON으로 생성(`trivy … --format cyclonedx`, JSON 출력의 `cyclonedxBom`) |
| `components: 0` 또는 `without_purl`이 많음 | 생성기가 purl을 쓰지 않음. Trivy나 CycloneDX 플러그인 사용 |
| `… still syncing, nothing resolved` | 첫 다운로드가 끝나지 않음. `osv synced`를 기다림 |
| `osv sync failed` | 인터넷 불가. export를 사내에 미러링하고 `PATCHLINE_OSV_URL` 지정 |
