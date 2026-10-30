# 설계: Dependency-Track과 함께 쓰는 자체 탐지

[English](native-detection.md) | 한국어

상태: 1~3단계 구현 완료, 4단계 예정.

## 목표

Dependency-Track 연동은 그대로 유지하면서, Patchline이 직접 취약점을 탐지할 수도 있게 합니다. CI가 SBOM을 Patchline에 올리면 Patchline이 취약점 DB와 대조하고, DB가 바뀌면 다시 분석합니다. 어느 경로로 들어오든(둘 다여도) 같은 Finding, 기한, PR 연결, 알림, 승인으로 이어집니다.

| Dependency-Track 기능 | Patchline |
|---|---|
| 프로젝트 버전별 SBOM 업로드·보관 | 1단계(완료) |
| 취약점 데이터 대조 | 1단계(OSV), 4단계(선택 엔진으로 Trivy) |
| 데이터가 바뀌면 재분석 | 1단계 |
| 구성요소 검색·영향 분석 | 2단계(완료) |
| 분석 판정과 VEX | 3단계(완료) |
| 라이선스·정책 위반 | 당분간 범위 밖 |

## 구조

```
                  ┌──────────────────────── 수집원 ──────────────────────────┐
Dependency-Track ─┤ dependencytrack: webhook + API (변경 없음)                │
                  │                                                          ├─▶ 관측 ─▶ Finding ─▶ SLA, PR, Slack, 승인
CI ── SBOM ───────┤ patchline: SBOM Inbox → 구성요소 → 대조 엔진 ◀── OSV DB    │     (서비스 × 환경 × 구성요소 × 취약점당 하나,
                  └──────────────────────────────────────────────────────────┘      출처 기록 포함)
```

### 수집원과 출처 기록(sighting)

**수집원**은 "수집원 S의 프로젝트 P에 구성요소 C가 있고, 취약점 V가 있다"는 **출처 기록**을 보고합니다. 지금까지 수집원은 `dependencytrack` 하나였고, 1단계에서 `patchline`을 추가합니다.

- Finding 단위는 그대로 서비스 × 환경 × 구성요소(purl) × 취약점(대표 ID, CVE 우선)입니다. Dependency-Track과 Patchline이 같은 것을 보면 **같은 Finding**을 갱신합니다. 메시지도 기한도 하나입니다.
- `finding_sightings`에 각 Finding을 지금 보고 중인 수집원 프로젝트를 기록합니다. 한 수집원 프로젝트를 다시 비교하면(새 BOM이나 재분석) 그 프로젝트의 기록을 바꿉니다.
- **어느 수집원도 더 이상 보고하지 않을 때 해결**됩니다. 즉 그 Finding을 보고했던 모든 프로젝트의 최신 BOM에서 사라져야 합니다. 어느 수집원이든 다시 보고하면 **재발**입니다.
- 심각도와 제목은 Finding의 대표 수집원 값을 씁니다. Dependency-Track이 보고하면 Dependency-Track이 우선이라, 수집원에 따라 심각도가 오가지 않습니다. Dependency-Track ID는 링크와 판정 기록용으로 그대로 둡니다.

### SBOM 수집(수집원 `patchline`)

- `POST /ingest/sbom?project=<이름>&version=<버전>`으로 CycloneDX(JSON)나 SPDX(JSON)를 받습니다. Webhook 토큰으로 인증하고, Dependency-Track 업로드처럼 `bom` 필드를 가진 multipart도 받습니다.
- 핸들러는 업로드를 Inbox에 저장만 합니다(webhook과 같은 재시도·중복 제거). 이후 처리기가 다음을 합니다.
  1. SBOM을 읽습니다: purl이 있는 구성요소, serial, `patchline:git:commit` / `patchline:git:ref` 속성
  2. 그 프로젝트 버전의 구성요소 스냅샷을 바꿉니다
  3. 구성요소를 대조해 출처를 기록하고, 이 스냅샷에서 사라진 Finding을 해결합니다
- 프로젝트 이름은 Dependency-Track 프로젝트 이름과 똑같이 인벤토리로 서비스에 연결되고, 버전은 환경이 됩니다.

### 대조(OSV)

- **데이터:** `osv-vulnerabilities.storage.googleapis.com`의 생태계별 OSV export를 씁니다.
  - 처음에는 `<ecosystem>/all.zip`을 받습니다.
  - 이후에는 `<ecosystem>/modified_id.csv`를 읽어 지난 동기화 이후 바뀐 레코드만 받습니다. 그래서 npm의 약 220MB export는 한 번만 받습니다.
- **생태계:** 설정할 수 있고 기본값은 Maven, npm, PyPI, Go입니다. 인터넷이 막힌 서버에서는 같은 구조의 사내 미러를 씁니다.
- **매칭 조건:** 구성요소의 purl이 OSV 패키지에 대응하고(Maven `group:artifact`, npm `@scope/name`, PyPI 정규화 이름, Go 모듈 경로 등), 버전이 영향 범위(`introduced` / `fixed` / `last_affected` 이벤트)나 명시된 `versions` 목록에 있으면 해당합니다.
- **심각도:** `database_specific.severity`(GitHub 권고)가 있으면 그 값을, 없으면 벡터로 계산한 CVSS v3 기본 점수를 씁니다. 둘 다 없으면 *unassigned*입니다. 별칭(CVE, GHSA) 덕분에 대표 ID가 Dependency-Track과 같아집니다.
- **재분석:** 동기화할 때마다 저장된 스냅샷을 모두 다시 분석합니다. 새로 해당하면 Finding과 알림이 생기고, 철회된 권고의 Finding은 해결됩니다.

### 2단계: 구성요소 검색과 영향 분석

구현했습니다.
- **구성요소 검색**(`/components`, `GET /api/v1/components`): 패키지가 어디에 쓰이는지 찾습니다. 버전 조건(`>= 2.0, < 2.17.0`)을 붙일 수 있습니다.
- **영향 분석**(`/vulnerabilities/{id}`, `GET /api/v1/vulnerabilities/{id}`): CVE나 GHSA를 OSV 별칭으로 찾아 다음을 보여 줍니다.
  - 영향받는 버전을 쓰는 스냅샷: 범위, 고치는 버전, 커밋, 종료된 것까지 포함한 Finding
  - 수정 버전을 쓰는 스냅샷 수
  - 모든 출처의 Finding

### 3단계: 분석 판정과 VEX

구현했습니다.
- **판정 종류:** 위험 수용에 더해 *해당 없음*(CycloneDX 근거 포함)과 *오탐*을 요청할 수 있습니다. 모두 요청·승인 흐름을 거치고, 본인 요청은 승인할 수 없습니다.
- **기록 위치:**
  - Dependency-Track이 아는 Finding은 판정을 그곳에 기록합니다(근거를 붙인 `NOT_AFFECTED`, `FALSE_POSITIVE`, 또는 `EXPLOITABLE` + `WILL_NOT_FIX` + Suppress).
  - Patchline만 보고한 Finding은 Patchline에 보관합니다(`analysis_*` 컬럼).
- **VEX 내보내기:** `GET /api/v1/vex?project=&version=`이 스냅샷의 Finding을 CycloneDX 1.5 VEX로 내보냅니다. 열림은 `in_triage`, Merge 후 재스캔 대기는 `in_triage` + `update`, 판정은 판정대로 표시합니다. CycloneDX 스키마 검증을 통과합니다.
- **BOM-Link:** VEX `affects`는 업로드한 CycloneDX SBOM을 가리키는 BOM-Link(`urn:cdx:<serial>/<version>#<bom-ref>`)입니다. Trivy `--vex`가 실제로 적용하는 것을 확인했습니다(해당 없음으로 판정한 Log4Shell은 빠지고, 열린 CVE는 남음).
- **아직 없는 것:** UI에서 판정 취소.

### 4단계: 선택 엔진으로 Trivy

엔진은 인터페이스입니다. OSV는 내장이고, OS 패키지와 이미지를 위해 Trivy 서버를 추가할 수 있습니다. Trivy 서버 API는 공개 문서가 없으므로 선택 사항으로 둡니다.

## 위험 요소

| 위험 | 대응 |
|---|---|
| 버전 비교가 생태계 규칙과 다름 | `internal/version`(Maven, SemVer, PyPI, Go 형식)을 재사용하고, 명시된 `versions` 목록을 우선함. 매칭마다 해당한 범위를 근거로 기록. 샘플 SBOM 6건에서 OSV API 결과와 개수가 일치함을 확인 |
| ID가 달라서 생기는 중복(GHSA와 CVE) | 별칭으로 대표 ID를 정함. Dependency-Track Finding과 같은 규칙 |
| 큰 다운로드 | 전체 export는 한 번만 받고 이후 증분. 생태계 설정 가능. npm 23만 건이 다운로드 포함 약 13초 |
| 수집원끼리 결과가 다름 | 수집원별 출처 기록. 모든 수집원이 보고를 멈춰야 해결 |
