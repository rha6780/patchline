# 설계: 연동을 포트 뒤로

[English](source-ports.md) | 한국어

상태: 1단계 구현.

## 목표

모든 취약점 연동이 같은 작은 인터페이스로 붙도록 해서, 코어(Intake, Finding, 승인, 알림, API)가 어떤 도구가 연결됐는지 모르게 합니다. Dependency-Track은 여러 어댑터 중 하나가 됩니다. 그러면 OpenCVE, Grype, 상용 스캐너를 붙일 때 Intake·스토어·UI를 고치지 않고 `internal/source/` 아래에 패키지 하나만 작성하면 됩니다.

하지 않는 것:

- 동작, Webhook URL, `/api/v1` JSON은 바꾸지 않습니다(`dt_*` 필드는 새 테이블에서 채워 유지).
- 별도 Go 모듈이나 런타임 플러그인은 쓰지 않습니다. 어댑터는 함께 컴파일하고 `main`에서 등록합니다.
- Gitea / GitHub PR Webhook은 취약점 출처가 아니므로 자체 핸들러를 유지하고, 새 Advisories 포트만 사용합니다.

## 지금 Dependency-Track이 새어 나오는 곳

| 위치 | Dependency-Track 의존 |
|---|---|
| `server/server.go` | Webhook 검증을 위해 Dependency-Track 알림을 직접 파싱 |
| `intake/intake.go` | 알림 그룹, `Project`/`Sighting`/`BOMInfo` 타입, 지연 대조(reconcile), `FindingsFetcher` |
| `intake/pullrequest.go` | 수정 PR 판정이 영향 범위를 **Dependency-Track에서만** 읽음. OSV Finding은 로컬 OSV 미러에 범위가 있는데도 *판단 불가* |
| `store/findings.go` | `DTKey`, `ApplyState(DTKey)`, `ResolveMissing(dtProjectUUID)`, `findings`의 `dt_*` 컬럼 5개 |
| `finding.Observation` | `DTProjectUUID`, `DTComponentUUID`, `DTVulnerabilityUUID`, `DTVulnSource`, `DTVulnID` |
| `app/app.go` | `InDT`, `dependencytrack.AnalysisUpdate`를 받는 `AnalysisWriter` |
| `web`, `notify`, `api` | `DTUIURL` + `DTProjectUUID`로 만든 링크, "Dependency-Track에 기록" 문구 |

## 설계

```
                 internal/source (포트)                      코어
 ┌─────────────────────────────────────────────┐
 │ Receiver      Webhook → Inbox 항목           │──▶ server  /webhooks/{name}
 │ Reporter      Inbox 항목 → Outcome           │──▶ intake  (upsert, 해결, 상태 반영, 예약)
 │ Detector      구성요소 → 매칭                │──▶ intake  (SBOM 업로드, 지금의 detect.Engine)
 │ Advisories    취약점 ID + 패키지 → 영향 범위 │──▶ intake  (수정 PR 판정)
 │ DecisionWriter 승인된 판정 → 도구에 기록     │──▶ app     (승인)
 │ Linker        ref → 도구 UI의 URL           │──▶ web, notify, api
 └─────────────────────────────────────────────┘
   어댑터: dependencytrack (Receiver, Reporter, Advisories, DecisionWriter, Linker)
           osv (Detector, Advisories) · trivy (Detector) · patchline SBOM (Reporter)
```

어댑터는 할 수 있는 포트만 구현하고, `main`이 `source.Registry`에 등록합니다. 코어는 레지스트리에 묻습니다("`/webhooks/dependency-track`은 누가 받나", "이 Finding의 판정은 누가 기록할 수 있나").

### 식별자: source ref

Finding의 도구별 식별자를 `findings.dt_*`에서 새 테이블로 옮깁니다.

```sql
CREATE TABLE finding_refs (
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    source      TEXT    NOT NULL,   -- dependencytrack, patchline, ...
    project     TEXT    NOT NULL,   -- 도구의 프로젝트 ID
    component   TEXT    NOT NULL DEFAULT '',
    vuln        TEXT    NOT NULL DEFAULT '',   -- 도구의 취약점 ID 또는 UUID
    vuln_source TEXT    NOT NULL DEFAULT '',   -- NVD, GITHUB, OSV, ...
    vuln_name   TEXT    NOT NULL DEFAULT '',   -- 도구가 부르는 이름, 예: CVE-2021-44228
    PRIMARY KEY (finding_id, source, project)
);
CREATE INDEX finding_refs_by_key ON finding_refs (source, project, component, vuln);
```

`finding_sightings`는 프로젝트가 Finding을 **지금** 보고하는지를 나타내고, `finding_refs`는 도구가 그 Finding을 **어떻게 부르는지**를 나타냅니다. ref는 Finding이 해결돼도 남아서 링크와 판정 기록이 계속 동작합니다. 마이그레이션은 `dt_*` 컬럼을 `finding_refs`로 복사합니다. 1~3단계 동안에는 다운그레이드가 되도록 `dt_*`에도 계속 쓰고, 4단계에서 컬럼을 삭제합니다.

`finding.Observation`은 `DT*` 필드 5개 대신 `Ref` 하나를 갖습니다.

```go
type Ref struct {
    Source, Project, Component, Vuln, VulnSource, VulnName string
}
```

### 포트

포트 정의(Go 코드)는 [영문 문서](source-ports.md#ports)와 같습니다. 요점은 다음과 같습니다.

- **Receiver**: 도구의 Webhook을 검증해 Inbox 항목으로 만듭니다. `/webhooks/{name}`의 `name`이 됩니다.
- **Reporter**: 자기 출처의 Inbox 항목을 `Outcome`으로 바꿉니다. `Outcome`에는 건드린 프로젝트, Observation 목록, 프로젝트 전체 스냅샷(나머지는 해결), ref 기준 상태 변경, 나중에 처리할 항목(예: 2분 뒤 대조)이 들어갑니다. Intake는 항목마다 한 트랜잭션으로 적용합니다.
- **Advisories**: Finding의 패키지에 대한 영향 범위와 수정 버전을 돌려줍니다.
- **DecisionWriter**: 승인된 판정을 그 Finding을 보고한 도구에 기록합니다.
- **Linker**: ref를 도구 UI 링크로 바꿉니다.

옮겨 가는 것:

- **intake**에는 Inbox 루프, 재시도, `Outcome` 적용만 남습니다. Dependency-Track 알림 그룹, 지연 대조, 타입 변환은 `source/dependencytrack`으로 옮깁니다. Patchline SBOM 경로는 `Detector`를 쓰는 `patchline` Reporter가 됩니다.
- **server**는 등록된 모든 `Receiver`에 대해 `POST /webhooks/{name}`을 제공하므로 `/webhooks/dependency-track` URL은 그대로입니다. Gitea는 별도 라우트를 유지합니다.
- **수정 PR 판정**은 `Advisories`를 순서대로 묻습니다. 먼저 OSV 미러(로컬, 네트워크 없음), 다음 Dependency-Track입니다. 눈에 보이는 변화는 이것 하나입니다. OSV·Trivy Finding의 PR도 *판단 불가* 대신 *해결*/*불충분* 판정을 받습니다.
- **app**: 판정을 승인할 때 레지스트리에서 Finding의 ref 중 하나와 맞는 `DecisionWriter`를 찾습니다. 있으면 지금처럼 그곳에 먼저 기록하고, 없으면 Patchline에만 저장합니다. "여기서 결정할 수 있나"는 "Writer가 있는 출처의 ref가 모두 기록 가능한가"가 되어 `InDT`와 `no_dt`를 대신합니다.
- **web / notify / api**는 `Linker`가 만든 ref별 링크를 보여 줍니다. API는 Dependency-Track ref에서 채운 `dt_project_uuid`, `dt_vuln_source`, `dt_vuln_id`를 유지하고 `refs` 배열을 추가합니다.
- **store**에서 `DTKey`, `ApplyState(DTKey)`, `ResolveMissing(dtProjectUUID)`가 빠지고, 대신 `ApplyStateByRef(Ref, …)`와 기존 `ResolveMissingIn(source, project, …)`을 씁니다.

## 단계

단계마다 커밋 하나 이상이며, 기존 테스트가 모두 통과하고 단독으로 배포할 수 있습니다.

| 단계 | 변경 | 완료 기준 |
|---|---|---|
| 1. 스토어에 ref | 백필을 포함한 마이그레이션 `00014_finding_refs`, `Observation.Ref`, `UpsertFinding`이 ref 기록(`dt_*`도 계속 기록), `ApplyStateByRef`. 호출하는 쪽은 그대로 | 백필, 두 출처 병합, 해결 뒤에도 ref 유지에 대한 스토어 테스트 |
| 2. 포트와 Dependency-Track 어댑터 | `internal/source` 포트와 레지스트리, Dependency-Track `Receiver` + `Reporter`, `patchline` Reporter, `Outcome`을 적용하는 Intake, 공통 Webhook 라우트 | `intake`와 `server`가 `source/dependencytrack`을 import하지 않음. Webhook·대조 테스트가 그대로 통과 |
| 3. Advisories, 판정, 링크 | PR 판정용 `Advisories`(OSV, Dependency-Track), `DecisionWriter`, `Linker`. `app`, `web`, `notify`, `api`가 ref 사용 | `source/`와 `main` 밖에서 `source/dependencytrack`을 import하지 않음. OSV Finding의 수정 PR이 판정을 받음 |
| 4. 정리 | `findings.dt_*` 컬럼 기록 중단 후 (한 릴리스 뒤) 삭제, `DTUIURL` 전달을 Linker로 대체 | `grep -r DTProjectUUID internal` 결과가 어댑터뿐 |

## 위험

| 위험 | 대응 |
|---|---|
| 백필 누락·중복 | `dt_*`에서 단순 `INSERT … SELECT`로 백필. 해결됨·병합·Patchline 전용 Finding이 섞인 DB를 마이그레이션해 비교하는 테스트 |
| 두 Dependency-Track 프로젝트가 같은 Finding을 보고 | 지금은 upsert할 때마다 `dt_*`를 덮어써서, 다른 프로젝트의 분석 변경이 아무 Finding에도 맞지 않아 버려짐(기존 버그, 1단계에서 수정). 프로젝트마다 ref가 생기면 판정은 그 Finding의 모든 Dependency-Track ref에 기록하고, 모두 성공해야 승인 |
| 1단계 이후 다운그레이드 | 4단계까지 `dt_*`에도 계속 쓰므로 이전 바이너리가 동작. goose `down`은 테이블을 삭제 |
| 공통 Webhook 라우트로 인증이 바뀜 | `Receiver.Accept`가 지금과 같은 secret을 받음. 이전 핸들러를 지우기 전에 Webhook 테스트를 옛 라우트와 새 라우트 모두에 실행 |
| 간접 계층 증가 | 두 번째 구현이 있거나 예정된 곳에만 포트를 둠: Advisories(OSV, Dependency-Track), Reporter(Dependency-Track, Patchline). Linker와 DecisionWriter는 구현이 하나씩이지만 `if inDT` 분기를 가장 많이 없앰 |

## 열린 질문

1. `dt_*` 컬럼은 언제 삭제할까요? 3단계 다음 릴리스인가요, 1.0까지 유지인가요?
2. API에서 `dt_*`를 지금 `refs`로 대체 예정(deprecated) 표시할까요, `v1` 동안 둘 다 계속 둘까요?
3. 포트를 검증할 첫 새 어댑터는 무엇으로 할까요? OpenCVE(CVE 피드, 구성요소 없음)는 `Advisories`에만 맞고, Grype나 SaaS 스캐너는 `Reporter`까지 검증합니다.
