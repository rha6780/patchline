# Patchline 동작 방식

[English](how-it-works.md) | 한국어

```
서비스 저장소     ── CI: SBOM (main) ─────┐
배포 파이프라인   ── 이미지 SBOM (prod) ──┼──▶  Patchline  ◀── 인벤토리(Git, YAML)
Renovate ── 수정 PR ── Git Webhook ───────┤      │     │    ◀── CISA KEV
Dependency-Track(선택) ── Webhook ────────┘      │     └──▶ OSV 미러, Trivy 서버
                                       ┌─────────┴─────────┐
                                  Slack, Webhook         웹 UI
```

| 도구 | 역할 |
|---|---|
| **Patchline** | 올린 SBOM을 로컬 OSV 미러와 Trivy 서버로 대조하고, Finding을 인벤토리와 연결하고, 기한을 계산하고, 알림을 보내고, 판정을 보관하고, 증거로 상태를 추적 |
| **Trivy 서버** | 컨테이너 이미지의 OS 패키지(deb, rpm, apk) 권고 |
| **Renovate** | 수정 PR 생성(의존성 업데이트, 베이스 이미지 Digest 갱신) |
| **Dependency-Track**(선택) | 두 번째 출처: 자체 분석기, Finding, 분석 판정 |

## Finding 상태

| 상태 | 전이 조건 |
|---|---|
| `new` (신규) | 처음 보고됨: Patchline에 올린 SBOM, 또는 Dependency-Track |
| `in_progress` (조치중) | 수정 PR이 연결됨(또는 Dependency-Track 분석이 In Triage·Exploitable) |
| `awaiting_verification` (검증대기) | 수정 PR Merge(또는 Dependency-Track 분석이 Resolved) |
| `resolved` (해결) | 보고했던 모든 프로젝트의 최신 SBOM에서 더 이상 보고되지 않음 |
| `not_affected` (해당 없음) | *해당 없음*·*오탐* 요청이 승인됨(또는 Dependency-Track 분석 결과) |
| `risk_accepted` (위험 수용) | 위험 수용이 승인됨(또는 Dependency-Track에서 Suppress) |
| `reopened` (재발) | 해결된 Finding이 다시 보고됨 |

판정은 **Patchline에서** 합니다. 한 사람이 예외를 요청하고 다른 사람이 승인합니다([로그인과 권한](access-control.ko.md)). 판정은 Finding에 보관되고(누가, 언제, 왜) Finding을 닫으며, [VEX](integrations/native-detection.ko.md)로 내보냅니다. Dependency-Track도 그 Finding을 보고하면 승인된 판정을 Dependency-Track에 먼저 기록해 두 도구가 같은 판정을 갖게 합니다.

## 수집

1. SBOM 업로드(`/ingest/sbom`)와 Webhook은 검증한 뒤 Inbox 테이블에 저장하고 `202`를 반환합니다. Webhook은 플랫폼이 delivery ID를 보내면 그것으로, 없으면 내용 해시로 중복을 제거합니다.
2. 백그라운드 처리기가 Inbox를 처리하고, 실패하면 backoff(30초 → 30분, 최대 5회)로 재시도합니다.
3. SBOM은 그 프로젝트 버전의 **스냅샷**이 됩니다. 구성요소 중 언어 패키지는 OSV 미러와, OS 패키지는 Trivy 서버로 대조합니다. 대조 결과마다 권고, 영향 범위, 수정 버전을 근거로 Finding을 기록합니다. OSV 데이터가 바뀌면 저장된 스냅샷을 모두 다시 대조하므로, 새 권고가 나오면 빌드 없이도 Finding이 생깁니다.
4. 프로젝트 **이름**은 인벤토리에서 서비스로 연결되고, **버전**은 환경(`main`, `prod`. 비어 있으면 `default`)이 됩니다. 인벤토리에 없는 프로젝트는 *미등록*으로 저장됩니다. 다른 서비스로 옮긴 프로젝트는 기록과 판정을 포함해 Finding을 그대로 가져갑니다([프로젝트와 브랜치 등록](projects.ko.md)).
5. Finding 단위는 서비스 × 환경 × 구성요소 × 취약점입니다. 대표 ID는 CVE를 우선하고, GHSA·OSV ID는 별칭으로 보관합니다. OSV와 Trivy, 또는 Patchline과 Dependency-Track이 보고한 같은 취약점은 Finding 하나입니다.
6. Dependency-Track을 쓰면: `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY`는 Finding을 담고 있고, `BOM_PROCESSED`는 비교 작업을 예약하며(아래 참고), `PROJECT_AUDIT_CHANGE`(그곳의 분석 판정)는 상태를 바꿉니다. `IN_TRIAGE`·`EXPLOITABLE` → 조치중, `NOT_AFFECTED`·`FALSE_POSITIVE` → 해당 없음, Suppress → 위험 수용, `RESOLVED` → 검증대기입니다.

## 해결 판정

Finding은 누군가 닫아서가 아니라 증거로 해결됩니다.

1. 업로드할 때마다 그 프로젝트 버전의 스냅샷이 바뀝니다. 새 스냅샷에 더 이상 없는 그 프로젝트 버전의 Finding은 커밋과 ref를 근거로 **해결** 처리합니다.
2. OSV 생태계가 모두 한 번 동기화되기 전에는 대조만 하고 해결 처리는 하지 않습니다. 덜 받은 데이터를 수정으로 착각하지 않기 위해서입니다. Trivy 서버에 연결할 수 없으면 업로드를 재시도하고 그동안 해결 처리하지 않습니다.
3. 해결된 Finding이 다시 보고되면 **재발**로 바뀝니다.
4. 프로젝트 버전마다 따로 해결하므로 `main`과 `prod`는 각각 해결됩니다.
5. 판정으로 닫힌 Finding(해당 없음, 위험 수용)은 그대로 둡니다.
6. 여러 프로젝트나 출처가 보고한 Finding은 모두 보고를 멈춰야 해결됩니다.
7. Dependency-Track을 쓰면: `BOM_PROCESSED`를 받을 때 BOM의 커밋을 기록하고 `PATCHLINE_DT_RECONCILE_DELAY`만큼 기다린 뒤(Dependency-Track 4.x는 분석이 끝나기 전에 보냄) 프로젝트의 현재 Finding을 조회해 더 이상 보고되지 않는 것을 해결 처리합니다.

커밋은 SBOM `metadata`의 `patchline:git:commit`, `patchline:git:ref` 속성에서 읽습니다. 넣는 방법은 [CI의 SBOM 생성](integrations/sbom-ci.ko.md)을 참고하세요.

## PR 연결

1. Gitea, Forgejo, GitHub가 **Pull Request** 이벤트를 `/webhooks/gitea`로 보냅니다([Git Webhook](integrations/git-webhooks.ko.md) 참고).
2. PR이 열리거나 바뀌면 Renovate의 변경 표(없으면 제목 `Update dependency X to vY`)에서 업데이트 내용을 읽습니다.
3. 업데이트마다 해당 저장소의 열린 Finding과 패키지 이름으로 연결합니다(Maven `group:artifact` = `group/artifact`). 환경은 base 브랜치 이름과 같은 것, 그리고 `default`만 봅니다.
4. 목표 버전을 취약 버전 범위와 비교해 **범위를 벗어남**, **여전히 영향 있음**, 범위 정보가 없으면 **확인 불가**로 판정합니다. 범위는 로컬 OSV 미러에서 찾고, Finding을 Dependency-Track이 보고했다면 Dependency-Track에서도 찾습니다.
5. PR이 연결되면 Finding은 *조치중*, Merge되면 *검증대기*가 됩니다. Merge 없이 닫히면 기록만 하고 상태는 유지합니다. 해결 판정은 다음 SBOM에서만 합니다.

베이스 이미지 업데이트는 OS 패키지 Finding과 연결하지 않습니다. 이 경우 다음 이미지 SBOM으로 해결됩니다.

## 기한 계산

정책([예시](../examples/policy/policy.yaml))이 위험 신호를 **실효 심각도**와 기한으로 바꿉니다.

1. 스캐너의 심각도에서 시작합니다.
2. EPSS 점수가 `epss_threshold` 이상이면 한 단계 올립니다(EPSS는 Dependency-Track Finding에 함께 옵니다. Dependency-Track이 없으면 이 단계는 건너뜁니다).
3. 서비스 노출도에 따라 조정합니다(기본: `internet` +1).
4. CISA KEV에 있는 CVE는 최소 `kev` 심각도(기본 critical)로 올립니다.
5. 기한은 그 심각도의 SLA(기본 critical 7일, high 30일, medium 90일, low 180일)이고, 처음 탐지된 시각(재발 시 재발 시각)부터 셉니다.
6. 기한 연장이 승인되면, 실효 심각도가 승인 당시 수준 이하인 동안 그 날짜가 기한이 됩니다. 상향되거나 재발하면 연장은 취소됩니다.

SLA 작업은 5분마다, 그리고 수집 직후에 열린 Finding을 다시 평가합니다. 그래서 어떤 CVE가 KEV에 추가되면 이미 열려 있는 Finding도 상향되고, 스레드에 사유와 바뀐 기한이 남습니다. 기한 전에 한 번 재알림을 남기고, 기한이 지나면 반복합니다. 새 Finding은 첫 평가가 끝난 뒤에 알리므로 첫 메시지부터 기한이 보이고, 알림 기준 심각도도 실효 심각도를 씁니다.

## 알림

- `PATCHLINE_NOTIFY_MIN_SEVERITY` 이상인 Finding은 서비스의 `slack_channel`(없으면 기본 채널)에 메시지를 **하나만** 보냅니다.
- Finding이 바뀌면(상태, 심각도) 같은 메시지를 `chat.update`로 수정하고, 변경 내용을 스레드에 남깁니다.
- 진행 상황을 Finding별로 저장하므로 재시작이나 Slack 장애가 있어도 메시지가 늦어질 뿐 빠지지 않습니다. Rate limit(`429`)을 받으면 `Retry-After`만큼 쉬었다가 보냅니다.
- 알리기 전에 이미 종료된 Finding(예: 바로 해당 없음으로 판정)은 보내지 않습니다.
- [Webhook 알림](integrations/webhook-notifications.ko.md)은 같은 이벤트를 서명된 JSON으로 받습니다. Slack과 Webhook이 모두 없으면 stdout으로 출력합니다.

## 범위 밖

SBOM 생성(CI에서 함, [CI의 SBOM 생성](integrations/sbom-ci.ko.md) 참고), 자사 코드 SAST, 설정 점검, 멀티테넌시.
