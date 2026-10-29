# Patchline

**취약점이 탐지된 순간부터 배포로 해결될 때까지, 하나의 타임라인과 기한으로 추적하는 알림 오케스트레이터**

[English](README.md) | 한국어

> ⚠️ **상태: 초기 개발 중.** 탐지, Slack, Renovate PR, 재스캔 해결 판정, 웹 UI까지 MVP 흐름이 처음부터 끝까지 동작합니다. 다만 `v0.1.0` 전까지 API, 설정, 데이터 모델은 바뀔 수 있습니다. API, 설정, 데이터 모델은 바뀔 수 있습니다.

Patchline은 [Dependency-Track](https://dependencytrack.org/) 위에서 조치 루프를 닫아 줍니다. Finding을 서비스·담당자와 연결하고, Renovate PR과 배포를 해결 근거로 추적하며, 수정이 배포될 때까지 Slack 메시지 하나를 계속 갱신합니다.

Patchline은 취약점을 **직접 탐지하거나 버전을 대조하지 않습니다.** 무엇이 취약한지는 Dependency-Track이 판정하고, 어떻게 고칠지는 Renovate가 제안하며, Patchline은 **실제로 고쳐졌는지, 누가, 언제까지** 고치는지를 추적합니다.

## 왜 필요한가

스캐너는 취약점을 잘 찾습니다. 보통 빠지는 건 그다음 단계입니다.

- 이 Finding의 담당자는 누구이고, 어느 Slack 채널에 알려야 하나?
- 이걸 고치는 PR이 있나? Merge됐나? Merge로 실제로 해결됐나?
- 수정이 `main`에만 있나, `prod`에도 배포됐나?
- 기한은 언제이고, 늦어진 건은 없나?

Patchline은 사람이 상태를 직접 바꾸는 대신 **증거**(Commit SHA → PR → 재스캔 → 이미지 Digest)로 이 질문에 답합니다.

## 동작 방식

```
서비스 저장소(Gitea) ── CI: SBOM (main) ──┐
배포 파이프라인      ── 이미지 SBOM (prod) ┼──▶ Dependency-Track ── webhook ──┐
인벤토리(manual)     ── CPE SBOM ──────────┘                                  │
                                                                              ▼
Renovate ── 보안 PR ── Gitea webhook ────────────────────────────────▶  Patchline  ◀── 인벤토리(Git, YAML)
배포 파이프라인 ── 배포 webhook (SHA, digest) ───────────────────────▶      │
                                                         ┌──────────────────┼──────────────────┐
                                                    Slack(Bot)        Gitea 이슈             Web UI
```

| 도구 | 역할 |
|---|---|
| **Dependency-Track** | SBOM 구성요소(purl / CPE)를 NVD·GHSA·OSV와 대조하고 분석 판정을 저장 |
| **Renovate** | 수정 PR 생성(의존성 업데이트, 베이스 이미지 Digest 갱신) |
| **Patchline** | Finding을 인벤토리와 연결하고, SLA를 계산하고, 알림을 보내고, 증거로 상태를 추적 |

호스트에 설치된 인프라 제품까지 보려면 나중에 OpenCVE를 수집원으로 추가할 수 있습니다.

## 기능

- **Git이 원천** — 서비스, 담당자, 채널, 저장소를 YAML로 관리
- **증거 기반 해결 판정** — 새 BOM에서 사라져야 해결로 처리하고 커밋을 근거로 남김. 다시 나타나면 재발. `main`과 `prod`를 따로 추적
- **Renovate PR 연결** — PR 열림 → *조치중*, Merge → *검증대기*. 목표 버전이 취약 범위를 벗어나는지 확인
- **Finding 1건 = 메시지 1개** — Slack 메시지를 `chat.update`로 수정하고 이력은 스레드에 남김
- **정책 기반 SLA** — 실효 심각도별 기한. CISA KEV, EPSS, 서비스 노출도로 상향. 기한 전과 초과 후 재알림
- **조회용 웹 UI** — 기한 초과 건수를 포함한 Overview, 서비스별 환경 비교, 근거 타임라인, 연동 상태
- **Gitea / Forgejo 우선 지원**(GitHub Webhook도 동작)
- **가벼움** — SQLite를 쓰는 바이너리(또는 컨테이너) 1개

예정: 만료가 있는 위험 수용, 운영 배포 근거, Gitea 이슈 미러, OpenCVE 수집원, PostgreSQL.

### Finding 상태

| 상태 | 전이 조건 |
|---|---|
| `needs_review` (확인 필요) | 구성요소 버전을 알 수 없거나 CPE 매칭이 불확실(예약) |
| `new` (신규) | Dependency-Track에서 새 Finding 발생 |
| `in_progress` (조치중) | 분석이 In Triage·Exploitable이거나 수정 PR이 연결됨 |
| `awaiting_verification` (검증대기) | 수정 PR Merge, 또는 분석이 Resolved |
| `resolved` (해결) | 프로젝트의 최신 BOM에서 더 이상 보고되지 않음 |
| `not_affected` (해당 없음) | 분석 결과 `NOT_AFFECTED` / `FALSE_POSITIVE` |
| `risk_accepted` (위험 수용) | Dependency-Track에서 Suppress |
| `reopened` (재발) | 해결된 Finding이 다시 보고됨 |

사람의 판정은 **한 곳에서만** 받습니다. Dependency-Track 분석입니다.

## 로드맵

| 마일스톤 | 범위 |
|---|---|
| ✅ **M0** 뼈대 | 모듈 구조, 설정, SQLite + 마이그레이션, `/healthz`, Compose 데모(DT + Patchline) |
| ✅ **M1** 수집 | DT Webhook → Inbox → 인벤토리와 연결된 Finding 생성 |
| ✅ **M2** 알림 | Slack 최초 알림, 메시지 갱신, 스레드 이력, Console Sink |
| ✅ **M3** 해결 판정 | 재스캔 diff → 해결·재발, Commit SHA 기록 |
| ✅ **M4** PR 연결 | Gitea Webhook, Renovate PR ↔ Finding, "이 PR로 고쳐지는가" 판정 |
| ✅ **M5** UI | Overview, Finding 타임라인 |
| ✅ SLA | 정책 기반 기한(KEV, EPSS, 노출도)과 재알림 |
| 이후 | 예외 만료, `prod` 배포 근거, Gitea 이슈 Sink, OpenCVE 수집원 |

## 기술 스택

| 영역 | 선택 |
|---|---|
| 언어 | Go |
| HTTP | `net/http` (Go 1.22+ 라우팅) |
| UI | `html/template` 서버 렌더링, JavaScript 없음 |
| DB | SQLite(`ncruces/go-sqlite3`, 순수 Go, cgo 없음), 마이그레이션은 `goose` |
| 설정 | 환경변수, 인벤토리는 YAML(`go.yaml.in/yaml/v3`) |
| 백그라운드 작업 | 프로세스 내 워커: Inbox 처리기와 Notifier(큐·Redis 없음) |
| 연동 | 표준 라이브러리 기반의 작은 HTTP 클라이언트(Dependency-Track, Slack Web API) |
| 버전 비교 | Maven, npm, PyPI, Go 형식을 다루는 자체 best-effort 비교 |
| 로깅 | `log/slog` |
| 컨테이너 | distroless, non-root |

## 레포 구조

```
patchline/
├── cmd/patchline/          # 진입점
├── internal/
│   ├── config/             # 환경변수 + YAML 설정
│   ├── server/             # HTTP: Webhook Inbox, 내부 API, UI 라우트
│   ├── finding/            # 모델, 상태 전이, 이벤트 로그
│   ├── policy/             # 등급 + SLA 규칙
│   ├── inventory/          # Git으로 관리하는 서비스 인벤토리
│   ├── intake/             # Inbox 처리기: Webhook 수신분 → Finding
│   ├── notify/             # Notifier: Finding당 메시지 1개, 갱신, 스레드 이력
│   ├── source/             # 입력: dependencytrack, gitea, jenkins
│   ├── sink/               # 출력: slack, giteaissue, console
│   ├── store/              # 저장소 + 마이그레이션
│   ├── version/            # 생태계 공통 버전 비교(best-effort)
│   ├── job/                # 스케줄 작업(재알림, 만료, heartbeat)
│   └── web/                # 서버 렌더링 화면 + 내장 CSS
├── examples/               # 샘플 인벤토리, 정책, SBOM
├── deploy/compose/         # docker compose 데모
└── docs/
```

## 시작하기

```sh
make build && ./bin/patchline     # :8080
make demo-up                      # docker compose로 Dependency-Track + Patchline 실행
```

데모 진행 순서(API 키, Webhook 설정, 샘플 SBOM 업로드)는 [deploy/compose/README.md](deploy/compose/README.md)에 있습니다.
데모 포트는 Patchline `18080`, Dependency-Track API `18081`, UI `18082`입니다(`deploy/compose/.env`에서 변경).

### 웹 UI

`http://localhost:8080/`(데모는 `:18080`)으로 접속합니다. 자체 로그인이 없으므로 인증 프록시 뒤에 두세요.

| 화면 | 경로 |
|---|---|
| Overview: 열린 Finding, 서비스 × 심각도, 조치 필요 건, 최근 해결, MTTR | `/` |
| Finding 목록(필터) | `/findings` |
| Finding 상세: 정보, 수정 PR, 근거 타임라인 | `/findings/{id}` |
| 서비스: 담당자, 저장소, 환경별 Finding(`main`에서는 해결됐지만 `prod`에 남은 건 강조) | `/services/{name}` |
| Integrations: DT 프로젝트별 마지막 BOM·커밋, BOM이 없는 인벤토리 프로젝트, 실패한 Webhook·알림 | `/integrations` |

### 엔드포인트

| 메서드 | 경로 | 용도 |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness(DB) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track Outbound Webhook(`?token=` 또는 `Authorization: Bearer`) |
| `POST` | `/webhooks/gitea` | Gitea / Forgejo / GitHub `pull_request` Webhook(HMAC 서명 또는 토큰) |
| `GET` | `/api/v1/findings` | 담당자 정보를 포함한 Finding 목록. 필터 `service`, `environment`, `state`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | Finding 타임라인 |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Finding에 연결된 PR |

### 설정

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `PATCHLINE_ADDR` | `:8080` | 수신 주소 |
| `PATCHLINE_DB_PATH` | `data/patchline.db` | SQLite 파일 |
| `PATCHLINE_INVENTORY_PATH` | — | 인벤토리 YAML 파일 또는 디렉터리([예시](examples/inventory/services.yaml)) |
| `PATCHLINE_WEBHOOK_TOKEN` | — | Webhook 공유 비밀값. 비우면 인증 없음(개발용) |
| `PATCHLINE_DT_URL` | — | Dependency-Track API 서버 URL |
| `PATCHLINE_DT_API_KEY` | — | `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` 권한의 API 키 |
| `PATCHLINE_GITEA_WEBHOOK_SECRET` | — | PR Webhook의 Secret. 비우면 `PATCHLINE_WEBHOOK_TOKEN` 사용 |
| `PATCHLINE_DT_UI_URL` | — | 메시지에 넣을 Dependency-Track UI 주소 |
| `PATCHLINE_DT_RECONCILE_DELAY` | `2m` | `BOM_PROCESSED` 이후 Finding을 비교하기 전 대기 시간 |
| `PATCHLINE_POLICY_PATH` | — | 조치 정책 YAML([예시](examples/policy/policy.yaml)). 비우면 기본값 |
| `PATCHLINE_KEV_URL` | CISA 피드 | CISA KEV 카탈로그 주소(하루 한 번 갱신). `off`면 사용 안 함 |
| `PATCHLINE_SLACK_BOT_TOKEN` | — | Slack Bot 토큰(`chat:write`, `chat:write.public`). 비우면 stdout으로 출력 |
| `PATCHLINE_SLACK_DEFAULT_CHANNEL` | — | `slack_channel`이 없는 서비스와 미등록 프로젝트용 채널 |
| `PATCHLINE_NOTIFY_MIN_SEVERITY` | `medium` | 알림을 보낼 최소 심각도 |
| `PATCHLINE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PATCHLINE_LOG_FORMAT` | `text` | `text` 또는 `json` |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` | 정상 종료 제한 시간 |

### 수집 동작 방식

1. Webhook 핸들러는 payload를 검증해 Inbox 테이블에 저장하고(내용 해시로 중복 제거) `202`를 반환합니다.
2. 백그라운드 처리기가 Inbox를 처리하고, 실패하면 backoff(30초 → 30분, 최대 5회)로 재시도합니다.
3. `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY`는 Finding을 직접 담고 있고, `BOM_PROCESSED`를 받으면 해당 프로젝트의 비교 작업을 예약합니다(아래 참고).
4. Dependency-Track 프로젝트 **이름**은 인벤토리에서 서비스로 연결되고, **버전**은 환경(`main`, `prod`)이 됩니다. 인벤토리에 없는 프로젝트는 *미등록*으로 저장됩니다.
5. Finding 단위는 서비스 × 환경 × 구성요소 × 취약점입니다. 대표 ID는 CVE를 우선하고, GHSA·OSV ID는 별칭으로 보관합니다.
6. `PROJECT_AUDIT_CHANGE`(Dependency-Track의 분석 판정)를 받으면 Finding 상태가 바뀝니다. `IN_TRIAGE`·`EXPLOITABLE` → 조치중, `NOT_AFFECTED`·`FALSE_POSITIVE` → 해당 없음, Suppress → 위험 수용, `RESOLVED` → 검증대기(이후 재스캔으로 확인)입니다.

### 해결 판정 방식

Finding은 누군가 닫아서가 아니라 증거로 해결됩니다.

1. `BOM_PROCESSED`를 받으면 BOM의 커밋과 ref를 기록하고, `PATCHLINE_DT_RECONCILE_DELAY` 뒤에 비교 작업을 예약합니다. (Dependency-Track 4.x는 새 구성요소 분석이 끝나기 전에 `BOM_PROCESSED`를 보내기 때문에, 바로 조회하면 결과가 불완전합니다.)
2. 비교 작업은 Dependency-Track API로 프로젝트의 현재 Finding을 조회합니다. 그 프로젝트의 Finding 중 더 이상 보고되지 않는 것은 커밋, ref, BOM serial을 근거로 **해결** 처리합니다.
3. 해결된 Finding이 다시 보고되면(이후 BOM 또는 `NEW_VULNERABILITY` 알림) **재발**로 바뀝니다.
4. Dependency-Track 프로젝트 버전마다 따로 비교하므로 `main`과 `prod`는 각각 해결됩니다.
5. 판정으로 닫힌 Finding(해당 없음, 위험 수용)은 그대로 둡니다.

커밋을 남기려면 업로드하기 전에 BOM의 `metadata`에 아래 속성을 추가하세요.

```sh
jq --arg c "$GITHUB_SHA" --arg r "$GITHUB_REF" \
  '.metadata.properties += [{"name":"patchline:git:commit","value":$c},{"name":"patchline:git:ref","value":$r}]' \
  bom.json > bom.patchline.json
```

### PR 연결 방식

1. Gitea, Forgejo, GitHub의 저장소(또는 조직)에 **Pull Request** 이벤트 Webhook을 추가합니다. 주소는 `/webhooks/gitea`, Secret은 `PATCHLINE_GITEA_WEBHOOK_SECRET`입니다.
2. PR이 열리거나 바뀌면 Renovate의 변경 표(없으면 제목 `Update dependency X to vY`)에서 업데이트 내용을 읽습니다.
3. 업데이트마다 해당 저장소의 열린 Finding과 패키지 이름으로 연결합니다(Maven `group:artifact` = `group/artifact`). 환경은 base 브랜치 이름과 같은 것만 봅니다.
4. 목표 버전을 Dependency-Track의 취약 버전 범위와 비교해 **범위를 벗어남**, **여전히 영향 있음**, 범위 정보가 없으면 **확인 불가**로 판정합니다.
5. PR이 연결되면 Finding은 *조치중*, Merge되면 *검증대기*가 됩니다. Merge 없이 닫히면 기록만 하고 상태는 유지합니다. 해결 판정은 다음 재스캔에서만 합니다.

베이스 이미지 업데이트는 아직 OS 패키지 Finding과 연결하지 않습니다. 이 경우에도 재스캔으로 해결됩니다.

### 기한 계산 방식

정책([예시](examples/policy/policy.yaml))이 위험 신호를 **실효 심각도**와 기한으로 바꿉니다.

1. 스캐너의 심각도에서 시작합니다.
2. EPSS 점수(Dependency-Track 제공)가 `epss_threshold` 이상이면 한 단계 올립니다.
3. 서비스 노출도에 따라 조정합니다(기본: `internet` +1).
4. CISA KEV에 있는 CVE는 최소 `kev` 심각도(기본 critical)로 올립니다.
5. 기한은 그 심각도의 SLA(기본 critical 7일, high 30일, medium 90일, low 180일)이고, 처음 탐지된 시각(재발 시 재발 시각)부터 셉니다.

SLA 작업은 5분마다, 그리고 수집 직후에 열린 Finding을 다시 평가합니다. 그래서 어떤 CVE가 KEV에 추가되면 이미 열려 있는 Finding도 상향되고, 스레드에 사유와 바뀐 기한이 남습니다. 기한 전에 한 번 재알림을 남기고, 기한이 지나면 반복합니다. 새 Finding은 첫 평가가 끝난 뒤에 알리므로 첫 메시지부터 기한이 보이고, 알림 기준 심각도도 실효 심각도를 씁니다.

### 알림 동작 방식

- `PATCHLINE_NOTIFY_MIN_SEVERITY` 이상인 Finding은 서비스의 `slack_channel`(없으면 기본 채널)에 메시지를 **하나만** 보냅니다.
- Finding이 바뀌면(상태, 심각도) 같은 메시지를 `chat.update`로 수정하고, 변경 내용을 스레드에 남깁니다.
- 진행 상황을 Finding별로 저장하므로 재시작이나 Slack 장애가 있어도 메시지가 늦어질 뿐 빠지지 않습니다. Rate limit(`429`)을 받으면 `Retry-After`만큼 쉬었다가 보냅니다.
- 알리기 전에 이미 종료된 Finding(예: 바로 해당 없음으로 판정)은 보내지 않습니다.
- Slack 토큰이 없으면 같은 내용을 stdout으로 출력합니다.

## 범위 밖

스캐너 실행, 버전 범위 대조(Dependency-Track에 위임), 자사 코드 SAST, 설정 점검, 멀티테넌시.

## 라이선스

[Apache-2.0](LICENSE)

Patchline은 Dependency-Track과 연동되지만 OWASP 또는 Dependency-Track 프로젝트와 관련이 없으며 보증받지 않았습니다.
