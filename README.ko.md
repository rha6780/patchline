# Patchline

**취약점이 탐지된 순간부터 배포로 해결될 때까지, 하나의 타임라인과 기한으로 추적하는 알림 오케스트레이터**

[English](README.md) | 한국어

> ⚠️ **상태: 초기 개발 중(M0).** 아직 사용할 수 있는 기능이 없습니다. API, 설정, 데이터 모델은 바뀔 수 있습니다.

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

## 기능 (예정)

- **Git이 원천** — 서비스, 담당자, 채널, 정책을 YAML로 관리하고 PR로 변경
- **증거 기반 해결 판정** — 새 SBOM에서 Finding이 사라져야 해결로 처리. `main`과 `prod`를 따로 추적
- **Renovate PR 연결** — PR 열림 → *조치중*, Merge → *검증대기*. PR의 목표 버전이 실제로 취약점을 고치는지도 확인
- **Finding 1건 = 메시지 1개** — Slack 메시지를 `chat.update`로 갱신하고 이력은 스레드에 남김
- **정책을 코드로** — CVSS, CISA KEV, EPSS, 서비스 노출도로 등급과 기한을 계산
- **만료가 있는 예외** — 위험 수용이 만료되면 자동으로 다시 열림
- **Gitea / Forgejo 우선 지원**
- **가벼움** — 바이너리(또는 컨테이너) 1개, 기본 SQLite, 선택적으로 PostgreSQL

### Finding 상태

| 상태 | 전이 조건 |
|---|---|
| `needs_review` (확인 필요) | 구성요소 버전을 알 수 없거나 CPE 매칭이 불확실 |
| `new` (신규) | Dependency-Track에서 새 Finding 발생 |
| `in_progress` (조치중) | 담당자 판정 또는 연결된 수정 PR 열림 |
| `awaiting_verification` (검증대기) | 수정 PR Merge |
| `resolved` (해결) | 새 SBOM에서 Finding이 사라짐(`main` → `prod`) |
| `not_affected` (해당 없음) | 분석 결과 `NOT_AFFECTED` / `FALSE_POSITIVE` |
| `risk_accepted` (위험 수용) | 승인자와 만료일을 지정해 Suppress |
| `reopened` (재발) | 해결된 Finding이 다시 나타남 |

사람의 판정은 **한 곳에서만** 받습니다(Dependency-Track Analysis, 또는 DT API를 호출하는 Patchline UI). Gitea 이슈는 쓰기 전용 미러입니다.

### Web UI

UI는 조회 위주입니다. 설정은 Git에서, 상세 분석은 Dependency-Track에서 합니다.

| 화면 | 보여주는 것 |
|---|---|
| Overview | 서비스 × 등급 매트릭스, 기한 초과·임박 건, MTTR |
| Service | 기술 스택 요약, `main`과 `prod`의 차이, 열린 Finding |
| Finding 타임라인 | 탐지 → 알림 → PR → Merge → 재스캔 → 배포 → 해결 |
| Integrations & Health | 프로젝트별 마지막 SBOM, 마지막 Renovate 실행, 미등록 저장소, 발송 실패 |
| Exceptions | 위험 수용·해당 없음 판정, 만료 임박 건 |

## 로드맵

| 마일스톤 | 범위 |
|---|---|
| **M0** 뼈대 | 모듈 구조, 설정, SQLite + 마이그레이션, `/healthz`, Compose 데모(DT + Patchline) |
| **M1** 수집 | DT Webhook → Inbox → 인벤토리와 연결된 Finding 생성 |
| **M2** 알림 | Slack 최초 알림, 메시지 갱신, 스레드 이력, Console Sink |
| **M3** 해결 판정 | 재스캔 diff → 해결·재발, Commit SHA 기록 |
| **M4** PR 연결 | Gitea Webhook, Renovate PR ↔ Finding, "이 PR로 고쳐지는가" 판정 |
| **M5** UI | Overview, Finding 타임라인 |
| 이후 | SLA 재알림, 예외 만료, `prod` 배포 근거, Gitea 이슈 Sink, OpenCVE 수집원 |

## 기술 스택

| 영역 | 선택 |
|---|---|
| 언어 | Go |
| HTTP | `net/http` (Go 1.22+ 라우팅) |
| UI | `templ` + HTMX |
| DB | SQLite(`modernc.org/sqlite`) / PostgreSQL(`pgx`), `sqlc`, `goose` |
| 스케줄러 | `gocron` |
| 연동 | Gitea SDK, `slack-go/slack`, 얇은 Dependency-Track 클라이언트 |
| 식별자 | `packageurl-go`, 생태계별 버전 비교 라이브러리 |
| 로깅 | `log/slog` |
| 릴리스 | GoReleaser |

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
│   ├── source/             # 입력: dependencytrack, gitea, jenkins
│   ├── sink/               # 출력: slack, giteaissue, console
│   ├── store/              # 저장소 + 마이그레이션
│   ├── job/                # 스케줄 작업(재알림, 만료, heartbeat)
│   └── web/                # templ 템플릿 + 정적 파일
├── examples/               # 샘플 인벤토리, 정책, SBOM
├── deploy/compose/         # docker compose 데모
└── docs/
```

## 시작하기

아직 준비 중입니다. 지금은 뼈대만 빌드하고 실행할 수 있습니다.

```sh
go build -o bin/patchline ./cmd/patchline
./bin/patchline            # :8080에서 실행, GET /healthz
```

Dependency-Track과 샘플 SBOM이 포함된 `docker compose up` 데모는 M0에서 추가할 예정입니다.

## 범위 밖

스캐너 실행, 버전 범위 대조(Dependency-Track에 위임), 자사 코드 SAST, 설정 점검, 멀티테넌시.

## 라이선스

[Apache-2.0](LICENSE)

Patchline은 Dependency-Track과 연동되지만 OWASP 또는 Dependency-Track 프로젝트와 관련이 없으며 보증받지 않았습니다.
