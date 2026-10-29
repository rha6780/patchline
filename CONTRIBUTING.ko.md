# Patchline 기여 가이드

[English](CONTRIBUTING.md) | 한국어

Patchline에 관심 가져 주셔서 고맙습니다. 버그 제보, 문서 수정, Pull Request 모두 환영합니다.

## 시작하기 전에

- **버그**: 무엇을 했는지, 무엇을 기대했는지, 실제로 어떻게 됐는지를 이슈로 남겨 주세요. Patchline 버전(`git describe`), Dependency-Track 버전, 관련 로그(`PATCHLINE_LOG_LEVEL=debug`)를 함께 적어 주세요. 토큰, 호스트 이름 같은 내부 정보는 지워 주세요.
- **기능 추가나 큰 변경**: 코드를 작성하기 전에 먼저 이슈를 열어 방향을 맞춰 주세요. [범위 밖](docs/how-it-works.ko.md#범위-밖) 항목도 확인해 주세요.
- **보안 문제**: 공개 이슈로 올리지 말고, GitHub의 **Security → Report a vulnerability**로 비공개 제보해 주세요.

## 개발 환경

Go([`go.mod`](go.mod)에 적힌 버전)가 필요하고, 데모를 돌리려면 메모리 8 GB 이상을 할당한 Docker가 필요합니다.

```sh
git clone https://github.com/rha6780/patchline.git
cd patchline
make build && ./bin/patchline    # :8080, 별도 설정 없이 실행
make test
```

Dependency-Track까지 포함한 전체 흐름은 [Compose 데모](deploy/compose/README.md)(`make demo-up`)로 확인할 수 있습니다.

| 명령 | |
|---|---|
| `make build` | `bin/patchline` 빌드 |
| `make run` | 빌드 후 실행 |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make docker` | 컨테이너 이미지 빌드 |
| `make demo-up` / `demo-down` / `demo-logs` | Compose 데모 |

## Pull Request

1. 저장소를 Fork하고 `main`에서 브랜치를 만듭니다.
2. Pull Request 하나에는 변경 하나만 담습니다. 동작이 바뀌면 테스트를 추가하거나 고칩니다.
3. Push하기 전에 CI와 같은 검사를 돌립니다.

   ```sh
   gofmt -l .            # 아무것도 출력되지 않아야 함
   go vet ./...
   go test -race ./...
   ```

4. 커밋 메시지는 기존 이력처럼 [Conventional Commits](https://www.conventionalcommits.org/ko/) 형식(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`)으로, 짧은 명령형 요약을 영어로 씁니다.
5. Pull Request에는 무엇을 왜 바꿨는지 적고 관련 이슈를 연결합니다.

### 문서와 번역

문서와 UI 문구는 영어와 한국어로 관리합니다.

- 문서를 고치면 `*.md`와 `*.ko.md`를 함께 고쳐 주세요. 한 언어만 쓸 수 있다면 Pull Request에 적어 주세요. 리뷰에서 번역합니다.
- UI와 Slack 문구는 [`internal/i18n/catalog.go`](internal/i18n/catalog.go)에 있습니다. 새 키는 두 언어 모두 추가해 주세요.
- 설정이 바뀌면 [docs/configuration.ko.md](docs/configuration.ko.md)를, 동작이 바뀌면 [docs/how-it-works.ko.md](docs/how-it-works.ko.md)나 [연동 가이드](docs/README.ko.md)를 고쳐 주세요.

## 프로젝트 구조

```
patchline/
├── cmd/patchline/          # 진입점
├── internal/
│   ├── config/             # 환경변수
│   ├── server/             # HTTP: Webhook Inbox, 내부 API, UI 라우트
│   ├── finding/            # 모델, 상태 전이, 이벤트 로그
│   ├── policy/             # 등급 + SLA 규칙
│   ├── inventory/          # Git으로 관리하는 서비스 인벤토리
│   ├── i18n/               # 영어·한국어 문구
│   ├── intake/             # Inbox 처리기: Webhook 수신분 → Finding
│   ├── notify/             # Notifier: Finding당 메시지 1개, 갱신, 스레드 이력
│   ├── source/             # 입력: dependencytrack, gitea, kev
│   ├── sink/               # 출력: slack, console
│   ├── store/              # 저장소 + 마이그레이션
│   ├── version/            # 생태계 공통 버전 비교(best-effort)
│   ├── job/                # 스케줄 작업: SLA 평가, 재알림, KEV 갱신
│   └── web/                # 서버 렌더링 화면 + 내장 CSS
├── examples/               # 샘플 인벤토리, 정책, SBOM
├── deploy/compose/         # docker compose 데모
├── deploy/self-hosted/     # 직접 설치용 docker compose(온프렘, 로컬)
└── docs/                   # 동작 방식, 설정, 연동 가이드
```

### 기술 스택

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

새 의존성은 꼭 필요할 때만 추가하고, 가능하면 표준 라이브러리를 씁니다. DB 변경은 `internal/store/migrations/`에 새 마이그레이션으로 추가하고, 기존 마이그레이션은 고치지 않습니다.

## 라이선스

기여한 내용은 프로젝트와 같은 [Apache License 2.0](LICENSE)으로 배포되는 데 동의한 것으로 봅니다.
