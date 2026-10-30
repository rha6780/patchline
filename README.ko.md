# Patchline

**취약점이 탐지된 순간부터 배포로 해결될 때까지, 하나의 타임라인과 기한으로 추적하는 알림 오케스트레이터**

[English](README.md) | 한국어

> ⚠️ **상태: 초기 개발 중.** 탐지, Slack, Renovate PR, 재스캔 해결 판정, 기한 관리, 웹 UI가 처음부터 끝까지 동작합니다. API, 설정, 데이터 모델은 바뀔 수 있습니다.

Patchline은 [Dependency-Track](https://dependencytrack.org/) 위에서 조치 루프를 닫아 줍니다. Finding을 서비스·담당자와 연결하고, Renovate PR과 재스캔을 해결 근거로 추적하며, 수정이 배포될 때까지 Slack 메시지 하나를 계속 갱신합니다.

Patchline은 취약점을 **직접 탐지하거나 버전을 대조하지 않습니다.** 무엇이 취약한지는 Dependency-Track이 판정하고, 어떻게 고칠지는 Renovate가 제안하며, Patchline은 **실제로 고쳐졌는지, 누가, 언제까지** 고치는지를 추적합니다.

## 왜 필요한가

스캐너는 취약점을 잘 찾습니다. 보통 빠지는 건 그다음 단계입니다.

- 이 Finding의 담당자는 누구이고, 어느 Slack 채널에 알려야 하나?
- 이걸 고치는 PR이 있나? Merge됐나? Merge로 실제로 해결됐나?
- 수정이 `main`에만 있나, `prod`에도 배포됐나?
- 기한은 언제이고, 늦어진 건은 없나?

Patchline은 사람이 상태를 직접 바꾸는 대신 **증거**(Commit SHA → PR → 재스캔)로 이 질문에 답합니다.

```
CI ── SBOM + 커밋 ──▶ Dependency-Track ── webhook ──▶ Patchline ──▶ Slack, 웹 UI
                                                         ▲   ▲
Renovate ── 수정 PR ──▶ Gitea / Forgejo / GitHub ─ webhook ┘   └── 인벤토리(YAML), CISA KEV
```

취약점은 Dependency-Track, Patchline에 올린 SBOM을 [OSV](https://osv.dev)와 직접 대조한 결과, 또는 둘 다에서 들어옵니다. 같은 취약점은 Finding 하나로 합쳐집니다.

## 시작하기

Dependency-Track까지 포함한 전체 흐름을 로컬에서 돌려 볼 수 있습니다(메모리 8 GB 이상을 할당한 Docker 필요).

```sh
cp deploy/compose/.env.example deploy/compose/.env
make demo-up
```

이어서 [deploy/compose/README.md](deploy/compose/README.md)를 따라 API 키를 만들고, Dependency-Track이 Patchline으로 알림을 보내도록 설정하고, 샘플 SBOM을 올립니다. 데모 포트는 Patchline `18080`, Dependency-Track API `18081`, UI `18082`입니다.

서버나 로컬 PC에 설치하려면 [deploy/self-hosted](deploy/self-hosted/README.ko.md)를 쓰세요. 이미 있는 Dependency-Track에 연결하거나 둘을 함께 띄울 수 있고, 인벤토리와 설정은 `.env`로 지정합니다.

```sh
cd deploy/self-hosted
cp .env.example .env               # PATCHLINE_WEBHOOK_TOKEN, Dependency-Track 주소와 키 설정
docker compose up -d --build
```

또는 바이너리(Go 버전은 [`go.mod`](go.mod) 참고)나 컨테이너 이미지를 직접 실행할 수도 있습니다.

```sh
make build && ./bin/patchline       # http://localhost:8080, SQLite는 data/에 저장

docker build -t patchline .
docker run -p 8080:8080 -v patchline-data:/data patchline
```

`admin` / `admin`으로 로그인해 새 비밀번호를 정하세요. 다른 사람은 SSO로 로그인하게 연결합니다([로그인과 권한](docs/access-control.ko.md)).

그다음 인벤토리를 만들고 도구를 연결합니다.

1. 서비스, 담당자, Slack 채널, 저장소를 인벤토리([예시](examples/inventory/services.yaml))에 적고 `PATCHLINE_INVENTORY_PATH`를 설정합니다.
2. [Dependency-Track](docs/integrations/dependency-track.ko.md), [CI의 SBOM 생성](docs/integrations/sbom-ci.ko.md), [Renovate](docs/integrations/renovate.ko.md)와 [Git Webhook](docs/integrations/git-webhooks.ko.md), [Slack](docs/integrations/slack.ko.md)을 연결합니다.

## 문서

- [동작 방식](docs/how-it-works.ko.md) — Finding 상태, 해결 판정, PR 연결, 기한, 알림
- [설정](docs/configuration.ko.md) — 환경변수, 엔드포인트, 웹 UI
- [로그인과 권한](docs/access-control.ko.md) — OIDC 로그인, 그룹별 권한(담당자 지정, 예외 요청·승인, Webhook 설정)
- [연동 가이드](docs/README.ko.md) — Dependency-Track, CI의 SBOM 생성, Renovate, Gitea / Forgejo / GitHub, Slack, CISA KEV·EPSS

## 기여하기

이슈와 Pull Request를 환영합니다. 개발 환경, 검사, 규칙은 [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)에 있습니다. 보안 문제는 공개 이슈 대신 비공개로 제보해 주세요.

## 라이선스

[Apache-2.0](LICENSE). [NOTICE](NOTICE)도 함께 확인하세요.

Patchline은 Dependency-Track과 연동되지만 OWASP 또는 Dependency-Track 프로젝트와 관련이 없으며 보증받지 않았습니다.
