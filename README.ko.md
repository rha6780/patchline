# Patchline

**취약점이 발견된 순간부터 수정이 배포될 때까지, 하나의 타임라인과 기한, 하나의 Slack 스레드로 추적합니다.**

[English](README.md) | 한국어

> ⚠️ **상태: 초기 개발 중.** 탐지, 알림, Renovate PR 추적, 재스캔으로 해결 판정, 기한 관리, 웹 UI까지 전체 흐름이 동작합니다. API, 설정, 데이터 모델은 바뀔 수 있습니다.

스캐너는 무엇이 취약한지 알려 줍니다. Patchline은 그다음을 추적합니다. 각 Finding의 담당자가 누구인지, 어떤 PR이 고치는지, 그 수정으로 취약점이 실제로 사라졌는지, 기한 안에 운영 환경까지 배포됐는지를 확인합니다.

## 주요 기능

- **탐지**: CI가 빌드마다 올리는 SBOM을 로컬 [OSV](https://osv.dev) 미러(언어 패키지)와 [Trivy](https://trivy.dev) 서버(이미지의 OS 패키지)로 대조합니다.
- **담당 지정**: YAML 인벤토리를 바탕으로 Finding마다 서비스, 담당자, Slack 채널을 연결합니다.
- **수정 추적**: Gitea, Forgejo, GitHub의 Renovate PR을 연결하고, 이후 SBOM에서 취약점이 사라졌을 때만 해결로 판정합니다.
- **기한 관리**: 심각도, 노출 범위, CISA KEV를 바탕으로 기한을 정하고, 기한 전후로 알려 줍니다.
- **알림**: Finding마다 Slack 메시지 하나를 수정이 배포될 때까지 계속 갱신합니다. 서명된 Webhook으로도 보낼 수 있습니다.
- **예외 처리**: 해당 없음, 오탐, 위험 수용, 기한 연장을 요청하면 다른 사람이 승인하고, 결정은 VEX로 내보냅니다.
- **자체 점검**: Patchline 자신의 의존성도 대조해, 업그레이드가 필요하면 알려 줍니다.

어떻게 고칠지는 Renovate가 제안하고, Patchline은 **실제로 고쳐졌는지, 누가, 언제까지** 고치는지를 추적합니다. [Dependency-Track](https://dependencytrack.org/)은 선택 사항입니다. 연결하면 Finding의 두 번째 출처가 되고, 승인된 결정은 Dependency-Track에도 기록됩니다.

## 왜 필요한가

취약점을 찾는 것은 쉬운 단계입니다. 보통 놓치는 것은 그 이후입니다.

- 이 Finding의 담당자는 누구이고, 어느 Slack 채널에 알려야 하나?
- 이걸 고치는 PR이 있나? Merge됐나? Merge로 실제로 해결됐나?
- 수정이 `main`에만 있나, `prod`에도 배포됐나?
- 기한은 언제이고, 기한을 넘긴 건은 없나?

Patchline은 사람이 상태를 직접 바꾸는 대신 **근거**(Commit SHA → PR → 재스캔)로 이 질문에 답합니다.

```
CI ── SBOM + 커밋 ──▶ Patchline ──▶ Slack, Webhook, 웹 UI
                        │   ▲
   OSV 미러, Trivy ◀────┘   ├── 수정 PR: Renovate → Gitea / Forgejo / GitHub Webhook
   (대조)                   ├── 인벤토리(YAML), CISA KEV
                            └── Dependency-Track Webhook(선택)
```

Dependency-Track도 연결하면, 양쪽에서 보고한 같은 취약점은 Finding 하나로 합쳐집니다.

## 시작하기

로컬에서 1분 정도면 실행해 볼 수 있습니다(Docker, `curl`, `jq` 필요).

```sh
make demo-up      # Patchline + Trivy 서버
make demo-seed    # 샘플 SBOM 업로드, Patchline이 OSV와 Trivy로 대조
```

http://localhost:18080에 접속하세요. Finding 둘러보기, 구성요소 검색, 수정 후 해결되는 과정, Dependency-Track 추가 방법(`make demo-up PROFILE=dependency-track && make demo-seed-dt`)은 [deploy/compose/README.md](deploy/compose/README.md)에서 안내합니다.

서버나 내 PC에 설치하려면 [deploy/self-hosted](deploy/self-hosted/README.ko.md)를 사용하세요. Patchline과 Trivy 서버를 함께 띄우고, 인벤토리와 설정은 `.env`에서 읽습니다. 필요하면 Dependency-Track도 함께 띄울 수 있습니다.

```sh
cd deploy/self-hosted
cp .env.example .env               # PATCHLINE_WEBHOOK_TOKEN, TRIVY_TOKEN 설정
docker compose up -d --build
```

바이너리(Go 버전은 [`go.mod`](go.mod) 참고)나 컨테이너 이미지를 직접 실행해도 됩니다.

```sh
make build && ./bin/patchline       # http://localhost:8080, SQLite는 data/에 저장

docker build -t patchline .
docker run -p 8080:8080 -v patchline-data:/data patchline
```

처음 실행하면 Patchline이 `admin` 계정의 일회용 비밀번호를 로그에 출력합니다(Docker Compose에서는 `docker compose logs patchline | grep one-time`). 이 비밀번호로 로그인해 새 비밀번호를 정한 뒤, 다른 사람들은 SSO로 로그인하도록 설정하세요([로그인과 권한](docs/access-control.ko.md)).

그다음 서비스를 등록하고 도구를 연결합니다.

1. 서비스, 담당자, Slack 채널, 저장소를 인벤토리([예시](examples/inventory/services.yaml))에 적고 `PATCHLINE_INVENTORY_PATH`로 지정합니다([프로젝트와 브랜치 등록](docs/projects.ko.md)).
2. CI가 빌드마다 [SBOM을 올리도록](docs/integrations/sbom-ci.ko.md) 설정합니다.
3. [Git Webhook](docs/integrations/git-webhooks.ko.md)으로 [Renovate](docs/integrations/renovate.ko.md)를 연결하고, [Slack](docs/integrations/slack.ko.md)도 연결합니다.
4. 필요하면 [Dependency-Track](docs/integrations/dependency-track.ko.md)을 두 번째 출처로 추가합니다.

## 문서

- [동작 방식](docs/how-it-works.ko.md) — Finding 상태, 해결 판정, PR 연결, 기한, 알림
- [프로젝트와 브랜치 등록](docs/projects.ko.md) — 서비스, 프로젝트 이름, 환경으로 쓰이는 버전, 브랜치와 커밋
- [설정](docs/configuration.ko.md) — 환경변수, 엔드포인트, 웹 UI
- [로그인과 권한](docs/access-control.ko.md) — OIDC 로그인, 그룹별 권한(담당자 지정, 예외 요청·승인, 설정 변경)
- [연동 가이드](docs/README.ko.md) — CI에서 SBOM 만들기, OSV·Trivy 탐지, Renovate, Gitea / Forgejo / GitHub, Slack, CISA KEV·EPSS, Dependency-Track

## 기여하기

이슈와 Pull Request를 환영합니다. 개발 환경, 검사, 규칙은 [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)를 참고하세요. 보안 문제는 공개 이슈 대신 비공개로 제보해 주세요.

## 라이선스

[Apache-2.0](LICENSE). [NOTICE](NOTICE)도 함께 확인하세요.

Patchline은 Dependency-Track과 함께 쓸 수 있지만, OWASP나 Dependency-Track 프로젝트와 관련이 없고 보증을 받은 것도 아닙니다.
