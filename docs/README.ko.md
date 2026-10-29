# Patchline 문서

[English](README.md) | 한국어

## 연동

Patchline은 이미 쓰고 있는 도구들 사이에서 동작합니다. 가이드마다 해당 도구에서 할 일, Patchline 설정, 동작 확인 방법을 정리했습니다.

| 도구 | 역할 | 가이드 |
|---|---|---|
| Dependency-Track | 취약점 수집원: Finding, 분석 판정, BOM 처리 | [dependency-track.ko.md](integrations/dependency-track.ko.md) |
| CI의 SBOM 생성(Trivy, CycloneDX) | Dependency-Track이 분석할 BOM을 만들고 커밋을 근거로 남김 | [sbom-ci.ko.md](integrations/sbom-ci.ko.md) |
| Renovate | 수정 PR을 만들고, Patchline이 이를 Finding과 연결 | [renovate.ko.md](integrations/renovate.ko.md) |
| Gitea / Forgejo / GitHub | Pull request Webhook | [git-webhooks.ko.md](integrations/git-webhooks.ko.md) |
| Slack | Finding당 메시지 1개, 갱신과 스레드 이력 | [slack.ko.md](integrations/slack.ko.md) |
| CISA KEV, EPSS | 심각도를 올리고 기한을 앞당기는 위험 신호 | [kev-epss.ko.md](integrations/kev-epss.ko.md) |

지금은 Dependency-Track을 취약점 수집원으로 사용합니다. 다른 도구도 수집원으로 연동할 수 있도록 지원할 예정입니다.

## 연결 구조

```
CI ── SBOM + 커밋 ──▶ Dependency-Track ── webhook ──▶ Patchline ──▶ Slack
                                                         ▲   ▲
Renovate ── 수정 PR ──▶ Gitea / Forgejo / GitHub ─ webhook ┘   └── CISA KEV
```

모든 연동은 **인벤토리**(`PATCHLINE_INVENTORY_PATH`)에서 만납니다. 인벤토리는 Dependency-Track 프로젝트 이름과 저장소를 서비스, 담당자, Slack 채널에 연결합니다. 예시는 [examples/inventory/services.yaml](../examples/inventory/services.yaml)입니다.

| 도구 쪽 이름 | 인벤토리에서 맞춰야 하는 값 |
|---|---|
| Dependency-Track 프로젝트 이름 | `repositories[].dependency_track_projects`(기본값: `repo`의 마지막 부분) |
| Dependency-Track 프로젝트 버전 | 환경(예: `main`, `prod`) |
| 저장소 전체 이름(`owner/name`) | `repositories[].repo` |
| PR의 base 브랜치 | PR을 연결할 환경 |

로컬에서 전체 흐름을 돌려 보려면 [Compose 데모](../deploy/compose/README.md)를 참고하세요.
