# Patchline 문서

[English](README.md) | 한국어

- [동작 방식](how-it-works.ko.md): Finding 상태, 수집, 해결 판정, PR 연결, 기한, 알림
- [설정](configuration.ko.md): 환경변수, 엔드포인트, 웹 UI
- [프로젝트와 브랜치 등록](projects.ko.md): 인벤토리의 서비스, 프로젝트 이름, 환경이 되는 버전, 브랜치와 커밋, 정리 방법
- [설계: 자체 탐지](design/native-detection.ko.md): OSV와 Trivy로 SBOM을 대조하는 구조와 다음 단계
- [설계: 연동을 포트 뒤로](design/source-ports.ko.md): 도구를 어댑터로 붙이는 방식
- [로그인과 권한](access-control.ko.md): OIDC(FusionAuth, Keycloak 등), 그룹 → 권한 매핑, 담당자 지정, 승인

## 연동

Patchline은 이미 쓰고 있는 도구들 사이에서 동작합니다. 가이드마다 해당 도구에서 할 일, Patchline 설정, 동작 확인 방법을 정리했습니다.

기본 구성에는 다른 스캐너가 필요 없습니다. CI가 SBOM을 올리면 Patchline이 대조하고, 판정도 Patchline에서 합니다. Dependency-Track은 두 번째 출처로 추가할 수 있습니다.

| 도구 | 역할 | 가이드 |
|---|---|---|
| CI의 SBOM 생성(Trivy, CycloneDX) | 빌드마다 SBOM을 만들어 Patchline에 올리고 커밋을 근거로 남김 | [sbom-ci.ko.md](integrations/sbom-ci.ko.md) |
| 탐지: OSV와 Trivy | 올린 SBOM을 대조. 언어 패키지는 로컬 OSV 미러, OS 패키지는 Trivy 서버로 대조하고, 판정과 VEX도 다룸 | [native-detection.ko.md](integrations/native-detection.ko.md), [trivy.ko.md](integrations/trivy.ko.md) |
| Renovate | 수정 PR을 만들고, Patchline이 Finding과 연결해 영향 범위를 벗어나는지 판정 | [renovate.ko.md](integrations/renovate.ko.md) |
| Gitea / Forgejo / GitHub | PR Webhook | [git-webhooks.ko.md](integrations/git-webhooks.ko.md) |
| Slack | Finding당 메시지 1개, 갱신과 스레드 이력 | [slack.ko.md](integrations/slack.ko.md) |
| Webhook 알림 | Finding과 변경마다 서명된 JSON 전송, 다른 시스템 연동용 | [webhook-notifications.ko.md](integrations/webhook-notifications.ko.md) |
| CISA KEV, EPSS | 심각도를 올리고 기한을 앞당기는 위험 신호 | [kev-epss.ko.md](integrations/kev-epss.ko.md) |
| Dependency-Track(선택) | Finding과 분석 판정의 두 번째 출처. 승인된 판정을 Dependency-Track에도 기록 | [dependency-track.ko.md](integrations/dependency-track.ko.md) |

## 연결 구조

```
CI ── SBOM + 커밋 ──▶ Patchline ──▶ Slack, Webhook
                        │   ▲
   OSV 미러, Trivy ◀────┘   ├── 수정 PR: Renovate → Gitea / Forgejo / GitHub Webhook
                            ├── CISA KEV
                            └── Dependency-Track Webhook(선택)
```

모든 연동은 **인벤토리**(`PATCHLINE_INVENTORY_PATH`)를 기준으로 이어집니다. 인벤토리는 프로젝트 이름과 저장소를 서비스, 담당자, Slack 채널에 연결합니다. 예시는 [examples/inventory/services.yaml](../examples/inventory/services.yaml), 등록 방법은 [프로젝트와 브랜치 등록](projects.ko.md)을 보세요.

| 도구 쪽 이름 | 인벤토리에서 맞춰야 하는 값 |
|---|---|
| SBOM 업로드의 프로젝트(`project`), 또는 Dependency-Track 프로젝트 이름 | `repositories[].projects`(기본값: `repo`의 마지막 부분) |
| 업로드의 버전, 또는 Dependency-Track 프로젝트 버전 | 환경(예: `main`, `prod`) |
| 저장소 전체 이름(`owner/name`) | `repositories[].repo` |
| PR의 base 브랜치 | PR을 연결할 환경(`default`도 포함) |

로컬에서 전체 흐름을 돌려 보려면 [Compose 데모](../deploy/compose/README.md)를, 서버나 로컬 PC에 설치하려면 [deploy/self-hosted](../deploy/self-hosted/README.ko.md)를 참고하세요.
