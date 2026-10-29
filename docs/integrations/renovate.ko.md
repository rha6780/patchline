# Renovate

[English](renovate.md) | 한국어

Renovate는 *어떻게 고칠지*를 제안합니다. Patchline은 Renovate와 직접 통신하지 않습니다. [Git Webhook](git-webhooks.ko.md)으로 Renovate의 PR을 받아 Finding과 연결합니다.

## Patchline이 PR에서 읽는 것

| 위치 | 용도 |
|---|---|
| PR 본문의 변경 표(`| Package | Change |`, `` `2.14.1` -> `2.17.1` ``) | 패키지 이름과 버전. PR 하나에 여러 행이 있어도 됨 |
| 표가 없을 때 제목(`Update dependency X to vY`) | 패키지 하나와 목표 버전 |
| 저장소 전체 이름 | Finding의 저장소(인벤토리의 `repo`) |
| base 브랜치 | PR을 연결할 환경(`main` → `...@main`의 Finding, 버전이 없는 프로젝트의 `default`도 포함) |

패키지마다 열린 Finding과 이름으로 연결합니다(Maven `group:artifact`는 `group/artifact`와 같게 봄). 이어서 목표 버전을 Dependency-Track의 취약 버전 범위와 비교합니다.

| 판정 | 의미 |
|---|---|
| ✅ 취약 범위를 벗어남 | 목표 버전이 모든 취약 범위 밖에 있음 |
| ⚠️ 여전히 영향 있음 | 목표 버전이 아직 범위 안에 있음. 이 PR로는 부족함 |
| ❔ 확인 불가 | 이 패키지의 범위 정보가 없음 |

PR이 연결되면 Finding은 *조치중*, Merge되면 *검증대기*가 됩니다. 해결은 다음 BOM에서만 판정합니다.

## Renovate 설정

Patchline은 Renovate 기본 설정으로 동작합니다. 기본 PR 본문을 유지하세요(`prBodyTemplate`을 바꿔 변경 표를 없애지 마세요).

Gitea에서 셀프호스팅하는 예시입니다.

```js
// config.js (Renovate runner)
module.exports = {
  platform: 'gitea',
  endpoint: 'https://git.example.com/api/v1/',
  token: process.env.RENOVATE_TOKEN,
  autodiscover: true,
};
```

```jsonc
// renovate.json (저장소 또는 공용 preset)
{
  "extends": ["config:recommended", "docker:pinDigests"],
  "osvVulnerabilityAlerts": true,
  "vulnerabilityAlerts": { "labels": ["security"] }
}
```

| 옵션 | 이유 |
|---|---|
| `osvVulnerabilityAlerts` | GitHub 보안 알림이 없는 플랫폼에서 OSV 데이터로 보안 PR 생성 |
| `docker:pinDigests` | 베이스 이미지를 digest로 고정해, 재빌드된 이미지(OS 패키지 수정)가 PR로 들어오게 함 |
| `vulnerabilityAlerts.labels` | 선택 사항. 보안 PR을 쉽게 구분하려는 용도이고, Patchline에는 필요 없음 |

## 제한

- 베이스 이미지 업데이트는 OS 패키지 Finding과 연결하지 않습니다. 이 경우 새 이미지의 재스캔으로 해결됩니다.
- 전이 의존성은 PR이 그 패키지를 직접 언급할 때만 연결됩니다. 상위 패키지(예: Spring Boot)를 올리면 재스캔으로 해결됩니다.

## 확인

열린 Finding이 있는 패키지로 Renovate PR을 엽니다. Finding 화면에 PR과 판정이 나오고, Slack 스레드에 "수정 PR 열림"이 남습니다.
