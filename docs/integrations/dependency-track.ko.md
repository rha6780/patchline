# Dependency-Track

[English](dependency-track.md) | 한국어

Dependency-Track은 *무엇이 취약한지*를 판정합니다. Patchline은 Dependency-Track의 알림을 받고 REST API로 Finding을 조회하며, 사람이 판정하는 곳은 Dependency-Track 분석 하나로 둡니다.

Dependency-Track 4.14로 확인했습니다.

## 1. Patchline용 API 키

**Administration → Access Management → Teams**에서 팀(예: `patchline`)을 만들고 아래 권한을 준 뒤 API 키를 발급합니다.

| 권한 | 용도 |
|---|---|
| `VIEW_VULNERABILITY` | `BOM_PROCESSED` 이후 프로젝트의 현재 Finding 조회(`GET /api/v1/finding/project/{uuid}`) |
| `VIEW_PORTFOLIO` | 수정 PR 판정에 쓰는 취약점 상세(취약 버전 범위) 조회(`GET /api/v1/vulnerability/source/{source}/vuln/{id}`) |

CI 업로드용 키는 별도 팀(`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`)으로 분리하세요. 그러면 Patchline이 가진 키로는 아무것도 바꿀 수 없습니다.

## 2. 알림 규칙

**Administration → Notifications → Alerts → Create Alert**

| 항목 | 값 |
|---|---|
| Publisher | Outbound Webhook |
| Scope | Portfolio |
| Groups | `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY`, `BOM_PROCESSED`, `PROJECT_AUDIT_CHANGE` |
| Destination | `https://patchline.example.com/webhooks/dependency-track?token=<PATCHLINE_WEBHOOK_TOKEN>` |

포트폴리오 일부만 추적하려면 규칙을 특정 프로젝트로 제한하세요.

| Group | Patchline 동작 |
|---|---|
| `NEW_VULNERABILITY`, `NEW_VULNERABLE_DEPENDENCY` | payload로 Finding 생성 |
| `BOM_PROCESSED` | BOM의 커밋을 기록하고, `PATCHLINE_DT_RECONCILE_DELAY` 후 프로젝트 Finding을 조회해 새 건은 추가하고 사라진 건은 해결 처리 |
| `PROJECT_AUDIT_CHANGE` | 분석 판정을 Finding 상태에 반영 |

## 3. Patchline 설정

```sh
PATCHLINE_DT_URL=https://dtrack-api.example.com     # Patchline에서 접근 가능한 API 서버 주소
PATCHLINE_DT_API_KEY=odt_...                         # 1단계에서 발급한 키
PATCHLINE_DT_UI_URL=https://dtrack.example.com      # 메시지와 UI 링크용 프론트엔드 주소
PATCHLINE_WEBHOOK_TOKEN=<충분히 긴 임의 문자열>        # Destination URL의 token과 같은 값
PATCHLINE_DT_RECONCILE_DELAY=2m                     # 큰 BOM 분석이 오래 걸리면 늘리기
```

`PATCHLINE_DT_URL`과 키가 없어도 알림으로 Finding은 생성되지만, 재스캔으로 해결 판정은 하지 않습니다.

## 4. 프로젝트, 버전, 인벤토리

| Dependency-Track | Patchline |
|---|---|
| 프로젝트 **이름** | 인벤토리에서 찾아 서비스, 담당자, Slack 채널에 연결 |
| 프로젝트 **버전** | 환경(`main`, `prod` 등). 비어 있으면 `default` |

환경마다 프로젝트 버전을 하나씩 쓰세요. 예를 들어 기본 브랜치는 `storefront-api@main`, 배포된 이미지는 `storefront-api@prod`입니다. 버전마다 따로 해결되므로, UI에서 "main에서는 해결됐지만 prod에는 남은 건"을 보여줄 수 있습니다.

인벤토리에 없는 프로젝트는 *미등록*으로 저장되고 UI의 **연동 상태**에 표시됩니다.

## 5. 분석 판정

판정은 Dependency-Track에서 합니다(Finding → **Analysis**). Patchline은 다음과 같이 반영합니다.

| Dependency-Track | Patchline 상태 |
|---|---|
| `NOT_SET` | 신규 |
| `IN_TRIAGE`, `EXPLOITABLE` | 조치중 |
| `RESOLVED` | 검증대기(재스캔으로 확인) |
| `NOT_AFFECTED`, `FALSE_POSITIVE` | 해당 없음 |
| Suppress(그 밖의 상태) | 위험 수용 |

## 확인

1. 인벤토리에 있는 프로젝트로 BOM을 업로드합니다.
2. Patchline의 `GET /api/v1/findings`에 담당자 정보와 함께 Finding이 나옵니다.
3. UI의 **연동 상태**에 프로젝트의 마지막 BOM 시각과 커밋이 표시됩니다.

| 증상 | 원인 |
|---|---|
| Webhook이 `401` 응답 | Destination URL의 token이 `PATCHLINE_WEBHOOK_TOKEN`과 다름 |
| Finding은 생기는데 해결되지 않음 | `PATCHLINE_DT_URL` / `PATCHLINE_DT_API_KEY`가 없거나 키에 `VIEW_VULNERABILITY` 권한이 없음 |
| 서비스가 미등록으로 표시됨 | 프로젝트 이름이 인벤토리와 다름 |
| **Webhook 처리 실패**에 항목이 쌓임 | 마지막 오류에 원인이 표시됨. 간격을 늘려 가며 재시도함 |
