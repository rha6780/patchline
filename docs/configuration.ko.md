# 설정

[English](configuration.md) | 한국어

Patchline은 환경변수로 설정합니다. 서비스, 담당자, 채널은 [인벤토리](../examples/inventory/services.yaml)에, 기한은 [정책](../examples/policy/policy.yaml)에 둡니다.

## 웹 UI

`http://localhost:8080/`(데모는 `:18080`)으로 접속합니다. 자체 로그인이 없으므로 인증 프록시 뒤에 두세요.

헤더에서 언어(English / 한국어)와 테마(시스템 / 라이트 / 다크)를 바꿀 수 있습니다. 선택은 쿠키에 저장되고, 저장된 값이 없으면 브라우저 언어를 따릅니다.

| 화면 | 경로 |
|---|---|
| Overview: 열린 Finding, 서비스 × 심각도, 조치 필요 건, 최근 해결, MTTR | `/` |
| Finding 목록: 빠른 필터(열림, 기한 초과, 7일 내 기한, 열린 critical, 검증대기)와 서비스·환경·상태·심각도 필터 | `/findings` |
| Finding 상세: 정보, 수정 PR, 근거 타임라인 | `/findings/{id}` |
| 서비스: 담당자, 저장소, 환경별 Finding(`main`에서는 해결됐지만 `prod`에 남은 건 강조) | `/services/{name}` |
| Integrations: DT 프로젝트별 마지막 BOM·커밋, BOM이 없는 인벤토리 프로젝트, 실패한 Webhook·알림 | `/integrations` |

## 엔드포인트

| 메서드 | 경로 | 용도 |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness(DB) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track Outbound Webhook(`?token=` 또는 `Authorization: Bearer`) |
| `POST` | `/webhooks/gitea` | Gitea / Forgejo / GitHub `pull_request` Webhook(HMAC 서명 또는 토큰) |
| `GET` | `/api/v1/findings` | 담당자 정보를 포함한 Finding 목록. 필터 `service`, `environment`, `state`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | Finding 타임라인 |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Finding에 연결된 PR |

## 설정

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `PATCHLINE_ADDR` | `:8080` | 수신 주소 |
| `PATCHLINE_DB_PATH` | `data/patchline.db` | SQLite 파일 |
| `PATCHLINE_INVENTORY_PATH` | — | 인벤토리 YAML 파일 또는 디렉터리([예시](../examples/inventory/services.yaml)) |
| `PATCHLINE_WEBHOOK_TOKEN` | — | Webhook 공유 비밀값. 비우면 인증 없음(개발용) |
| `PATCHLINE_DT_URL` | — | Dependency-Track API 서버 URL |
| `PATCHLINE_DT_API_KEY` | — | `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY` 권한의 API 키 |
| `PATCHLINE_GITEA_WEBHOOK_SECRET` | — | PR Webhook의 Secret. 비우면 `PATCHLINE_WEBHOOK_TOKEN` 사용 |
| `PATCHLINE_DT_UI_URL` | — | 메시지에 넣을 Dependency-Track UI 주소 |
| `PATCHLINE_DT_RECONCILE_DELAY` | `2m` | `BOM_PROCESSED` 이후 Finding을 비교하기 전 대기 시간 |
| `PATCHLINE_POLICY_PATH` | — | 조치 정책 YAML([예시](../examples/policy/policy.yaml)). 비우면 기본값 |
| `PATCHLINE_KEV_URL` | CISA 피드 | CISA KEV 카탈로그 주소(하루 한 번 갱신). `off`면 사용 안 함 |
| `PATCHLINE_SLACK_BOT_TOKEN` | — | Slack Bot 토큰(`chat:write`, `chat:write.public`). 비우면 stdout으로 출력 |
| `PATCHLINE_SLACK_DEFAULT_CHANNEL` | — | `slack_channel`이 없는 서비스와 미등록 프로젝트용 채널 |
| `PATCHLINE_NOTIFY_MIN_SEVERITY` | `medium` | 알림을 보낼 최소 심각도 |
| `PATCHLINE_NOTIFY_LANG` | `en` | Slack·콘솔 메시지 언어: `en` 또는 `ko` |
| `PATCHLINE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `PATCHLINE_LOG_FORMAT` | `text` | `text` 또는 `json` |
| `PATCHLINE_SHUTDOWN_TIMEOUT` | `10s` | 정상 종료 제한 시간 |
