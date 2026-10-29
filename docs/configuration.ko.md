# 설정

[English](configuration.md) | 한국어

Patchline은 환경변수로 설정합니다. 서비스, 담당자, 채널은 [인벤토리](../examples/inventory/services.yaml)에, 기한은 [정책](../examples/policy/policy.yaml)에 둡니다.

## 웹 UI

`http://localhost:8080/`(데모는 `:18080`)으로 접속합니다. 로그인을 설정하지 않으면 UI는 누구에게나 열린 조회 전용이므로, 신뢰할 수 있는 네트워크나 인증 프록시 뒤에 두세요. OIDC를 설정하면 사용자가 로그인하고, 그룹에 따라 바꿀 수 있는 것이 정해집니다. [로그인과 권한](access-control.ko.md)을 참고하세요.

헤더에서 언어(English / 한국어)와 테마(시스템 / 라이트 / 다크)를 바꿀 수 있습니다. 선택은 쿠키에 저장되고, 저장된 값이 없으면 브라우저 언어를 따릅니다.

| 화면 | 경로 |
|---|---|
| Overview: 열린 Finding, 서비스 × 심각도, 조치 필요 건, 최근 해결, MTTR | `/` |
| Finding 목록: 빠른 필터(열림, 기한 초과, 7일 내 기한, 열린 critical, 검증대기)와 서비스·환경·상태·심각도 필터 | `/findings` |
| Finding 상세: 정보, 수정 PR, 근거 타임라인 | `/findings/{id}` |
| 서비스: 담당자, 저장소, 환경별 Finding(`main`에서는 해결됐지만 `prod`에 남은 건 강조) | `/services/{name}` |
| Integrations: DT 프로젝트별 마지막 BOM·커밋, BOM이 없는 인벤토리 프로젝트, 실패한 Webhook·알림 | `/integrations` |
| 승인: 대기 중인 위험 수용·기한 연장 요청, 최근 결정(`exceptions.request` 또는 `exceptions.approve`) | `/approvals` |
| 설정: Webhook 토큰·Secret 교체(`settings.webhooks`), 감사 로그(`audit.read`) | `/settings` |
| 연동 가이드: 알림을 받을 수 있는 취약점 소스(Dependency-Track 지원, OpenCVE 예정), 연결 방법, `docs/integrations` 가이드 링크 | `/docs/integrations` |

모든 화면 하단의 푸터에 연동 가이드, 이 문서, 연동 도구, 프로젝트 링크가 있습니다.

## 엔드포인트

| 메서드 | 경로 | 용도 |
|---|---|---|
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness(DB) |
| `POST` | `/webhooks/dependency-track` | Dependency-Track Outbound Webhook(`?token=` 또는 `Authorization: Bearer`) |
| `POST` | `/webhooks/gitea` | Gitea / Forgejo / GitHub `pull_request` Webhook(HMAC 서명 또는 토큰) |
| `GET` | `/api/v1/findings` | 서비스 담당자와 처리 담당자를 포함한 Finding 목록. 필터 `service`, `environment`, `state`, `assignee`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | Finding 타임라인 |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Finding에 연결된 PR |
| `GET` | `/auth/login`, `/auth/callback`; `POST /auth/logout` | OIDC 로그인(설정한 경우) |

로그인을 설정하면 `/api/v1/*`에도 `findings.read` 권한이 있는 세션이 필요하며, 없으면 `401`을 반환합니다.

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
| `PATCHLINE_PUBLIC_URL` | — | 사용자가 접속하는 Patchline 주소. OIDC를 쓰면 필수(Redirect URI `/auth/callback`) |
| `PATCHLINE_OIDC_ISSUER` | — | OIDC Issuer URL. 비우면 로그인 없이 조회 전용 |
| `PATCHLINE_OIDC_CLIENT_ID` | — | OIDC 클라이언트 ID |
| `PATCHLINE_OIDC_CLIENT_SECRET` | — | OIDC 클라이언트 Secret |
| `PATCHLINE_OIDC_SCOPES` | `profile,email` | `openid` 외에 요청할 scope |
| `PATCHLINE_OIDC_GROUPS_CLAIM` | `groups` | 그룹으로 읽을 ID 토큰 클레임. 쉼표로 여러 개, 점(.)으로 중첩 클레임(`realm_access.roles`) |
| `PATCHLINE_SESSION_TTL` | `12h` | 로그인 유지 시간 |
| `PATCHLINE_ACCESS_POLICY_PATH` | — | 그룹 → 권한 매핑([예시](../examples/access/access-policy.yaml)). 비우면 로그인한 사람은 조회만 가능 |
