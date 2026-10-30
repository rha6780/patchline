# 설정

[English](configuration.md) | 한국어

Patchline은 환경변수로 설정합니다. 서비스, 담당자, 채널은 [인벤토리](../examples/inventory/services.yaml)에, 기한은 [정책](../examples/policy/policy.yaml)에 둡니다.

## 웹 UI

`http://localhost:8080/`(데모는 `:18080`)으로 접속합니다. 모든 화면과 API에 로그인이 필요합니다. 처음 실행하면 `admin` / `admin`으로 로그인해 새 비밀번호를 정하세요. OIDC를 설정하면 SSO로 로그인하고, 그룹에 따라 할 수 있는 일이 정해집니다. [로그인과 권한](access-control.ko.md)을 참고하세요.

헤더에서 언어(English / 한국어)와 테마(시스템 / 라이트 / 다크)를 바꿀 수 있습니다. 선택은 쿠키에 저장되고, 저장된 값이 없으면 브라우저 언어를 따릅니다.

| 화면 | 경로 |
|---|---|
| Overview: 열린 Finding, 서비스 × 심각도, 조치 필요 건, 최근 해결, MTTR | `/` |
| Finding 목록: 빠른 필터(열림, 기한 초과, 7일 내 기한, 열린 critical, 검증대기)와 서비스·환경·상태·심각도 필터 | `/findings` |
| Finding 상세: 정보, 수정 PR, 근거 타임라인 | `/findings/{id}` |
| 서비스: 담당자, 저장소, 프로젝트별 브랜치·커밋, 환경별 Finding(`main`에서는 해결됐지만 `prod`에 남은 건 강조). 검색, 심각도, 환경, 브랜치, 저장소로 필터 | `/services/{name}` |
| Integrations: DT 프로젝트별 마지막 BOM·커밋, BOM이 없는 인벤토리 프로젝트, 실패한 Webhook·알림 | `/integrations` |
| 구성요소: 패키지 사용처 검색, 취약점 영향 분석 | `/components`, `/vulnerabilities/{id}` |
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
| `POST` | `/ingest/sbom` | CycloneDX(JSON·XML)·SPDX(JSON) SBOM 업로드, 자체 탐지([가이드](integrations/native-detection.ko.md)). Webhook 토큰으로 인증 |
| `GET` | `/api/v1/findings` | 서비스 담당자와 처리 담당자를 포함한 Finding 목록. 필터: `q`(취약점 ID·별칭, 구성요소, 제목), `service`, `environment`, `branch`(그 Finding을 보고한 최신 SBOM의 브랜치·태그: `main`, `v1.4.0`), `repository`, `severity`(실효 심각도), `state`, `assignee`, `open=1`, `limit` |
| `GET` | `/api/v1/findings/{id}/events` | Finding 타임라인 |
| `GET` | `/api/v1/findings/{id}/pull-requests` | Finding에 연결된 PR |
| `GET` | `/api/v1/components` | 저장된 SBOM에서 패키지 사용처 검색. `q`, `ecosystem`, `version`(예: `<2.17.0`), `limit` |
| `GET` | `/api/v1/vulnerabilities/{id}` | CVE·GHSA의 영향 범위: 영향받는 스냅샷, 고치는 버전, 모든 출처의 Finding |
| `GET` | `/api/v1/vex` | 프로젝트 버전의 CycloneDX 1.5 VEX(`project`, `version`, 파일로 받으려면 `download=1`) |
| `GET` | `/login` | 로그인 화면(로컬 관리자, SSO) |
| `POST` | `/auth/local`, `/account/password` | 로컬 관리자 로그인과 비밀번호 변경 |
| `GET` | `/auth/login`, `/auth/callback`; `POST /auth/logout` | OIDC 로그인(설정한 경우), 로그아웃 |

`/api/v1/*`에는 `findings.read` 권한이 있는 세션이 필요하며, 없으면 `401`을 반환합니다(`PATCHLINE_ALLOW_ANONYMOUS=true`면 예외).

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
| `PATCHLINE_OSV_ECOSYSTEMS` | `Maven,npm,PyPI,Go` | 자체 탐지에서 대조할 OSV 생태계(`crates.io`, `NuGet`, `RubyGems`, `Packagist`도 가능). `off`면 SBOM을 저장만 함 |
| `PATCHLINE_OSV_URL` | OSV export | OSV export 주소. 사내 미러를 쓸 때 지정 |
| `PATCHLINE_OSV_REFRESH` | `6h` | OSV 변경분을 받는 주기 |
| `PATCHLINE_TRIVY_URL` | — | 자체 탐지의 두 번째 엔진인 Trivy 서버. OS 패키지(deb, rpm, apk) 대조 |
| `PATCHLINE_TRIVY_TOKEN` | — | Trivy 서버의 `--token` |
| `PATCHLINE_TRIVY_SCOPE` | `os` | `all`이면 언어 패키지도 Trivy로 보냄(OSV 결과와 합쳐짐) |
| `PATCHLINE_PUBLIC_URL` | — | 사용자가 접속하는 Patchline 주소. OIDC를 쓰면 필수(Redirect URI `/auth/callback`). `https://`면 세션 쿠키에 Secure가 붙음 |
| `PATCHLINE_LOCAL_ADMIN` | `true` | 내장 `admin` 계정(`admin` / `admin`으로 시작, 비밀번호 변경 강제). `false`로 하려면 OIDC 필요 |
| `PATCHLINE_ALLOW_ANONYMOUS` | `false` | 세션 없는 요청도 조회 허용. 인증 프록시 뒤에서만 사용 |
| `PATCHLINE_OIDC_ISSUER` | — | OIDC Issuer URL. 비우면 로컬 관리자만 사용 |
| `PATCHLINE_OIDC_CLIENT_ID` | — | OIDC 클라이언트 ID |
| `PATCHLINE_OIDC_CLIENT_SECRET` | — | OIDC 클라이언트 Secret |
| `PATCHLINE_OIDC_SCOPES` | `profile,email` | `openid` 외에 요청할 scope |
| `PATCHLINE_OIDC_GROUPS_CLAIM` | `groups` | 그룹으로 읽을 ID 토큰 클레임. 쉼표로 여러 개, 점(.)으로 중첩 클레임(`realm_access.roles`) |
| `PATCHLINE_SESSION_TTL` | `12h` | 로그인 유지 시간 |
| `PATCHLINE_ACCESS_POLICY_PATH` | — | 그룹 → 권한 매핑([예시](../examples/access/access-policy.yaml)). 비우면 로그인한 사람은 조회만 가능 |
