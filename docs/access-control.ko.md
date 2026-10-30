# 로그인과 권한

[English](access-control.md) | 한국어

모든 화면과 API에 로그인이 필요합니다. 로그인 방법은 두 가지입니다.

- **로컬 관리자**: 초기 설정용이자 SSO를 쓸 수 없을 때를 위한 내장 `admin` 계정입니다. 모든 권한을 가집니다.
- **SSO**: 나머지 사람은 OpenID Connect(FusionAuth, Keycloak, Okta, Entra ID, Google 등)로 로그인합니다. ID 토큰의 그룹이나 역할에 따라 할 수 있는 일이 정해집니다.

| 권한 | 할 수 있는 일 |
|---|---|
| `findings.read` | 웹 UI와 `GET /api/v1/*` 사용 |
| `findings.assign` | Finding의 처리 담당자 지정·해제 |
| `exceptions.request` | **위험 수용**이나 **기한 연장** 요청 |
| `exceptions.approve` | 다른 사람의 요청 승인·반려 |
| `settings.webhooks` | Webhook 토큰과 Git Webhook Secret 확인(일부만 표시)·교체 |
| `audit.read` | 감사 로그 확인 |
| `tokens.manage` | API 토큰 생성·폐기 |
| `sbom.upload` | `/ingest/sbom`에 SBOM 업로드(API 토큰용) |
| `*` | 위 전부 |

Webhook(`/webhooks/*`)과 헬스체크에는 로그인이 필요 없습니다. 각자의 비밀값으로 인증합니다.

## 로컬 관리자

처음 실행하면 Patchline이 `admin` 계정을 비밀번호 `admin`으로 만들고, 바꿀 때까지 경고 로그를 남깁니다.

1. Patchline에 접속해 `admin` / `admin`으로 로그인합니다.
2. 새 비밀번호를 정합니다(12자 이상, `admin` 불가). 바꾸기 전까지는 모든 화면이 비밀번호 변경 화면으로 이동하고, API는 `403`을 반환합니다.

| | |
|---|---|
| 잠금 | 연속 5회 실패하면 15분 동안 잠김 |
| 비밀번호 변경 | 관리자의 다른 세션이 종료됨 |
| 비밀번호 분실 | `patchline reset-admin-password`(같은 `PATCHLINE_DB_PATH`로 실행)를 실행하면 `admin`으로 돌아가고(다음 로그인 때 변경 필요) 세션이 종료됩니다. 직접 설치용 compose에서는 `docker compose run --rm patchline reset-admin-password` |
| 끄기 | SSO가 동작하면 `PATCHLINE_LOCAL_ADMIN=false`. 기존 세션도 종료됨 |

localhost 밖으로 공개하기 **전에** 기본 비밀번호를 바꾸세요. 바꾸기 전에는 로그인 화면에 접속할 수 있는 누구나 이 계정을 가져갈 수 있습니다.

`PATCHLINE_ALLOW_ANONYMOUS=true`로 두면 세션 없는 요청도 조회(UI, API)할 수 있습니다. 인증 프록시가 이미 앞을 막고 있는 경우에만 쓰세요. 변경 작업에는 여전히 로그인이 필요합니다.

## 1. IdP에 Patchline 등록

OIDC 애플리케이션을 만듭니다(Confidential 클라이언트, Authorization Code 방식).

| 항목 | 값 |
|---|---|
| Redirect URI | `https://patchline.example.com/auth/callback` (`PATCHLINE_PUBLIC_URL` + `/auth/callback`) |
| Grant | Authorization Code. Patchline은 항상 PKCE(S256)를 보냅니다 |
| Scope | `openid profile email`, 그리고 ID 토큰에 그룹을 넣는 데 필요한 scope |
| ID 토큰 클레임 | `sub`, `email`, `name`, 그룹 또는 역할 클레임 |

### FusionAuth

1. **Applications → Add**: **OAuth** 탭에서 Authorized redirect URL을 넣고 *Authorization Code* grant를 켭니다. 원하면 *Require PKCE*도 켭니다.
2. **Roles** 탭에 `patchline-approver`, `patchline-developer`, `patchline-ops` 같은 역할을 추가합니다.
3. 역할은 **Groups**로 부여합니다. 그룹에 애플리케이션 역할을 연결하면 팀 소속이 곧 권한이 됩니다.
4. FusionAuth는 기본적으로 역할을 ID 토큰이 아니라 Access 토큰에만 넣습니다. **JWT populate lambda**를 만들고 애플리케이션의 *Id Token populate lambda*로 지정하세요(**Applications → Edit → JWT**).

   ```js
   function populate(jwt, user, registration) {
     jwt.roles = (registration && registration.roles) || [];
   }
   ```

5. Patchline에는 `PATCHLINE_OIDC_GROUPS_CLAIM=roles`를 설정하고, 접근 정책에 역할 이름을 씁니다.

Issuer는 `https://<fusionauth-host>`입니다(테넌트가 여러 개면 `https://<host>/<tenant-id>`일 수 있으니 discovery 문서의 `iss`를 확인하세요).

### Keycloak

Redirect URI를 넣은 Confidential 클라이언트를 만듭니다. 그다음 *Group Membership* 매퍼를 추가합니다(클레임 `groups`, *Full group path* 끔, *Add to ID token* 켬). Realm 역할을 쓰려면 `PATCHLINE_OIDC_GROUPS_CLAIM=realm_access.roles`로 지정합니다. Issuer는 `https://<host>/realms/<realm>`입니다.

### 그 밖의 IdP

| IdP | 그룹 클레임 | 참고 |
|---|---|---|
| Okta | `groups` | ID 토큰에 *groups* 클레임 추가(예: *starts with* `patchline-` 필터) |
| Microsoft Entra ID | `groups` 또는 `roles` | 그룹 클레임은 객체 ID라서, 앱 역할(`roles`)이 정책에 쓰기 편합니다 |
| Google | — | 토큰에 그룹이 없으므로 `users:`에 이메일로 지정합니다 |

## 2. Patchline 설정

```sh
PATCHLINE_PUBLIC_URL=https://patchline.example.com
PATCHLINE_OIDC_ISSUER=https://auth.example.com
PATCHLINE_OIDC_CLIENT_ID=...
PATCHLINE_OIDC_CLIENT_SECRET=...
PATCHLINE_OIDC_GROUPS_CLAIM=groups          # 쉼표로 여러 개, 점(.)으로 중첩 클레임
PATCHLINE_OIDC_SCOPES=profile,email          # openid 외에 요청할 scope
PATCHLINE_SESSION_TTL=12h
PATCHLINE_ACCESS_POLICY_PATH=/etc/patchline/access-policy.yaml
```

Patchline은 시작할 때 IdP의 discovery 문서를 읽고, 읽지 못하면 시작하지 않습니다. HTTPS로 서비스하세요. `PATCHLINE_PUBLIC_URL`이 `https://`이면 세션 쿠키에 `Secure`가 붙습니다.

## 3. 그룹에 권한 매핑

```yaml
# access-policy.yaml (예시: examples/access/access-policy.yaml)
default: [findings.read]              # 로그인한 모든 사람

groups:
  developers:   [findings.assign, exceptions.request]
  sec-team:     [findings.assign, exceptions.request, exceptions.approve, audit.read]
  platform-ops: [settings.webhooks, audit.read]

users:                                 # 이메일 또는 subject
  admin@example.com: ["*"]
```

- 권한은 합쳐집니다: `default` + 해당하는 모든 그룹 + 본인 항목.
- 모르는 권한이나 항목이 있으면 시작하지 않습니다. 오타로 권한이 잘못 부여되거나 빠지지 않습니다.
- 그룹은 요청마다 세션에서 읽고, 정책은 시작할 때 읽습니다. 정책을 바꾸면 재시작 후 적용되고 다시 로그인할 필요는 없습니다. IdP에서 그룹을 바꾸면 다음 로그인부터 적용됩니다.
- 정책 파일이 없으면 로그인한 사람은 조회만 할 수 있습니다.
- `findings.read`가 없는 사람이 로그인하면 "접근 권한 없음" 화면이 나옵니다.

시작 로그에 승인권자와 설정 변경권자가 표시됩니다(`policy="exceptions.approve: sec-team; settings.webhooks: platform-ops"`). 로그인할 때마다 그룹과 결과 권한도 로그에 남습니다.

## 할 수 있는 일

### 담당자 지정

`findings.assign` 권한이 있으면 Finding의 **처리 담당자**를 이메일로 지정합니다(*나에게 지정*도 가능). 인벤토리의 서비스 담당자는 그대로입니다. 처리 담당자는 다음 위치에 표시됩니다.
- Finding 상세
- 목록(*내 담당*)
- Slack 메시지
- `GET /api/v1/findings?assignee=`

### 요청과 승인

| 요청 | 승인하면 |
|---|---|
| **위험 수용**(사유) | Finding을 *위험 수용*으로 바꿈(VEX: `exploitable`, 대응 `will_not_fix`) |
| **해당 없음**(근거, 사유) | Finding을 *해당 없음*으로 바꿈. `code_not_reachable`, `protected_at_perimeter` 같은 CycloneDX 근거를 함께 기록 |
| **오탐**(사유) | Finding을 *해당 없음*으로 바꿈(VEX: `false_positive`) |
| **기한 연장**(새 날짜, 사유) | 기한을 그 날짜의 끝으로 옮김 |

판정을 어디에 기록하는지는 누가 그 Finding을 보고했느냐에 따라 다릅니다.
- **Dependency-Track이 보고한 Finding:** 판정을 Dependency-Track에도 기록합니다. `EXPLOITABLE` + `WILL_NOT_FIX` + Suppress, 근거를 붙인 `NOT_AFFECTED`, `FALSE_POSITIVE` 중 하나이고, 코멘트에 사유와 요청자·승인자가 들어갑니다. Patchline이 Dependency-Track에 기록할 수 없으면 요청 단계에서 거부합니다.
- **Patchline만 보고한 Finding**([자체 탐지](integrations/native-detection.ko.md)): 판정을 Patchline에 보관하고 VEX로 내보냅니다.

- `exceptions.request` 권한이 있으면 Finding 상세에서 요청합니다. 승인권자는 **승인** 메뉴에서 대기 중인 요청을 모두 봅니다.
- **본인의 요청은 승인할 수 없습니다.** 두 권한을 모두 가져도 마찬가지입니다. 요청자는 대기 중인 요청을 철회할 수 있습니다.
- Finding마다 종류별로 대기 중인 요청은 하나만 둘 수 있습니다.
- Dependency-Track이 분석 기록을 거부하면 승인되지 않고 요청은 대기 상태로 남습니다. 이 기능을 쓰려면 Patchline의 API 키에 `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`에 더해 `VULNERABILITY_ANALYSIS` 권한이 필요합니다.
- 연장된 기한은 실효 심각도가 승인 당시 수준 이하일 때만 유지됩니다. 상향되거나(예: CVE가 CISA KEV에 등재) 재발하면 정책의 기한이 다시 적용됩니다.
- 요청, 결정, 메모는 Finding 타임라인과 Slack 스레드에 남습니다.

### Webhook 설정

`settings.webhooks` 권한이 있으면 **설정 → Webhook**에서 `PATCHLINE_WEBHOOK_TOKEN`과 `PATCHLINE_GITEA_WEBHOOK_SECRET`을 재시작 없이 교체합니다.
- 생성한 값은 한 번만 보여 줍니다.
- 저장한 값은 초기화하기 전까지 환경변수 대신 쓰입니다.
- 값은 Patchline DB에 저장되므로 DB 파일과 백업에 대한 접근을 제한하세요.
- 화면에는 저장된 값의 마지막 몇 글자만 표시합니다.

### API 토큰

도구는 세션 대신 API 토큰을 씁니다. 예를 들어 SBOM을 올리는 CI, VEX를 가져가는 스캐너, Finding을 읽는 스크립트입니다. `tokens.manage` 권한이 있으면 **설정 → API 토큰**에서 만듭니다.

| | |
|---|---|
| 권한 | `findings.read`(조회 API: Finding, 구성요소, 영향 분석, VEX)와 `sbom.upload`(`/ingest/sbom`) 중 선택. 변경 권한은 토큰에 줄 수 없음 |
| 만료 | 30일, 90일, 365일 또는 만료 없음 |
| 값 | `plt_…`. 한 번만 표시하고, Patchline에는 SHA-256만 저장 |
| 범위 | `/api/*`와 `/ingest/sbom`. 토큰으로 웹 UI는 열 수 없음 |
| 폐기 | 언제든 가능. 생성·폐기는 감사 로그에 남고, 목록에서 마지막 사용 시각을 볼 수 있음 |

```sh
curl -sS -H "Authorization: Bearer $PATCHLINE_TOKEN" "$PATCHLINE_URL/api/v1/vex?project=storefront-api&version=main"
```

`/ingest/sbom`에는 공유 Webhook 토큰 대신 `sbom.upload` 권한의 토큰을 쓸 수 있습니다. 파이프라인마다 토큰을 따로 주고 따로 폐기할 수 있습니다.

### 감사 로그

`audit.read` 권한이 있으면 담당자 지정, 요청, 결정, 설정 변경을 누가 언제 했는지 봅니다. 설정 값 자체는 기록하지 않습니다.

## 보안 참고

- Authorization Code + PKCE, `state`, `nonce`를 사용합니다. ID 토큰은 IdP의 키로 서명을 검증하고 issuer, audience, 만료를 확인합니다.
- 세션은 256비트 난수 쿠키입니다(`HttpOnly`, `SameSite=Lax`, HTTPS면 `Secure`). DB에는 SHA-256 해시만 저장합니다.
- 모든 폼에 세션별 CSRF 토큰이 들어갑니다.
- 로그아웃하면 Patchline 세션이 끝납니다. IdP 세션은 대부분의 SSO 애플리케이션처럼 유지됩니다.
