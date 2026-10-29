# 직접 설치(Docker Compose)

[English](README.md) | 한국어

서버 한 대나 로컬 PC에서 Patchline을 실행합니다. 기본은 Patchline만 띄우고 이미 쓰고 있는 Dependency-Track에 연결합니다. `dependency-track` 프로필을 켜면 Dependency-Track(API 서버, 프론트엔드, PostgreSQL)도 함께 띄웁니다.

샘플 데이터로 빠르게 둘러보려면 [Compose 데모](../compose/README.md)를 쓰세요.

| 파일 | |
|---|---|
| `docker-compose.yml` | Patchline, 그리고 Dependency-Track(`dependency-track` 프로필)과 Trivy 서버(`trivy` 프로필) |
| `.env.example` | 설정. `.env`로 복사해서 사용 |
| `scripts/enable-trivy.sh` | Dependency-Track API로 Trivy 분석기를 켬 |
| `config/` | 인벤토리와 정책. `/etc/patchline`에 읽기 전용으로 마운트(커밋하지 않음) |

## 1. 설정

```sh
cd deploy/self-hosted
cp .env.example .env
mkdir -p config
cp -r ../../examples/inventory config/          # config/inventory/*.yaml을 수정
cp ../../examples/policy/policy.yaml config/     # 선택
```

`.env`에서 최소한 아래 값을 채웁니다.

| 변수 | |
|---|---|
| `PATCHLINE_WEBHOOK_TOKEN` | 필수. `openssl rand -hex 32` |
| `PATCHLINE_DT_URL`, `PATCHLINE_DT_API_KEY` | Dependency-Track API 서버 주소와 `VIEW_VULNERABILITY`, `VIEW_PORTFOLIO` 권한의 키 |
| `PATCHLINE_DT_UI_URL` | 링크에 쓸 Dependency-Track UI 주소 |
| `PATCHLINE_POLICY_PATH` | 정책을 복사했다면 `/etc/patchline/policy.yaml` |
| `PATCHLINE_SLACK_BOT_TOKEN`, `PATCHLINE_SLACK_DEFAULT_CHANNEL` | 선택. 없으면 메시지를 로그로 출력 |

전체 변수는 [docs/configuration.ko.md](../../docs/configuration.ko.md)에 있습니다. 인벤토리 변경을 리뷰받고 싶다면 `config/`를 별도 Git 저장소로 관리하고, `PATCHLINE_CONFIG_DIR`을 그 checkout 경로로 지정하세요.

## 2. 실행

이미 Dependency-Track이 있는 경우:

```sh
docker compose up -d --build
docker compose ps           # patchline이 "healthy"여야 함
curl -s http://127.0.0.1:8080/readyz
```

Dependency-Track도 함께 띄우려면 `.env`에 `DT_DB_PASSWORD`를 넣고 `PATCHLINE_DT_URL=http://dtrack-apiserver:8080`으로 설정한 뒤 실행합니다.

```sh
docker compose --profile dependency-track up -d --build
```

| | URL |
|---|---|
| Patchline | http://localhost:8080 |
| Dependency-Track UI | http://localhost:8082 (첫 로그인 `admin` / `admin`, 바로 변경하세요) |
| Dependency-Track API | http://localhost:8081 |

Trivy 분석기를 추가하려면 `TRIVY_TOKEN`을 넣고 `--profile trivy`를 붙입니다. Dependency-Track에서 켜는 방법(`scripts/enable-trivy.sh`)은 [Trivy](../../docs/integrations/trivy.ko.md)를 참고하세요.

Dependency-Track API 서버는 메모리를 몇 GB 사용하므로 Docker에 8 GB 이상 할당하세요. 처음 실행할 때는 취약점 데이터를 내려받느라 몇 분 걸립니다. 그다음 Patchline용 API 키를 만들어 `.env`에 넣고 `docker compose up -d`를 다시 실행합니다.

## 3. 도구 연결

[연동 가이드](../../docs/README.ko.md)를 따릅니다. Webhook 주소는 보내는 쪽이 어디서 실행되는지에 따라 다릅니다.

| 보내는 쪽 | Patchline 주소 |
|---|---|
| 이 compose 파일의 Dependency-Track | `http://patchline:8080/webhooks/dependency-track?token=...` |
| 다른 곳의 Dependency-Track, Gitea, Forgejo, GitHub | `https://<프록시 주소>/webhooks/...` 또는 `PATCHLINE_BIND=0.0.0.0`으로 열고 `http://<서버>:8080/...` |

## 외부에 공개하기

포트는 기본으로 `127.0.0.1`에만 열립니다. `PATCHLINE_BIND=0.0.0.0`으로 바꾸기 전에 [OIDC 로그인](../../docs/access-control.ko.md)을 켜거나, 사용자를 인증하는 리버스 프록시(예: oauth2-proxy) 뒤에 두세요. 어느 쪽이든 앞단에서 TLS를 처리하세요. Webhook 경로(`/webhooks/*`)는 자체 인증이 있습니다.

로그인을 쓰려면 접근 정책을 `config/access-policy.yaml`에 두고([예시](../../examples/access/access-policy.yaml)에서 시작), `.env`에 `PATCHLINE_OIDC_*` 변수를 설정하세요.

## 인터넷이 막힌 서버

인터넷이 되는 곳에서 이미지를 빌드해 옮깁니다.

```sh
make docker                                   # patchline:<version> 태그
docker save patchline:<version> | gzip > patchline.tar.gz
# 서버에서
docker load < patchline.tar.gz
# .env: PATCHLINE_IMAGE=patchline:<version>
docker compose up -d                          # --build 없이
```

CISA KEV 피드는 사내에 미러링해서 `PATCHLINE_KEV_URL`로 지정하거나 `off`로 끕니다([CISA KEV, EPSS](../../docs/integrations/kev-epss.ko.md) 참고).

## 운영

| 작업 | 명령 |
|---|---|
| 로그 | `docker compose logs -f patchline` |
| 인벤토리·정책 다시 읽기 | `docker compose restart patchline` |
| 업그레이드 | `git pull && docker compose up -d --build`(시작할 때 마이그레이션 실행) |
| 중지 | `docker compose down`(데이터는 볼륨에 남음) |
| 데이터까지 모두 삭제 | `docker compose down -v` |

SQLite DB는 Patchline을 멈춘 상태에서 `patchline-data` 볼륨을 복사해 백업합니다.

```sh
docker compose stop patchline
docker run --rm -v patchline_patchline-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/patchline-data.tgz -C /data .
docker compose start patchline
```

컨테이너는 non-root 사용자, 읽기 전용 루트 파일시스템, capability 없이 실행되며 `/data`만 쓸 수 있습니다.
