# Trivy

[English](trivy.md) | 한국어

Trivy는 Patchline과 함께 최대 세 가지 역할을 합니다.

| 용도 | 하는 일 | 가이드 |
|---|---|---|
| Patchline의 엔진 | Patchline이 업로드된 SBOM의 OS 패키지(deb, rpm, apk)를 Trivy 서버로 보내고, 결과를 Finding으로 기록 | 이 문서 |
| CI의 SBOM 생성기 | `trivy fs` / `trivy image`로 CI가 올릴 CycloneDX SBOM 생성 | [CI의 SBOM 생성](sbom-ci.ko.md) |
| Dependency-Track 분석기(선택) | Dependency-Track이 BOM의 구성요소를 같은 Trivy 서버로 보냄 | [아래](#선택-dependency-track-분석기) |

언어 패키지는 Patchline의 OSV 미러로 대조하고, OSV가 잘 다루지 못하는 OS 패키지의 배포판 보안 권고는 Trivy가 맡습니다. 대조 결과가 Finding이 되는 과정은 [탐지](native-detection.ko.md)를 보세요.

## 1. Trivy 서버 실행

[직접 설치용 compose](../../deploy/self-hosted/README.ko.md)는 Patchline 옆에 Trivy 서버를 함께 띄웁니다. `.env`에 `TRIVY_TOKEN`(`openssl rand -hex 32`)을 넣고 `docker compose up -d`를 실행하세요. [데모](../../deploy/compose/README.md)에도 Trivy 서버가 있습니다.

처음 실행할 때 DB를 내려받고(`docker compose logs trivy`에 `Listening 0.0.0.0:8080...`), `trivy-cache` 볼륨에 보관합니다. 호스트 포트는 열지 않으며, Patchline은 `http://trivy:8080`으로 접속합니다.

다른 환경에서는 같은 이미지를 서버 모드로 띄웁니다.

```sh
docker run -d --name trivy -p 8083:8080 -v trivy-cache:/root/.cache/trivy \
  -e TRIVY_LISTEN=0.0.0.0:8080 -e TRIVY_TOKEN=<token> aquasec/trivy:<version> server
```

버전(`TRIVY_VERSION`)은 검토한 것으로 고정하세요. Patchline과 Dependency-Track이 쓰는 Trivy 서버 API는 공개 문서가 없으므로, Trivy를 업그레이드한 뒤에는 업로드가 계속 대조되는지 확인하세요.

## 2. Patchline 연결

Compose 구성에서는 자동으로 설정됩니다. 다른 환경에서는 다음과 같이 설정합니다.

```sh
PATCHLINE_TRIVY_URL=http://trivy:8080
PATCHLINE_TRIVY_TOKEN=<서버의 TRIVY_TOKEN>
PATCHLINE_TRIVY_SCOPE=os        # all: 언어 패키지도 보냄(OSV 결과와 합쳐짐)
```

Trivy 없이 쓰려면 `PATCHLINE_TRIVY_URL=`(빈 값)로 둡니다. 그러면 언어 패키지만 대조합니다.

- OS 패키지의 purl에는 `distro` 한정자가 필요합니다(`pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u4?distro=debian-11.6`). `trivy image --format cyclonedx`는 이 한정자를 넣어 줍니다. 한정자가 없는 패키지는 건너뜁니다.
- Debian·Ubuntu 권고는 소스 패키지 이름을 씁니다. Trivy의 `aquasecurity:trivy:SrcName` 속성(또는 Syft의 `upstream` 한정자)을 읽어 `libssl1.1`을 `openssl`로 조회합니다.
- 업로드 한 번마다 OS 릴리스별로 Trivy 스캔을 한 번씩 합니다. Trivy에 연결할 수 없으면 업로드를 재시도하고, 그동안은 해결 판정을 하지 않습니다.
- 배포판 권고 하나(`DLA-3942-1`)가 CVE 여러 개를 고쳐도 CVE마다 별도 Finding입니다. 권고 ID는 별칭으로 보관합니다.

## 인터넷이 막힌 서버

Trivy DB를 사내 OCI 레지스트리에 미러링하고 `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY`를 지정합니다(예: `registry.internal/aquasec/trivy-db:2`, `registry.internal/aquasec/trivy-java-db:1`).

## 확인

1. 이미지 SBOM(`trivy image --format cyclonedx`)을 올립니다([CI의 SBOM 생성](sbom-ci.ko.md) 참고).
2. Patchline 로그에 `sbom analyzed … result="N findings (N new), 0 resolved"`가 남습니다.
3. 해당 Finding의 타임라인에 *Patchline에서 탐지 (Trivy, CVE-…)*가 표시됩니다.

| 증상 | 원인 |
|---|---|
| 업로드가 **연동 상태 → 처리 실패(업로드·Webhook)**에 나오고 재시도됨 | Trivy에 연결할 수 없거나 아직 DB를 내려받는 중, 또는 `PATCHLINE_TRIVY_TOKEN`이 서버 토큰과 다름 |
| 오래된 패키지가 있는 이미지인데 `0 findings` | purl에 `distro` 한정자가 없음. `trivy image`나 배포판을 지정한 Syft로 SBOM을 만드세요 |

## (선택) Dependency-Track 분석기

[Dependency-Track](dependency-track.ko.md)도 쓴다면 같은 Trivy 서버를 분석기로 쓸 수 있습니다. 그러면 NVD, GHSA, OSV에 더해 Trivy DB로도 대조합니다. 직접 설치용 구성에서는 `docker compose --profile dependency-track up -d`로 띄우며, Dependency-Track은 `http://trivy:8080`으로 Trivy에 접속합니다.

**Administration → Analyzers → Trivy**

| 항목 | 값 |
|---|---|
| Enable | 켬 |
| Base URL | `http://trivy:8080`(같은 compose 네트워크) 또는 서버 주소 |
| API Token | `TRIVY_TOKEN` |
| Ignore Unfixed | 선택: 수정 버전이 없는 취약점 제외 |

또는 `SYSTEM_CONFIGURATION` 권한의 임시 키로 API를 호출합니다.

```sh
cd deploy/self-hosted
DT_URL=http://localhost:8081 DT_ADMIN_KEY=odt_... TRIVY_TOKEN=<token> ./scripts/enable-trivy.sh
```

끝나면 그 키는 지우세요. Patchline이 쓰는 키는 그대로 둡니다(`VIEW_VULNERABILITY`, `VIEW_PORTFOLIO`, 판정을 기록하려면 `VULNERABILITY_ANALYSIS`).

이후 `docker compose logs dtrack-apiserver | grep Trivy`에 프로젝트마다 `Trivy vulnerability analysis complete`가 보입니다.

| 증상 | 원인 |
|---|---|
| `TrivyAnalysisTask` 로그가 없음 | 분석기가 꺼져 있거나, 켜기 전에 BOM을 올림(다시 업로드) |
| Dependency-Track 로그에 인증 오류 | API Token이 `TRIVY_TOKEN`과 다름 |
| Connection refused | Base URL이 틀렸거나 Trivy가 아직 DB를 내려받는 중 |
