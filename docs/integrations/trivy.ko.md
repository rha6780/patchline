# Trivy

[English](trivy.md) | 한국어

Trivy는 두 곳에서 쓸 수 있고, 어느 쪽이든 Dependency-Track을 거쳐 Patchline으로 들어옵니다. Patchline 쪽에는 Trivy 설정이 필요 없습니다.

| 용도 | 하는 일 | 가이드 |
|---|---|---|
| CI의 SBOM 생성기 | `trivy fs` / `trivy image`로 Dependency-Track에 올릴 CycloneDX BOM 생성 | [CI의 SBOM 생성](sbom-ci.ko.md) |
| Dependency-Track 분석기 | Dependency-Track이 BOM의 구성요소를 Trivy 서버로 보내고, Trivy 결과를 자체 결과에 추가 | 이 문서 |

분석기로 쓰면 NVD, GHSA, OSV에 더해 Trivy 취약점 DB(OS 패키지의 배포판 보안 권고 포함)로도 대조합니다. 이 결과도 같은 알림, 같은 재스캔 해결 판정으로 Patchline에 들어옵니다.

## 1. Trivy 서버 실행

[직접 설치용 compose](../../deploy/self-hosted/README.ko.md)를 쓴다면 `.env`에 `TRIVY_TOKEN`을 넣고 `trivy` 프로필을 추가합니다.

```sh
docker compose --profile dependency-track --profile trivy up -d     # 또는 make up PROFILE="dependency-track trivy"
```

처음 실행할 때 DB를 내려받고(`docker compose logs trivy`에 `Listening 0.0.0.0:8080...`), `trivy-cache` 볼륨에 보관합니다. 호스트 포트는 열지 않으며, Dependency-Track은 `http://trivy:8080`으로 접속합니다.

다른 환경에서는 같은 이미지를 서버 모드로 띄웁니다.

```sh
docker run -d --name trivy -p 8083:8080 -v trivy-cache:/root/.cache/trivy \
  -e TRIVY_LISTEN=0.0.0.0:8080 -e TRIVY_TOKEN=<token> aquasec/trivy:<version> server
```

버전(`TRIVY_VERSION`)은 검토한 것으로 고정하세요. Dependency-Track이 쓰는 REST API는 공개 문서가 없으므로, Trivy를 올린 뒤에는 분석이 되는지 확인하세요.

## 2. Dependency-Track에서 분석기 켜기

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

끝나면 그 키는 지우세요. Patchline이 쓰는 키는 읽기 전용(`VIEW_VULNERABILITY`, `VIEW_PORTFOLIO`)으로 유지합니다.

## 인터넷이 막힌 서버

Trivy DB를 사내 OCI 레지스트리에 미러링하고 `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY`를 지정합니다(예: `registry.internal/aquasec/trivy-db:2`, `registry.internal/aquasec/trivy-java-db:1`).

## 확인

1. BOM을 올립니다([CI의 SBOM 생성](sbom-ci.ko.md) 참고).
2. `docker compose logs dtrack-apiserver | grep Trivy`에 해당 프로젝트의 `Trivy vulnerability analysis complete`가 보입니다.
3. 새 Finding은 평소처럼 Patchline에 들어오고, Dependency-Track에서는 분석기가 Trivy로 표시됩니다.

| 증상 | 원인 |
|---|---|
| `TrivyAnalysisTask` 로그가 없음 | 분석기가 꺼져 있거나, 켜기 전에 BOM을 올림(다시 업로드) |
| Dependency-Track 로그에 인증 오류 | API Token이 `TRIVY_TOKEN`과 다름 |
| Connection refused | Base URL이 틀렸거나 Trivy가 아직 DB를 내려받는 중 |
