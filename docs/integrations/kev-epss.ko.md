# CISA KEV와 EPSS

[English](kev-epss.md) | 한국어

두 위험 신호가 **실효 심각도**를 조정하고, 실효 심각도가 기한과 알림 기준을 정합니다.

| 신호 | 출처 | 기본 효과 |
|---|---|---|
| CISA Known Exploited Vulnerabilities | CISA JSON 피드, 하루 한 번 갱신 | 최소 `critical`(SLA 7일) |
| EPSS 점수 | Dependency-Track Finding API(`epssScore`) | 0.5 이상이면 한 단계 상향 |

둘 다 [정책 파일](../../examples/policy/policy.yaml)에서 설정합니다.

```yaml
escalation:
  kev: critical         # ""이면 사용 안 함
  epss_threshold: 0.5   # 0이면 사용 안 함
```

## KEV

```sh
PATCHLINE_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json  # 기본값
# PATCHLINE_KEV_URL=off                                   # 사용 안 함
# PATCHLINE_KEV_URL=https://mirror.internal/kev.json      # 내부 미러
```

- Patchline은 카탈로그를 최대 하루 한 번 내려받아(마지막 갱신 시각을 저장하므로 재시작해도 다시 받지 않습니다) 각 Finding의 CVE ID와 별칭으로 대조합니다.
- 어떤 CVE가 카탈로그에 추가되면, 다음 평가 때 그 CVE의 열린 Finding이 상향됩니다. Slack 스레드에 사유와 새 기한이 남습니다.
- 인터넷에 접속할 수 없는 환경이면 JSON 파일을 내부에 미러링하고(정적 파일 서버에 주기적으로 `curl`하는 정도로 충분) `PATCHLINE_KEV_URL`을 그 주소로 지정하세요.
- 갱신에 실패하면 경고를 남기고 기존 카탈로그로 계속 동작합니다.

## EPSS

Patchline은 Dependency-Track이 Finding과 함께 돌려주는 EPSS 점수를 저장하고 다음 평가에 사용합니다. Dependency-Track에 해당 취약점의 EPSS 데이터가 없으면 점수가 비어 있을 뿐 아무것도 바뀌지 않습니다.

## 확인

- Patchline은 카탈로그를 내려받을 때마다(처음 시작할 때, 이후 하루 한 번) `kev catalog refreshed` 로그를 카탈로그 버전, 항목 수와 함께 남깁니다.
- KEV에 있는 Finding은 UI에 **CISA KEV** 태그가 붙고, 심각도가 `critical (스캐너: medium, CISA KEV 등재)`처럼 표시됩니다.
