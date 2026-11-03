# Webhook 알림

[English](webhook-notifications.md) | 한국어

Patchline은 Finding이 생기거나 바뀔 때마다 지정한 URL로 JSON 요청을 보낼 수 있습니다. 티켓 시스템, Teams·Power Automate 워크플로, 사내 이벤트 버스 등에 연결할 수 있습니다. Slack과 동시에 동작하며 기준 심각도와 필터를 따로 둘 수 있습니다.

## 설정

```sh
PATCHLINE_NOTIFY_WEBHOOK_URL=https://hooks.example.com/patchline
PATCHLINE_NOTIFY_WEBHOOK_SECRET=...            # 모든 요청에 서명 (권장)
PATCHLINE_NOTIFY_WEBHOOK_MIN_SEVERITY=high     # 기본값 PATCHLINE_NOTIFY_MIN_SEVERITY
PATCHLINE_NOTIFY_WEBHOOK_SERVICES=storefront,payments   # 기본값: 모든 서비스
PATCHLINE_NOTIFY_WEBHOOK_ENVIRONMENTS=prod     # 기본값: 모든 환경
PATCHLINE_PUBLIC_URL=https://patchline.example.com      # finding.url 추가
```

Slack에도 같은 필터를 `PATCHLINE_SLACK_MIN_SEVERITY`, `PATCHLINE_SLACK_SERVICES`, `PATCHLINE_SLACK_ENVIRONMENTS`로 지정할 수 있습니다. Slack과 Webhook이 모두 없으면 메시지를 stdout으로 출력합니다.

## 요청

| 헤더 | 값 |
|---|---|
| `X-Patchline-Event` | `finding.opened` 또는 `finding.event` |
| `X-Patchline-Delivery` | `42.opened`, `42.9`(Finding ID, 이벤트 ID). 재시도해도 같으므로 이 값으로 중복을 거르면 됩니다 |
| `X-Patchline-Signature-256` | 본문을 secret으로 HMAC-SHA256한 hex 값에 `sha256=`를 붙인 값 (secret이 있을 때만) |

- `finding.opened`: Finding이 처음으로 기준을 넘었을 때. 첫 정책 평가 뒤에 보내므로 기한이 들어 있습니다.
- `finding.event`: 이후 생긴 모든 변경(상태·심각도·기한 변경, 수정 PR, 리마인더, 담당자 지정, 요청). `event` 객체가 붙습니다.

두 요청 모두 Finding의 현재 상태를 담습니다. 본문 예시와 필드는 [영문 문서](webhook-notifications.md#requests)와 같습니다.

`v1` 안에서는 필드가 추가될 수 있으니 모르는 필드는 무시하세요. `text`는 `PATCHLINE_NOTIFY_LANG` 언어로 작성됩니다.

## 서명 확인

```python
import hmac, hashlib
def valid(secret: bytes, body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

파싱하기 전의 원본 본문으로 계산해야 합니다.

## 전달

- `2xx`면 성공입니다. `429`, `503`은 `Retry-After`만큼(없으면 30초) 멈췄다 다시 보냅니다. 그 밖의 응답과 네트워크 오류는 최대 1시간까지 간격을 늘려 재시도합니다.
- Finding마다 이벤트를 순서대로 보냅니다. 앞 이벤트가 성공해야 다음 이벤트를 보냅니다.
- 실패한 전달은 **연동 → 알림 실패**에 sink `webhook`으로 표시됩니다.
- 열린 Finding이 많은 DB에 URL을 설정하면 조건에 맞는 Finding이 모두 전송됩니다. 필터부터 설정하세요.
