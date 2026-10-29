# Slack

[English](slack.md) | 한국어

Patchline은 **Finding마다 메시지를 하나만** 보내고 계속 갱신합니다. 상태, 기한, 수정 PR은 같은 메시지를 수정해 반영하고, 변경 내용은 메시지 스레드에 남깁니다.

## 1. Slack 앱 만들기

1. <https://api.slack.com/apps> → **Create New App** → From scratch.
2. **OAuth & Permissions → Bot Token Scopes**에 `chat:write`를 추가합니다. 봇을 초대하지 않고 공개 채널에 보내려면 `chat:write.public`도 추가합니다.
3. **Install to Workspace** 후 **Bot User OAuth Token**(`xoxb-...`)을 복사합니다.
4. 비공개 채널은 봇을 초대해야 합니다: `/invite @앱이름`.

## 2. Patchline 설정

```sh
PATCHLINE_SLACK_BOT_TOKEN=xoxb-...
PATCHLINE_SLACK_DEFAULT_CHANNEL=#security     # slack_channel이 없는 서비스와 미등록 프로젝트용
PATCHLINE_NOTIFY_MIN_SEVERITY=medium          # 실효 심각도 기준: critical | high | medium | low | info
PATCHLINE_NOTIFY_LANG=ko                      # en | ko
PATCHLINE_DT_UI_URL=https://dtrack.example.com  # "Dependency-Track에서 열기" 링크 추가
```

토큰이 없으면 같은 메시지를 Patchline 로그로 출력합니다. 처음 시험해 볼 때 유용합니다.

## 3. 서비스별 채널

```yaml
# 인벤토리
services:
  - name: storefront
    slack_channel: "#team-storefront"
```

Finding은 서비스의 채널로, 없으면 `PATCHLINE_SLACK_DEFAULT_CHANNEL`로 갑니다. 둘 다 없으면 보내지 않습니다(UI에는 표시됨).

## 보내는 내용

| 변경 | 메시지 | 스레드 |
|---|---|---|
| 새 Finding(첫 정책 평가 후) | 심각도, 구성요소, 담당자, 기한과 함께 전송 | — |
| Dependency-Track 분석 판정 | 상태 | "상태: 신규 → 조치중 (…)" |
| 수정 PR 열림 / 병합 / 닫힘 | 수정 PR 항목 | PR, 버전, 판정, 병합 커밋 |
| 상향(KEV, EPSS) 또는 기한 변경 | 심각도, 기한 | 사유와 새 기한 |
| 기한 임박 / 초과 | 기한 | 재알림 |
| 재스캔으로 해결 / 재발 | 상태 | 커밋과 ref |

`PATCHLINE_NOTIFY_MIN_SEVERITY`보다 낮은 Finding과, 알리기 전에 이미 종료된 Finding은 보내지 않습니다.

## 전송

- Finding별로 진행 상황을 저장하므로 재시작이나 Slack 장애가 있어도 메시지가 늦어질 뿐 빠지지 않습니다.
- `429`를 받으면 `Retry-After`만큼 쉬고, 그 밖의 오류는 간격을 늘려 재시도합니다.
- 열린 Finding이 많은 DB에서 처음 연결하면 기준을 넘는 건이 한꺼번에 전송됩니다. 너무 많다면 먼저 `PATCHLINE_NOTIFY_MIN_SEVERITY`를 올리세요.

## 확인

UI의 **연동 상태 → 알림 실패**에 실패한 전송과 Slack 오류가 표시됩니다.

| 오류 | 해결 |
|---|---|
| `not_in_channel` | 봇을 초대하거나, 공개 채널이면 `chat:write.public` 추가 |
| `channel_not_found` | 인벤토리의 채널 이름이 틀렸거나, 비공개 채널에 봇을 초대하지 않음 |
| `invalid_auth` / `not_authed` | 토큰이 틀렸거나 앱이 삭제됨 |
| `missing_scope` | 권한을 추가하고 앱을 다시 설치 |
