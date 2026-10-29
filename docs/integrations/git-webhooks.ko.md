# Gitea, Forgejo, GitHub Webhook

[English](git-webhooks.md) | 한국어

Patchline은 `POST /webhooks/gitea`에서 `pull_request` 이벤트를 받습니다. Gitea, Forgejo, GitHub 모두 같은 엔드포인트를 씁니다(payload 형식이 같음).

## Patchline 설정

```sh
PATCHLINE_GITEA_WEBHOOK_SECRET=<충분히 긴 임의 문자열>
```

Secret을 설정하면 모든 요청에 올바른 HMAC-SHA256 서명(`X-Gitea-Signature`, `X-Forgejo-Signature`, GitHub의 `X-Hub-Signature-256`)이 있어야 합니다. 설정하지 않으면 `PATCHLINE_WEBHOOK_TOKEN`(`?token=...`)으로 인증합니다. 이 방식은 신뢰할 수 있는 네트워크에서만 쓰세요.

## Gitea / Forgejo

**저장소 → Settings → Webhooks → Add webhook → Gitea**(또는 Forgejo). 모든 저장소에 한 번에 적용하려면 **조직**에 추가하세요.

| 항목 | 값 |
|---|---|
| Target URL | `https://patchline.example.com/webhooks/gitea` |
| HTTP method | POST |
| Content type | `application/json` |
| Secret | `PATCHLINE_GITEA_WEBHOOK_SECRET` |
| Trigger on | Custom events → **Pull request** |

## GitHub

**저장소(또는 조직) → Settings → Webhooks → Add webhook**

| 항목 | 값 |
|---|---|
| Payload URL | `https://patchline.example.com/webhooks/gitea` |
| Content type | `application/json` |
| Secret | `PATCHLINE_GITEA_WEBHOOK_SECRET` |
| Events | Let me select individual events → **Pull requests** |

## 동작

| 이벤트 | Patchline |
|---|---|
| 열림, 다시 열림, 갱신, 수정 | 업데이트 내용을 읽어 열린 Finding과 연결([Renovate](renovate.ko.md) 참고) |
| Merge로 닫힘 | Finding → 검증대기. Merge 커밋 기록 |
| Merge 없이 닫힘 | 타임라인에 기록하고 상태는 유지 |
| 그 밖의 이벤트(ping, push 등) | `202`로 응답하고 무시 |

같은 이벤트가 다시 와도 delivery id로 중복을 걸러냅니다.

## 인벤토리

저장소 전체 이름(`owner/name`)이 인벤토리의 `repo`에 있어야 하고, Finding은 그 저장소에 연결된 Dependency-Track 프로젝트에서 와야 합니다.

## 확인

Pull request 이벤트로 **Test delivery**(Gitea/Forgejo) 또는 **Redeliver**(GitHub)를 실행하면 Patchline이 `202`로 응답합니다. `401`이면 Secret이 다릅니다.
