# Gitea, Forgejo and GitHub webhooks

English | [한국어](git-webhooks.ko.md)

Patchline receives `pull_request` events at `POST /webhooks/gitea`. The same endpoint accepts Gitea, Forgejo and GitHub; the payloads have the same shape.

## Patchline settings

```sh
PATCHLINE_GITEA_WEBHOOK_SECRET=<long random string>
```

With a secret, every request must carry a valid HMAC-SHA256 signature (`X-Gitea-Signature`, `X-Forgejo-Signature` or GitHub's `X-Hub-Signature-256`). Without one, the endpoint falls back to `PATCHLINE_WEBHOOK_TOKEN` (`?token=...`); use that only on a trusted network.

## Gitea / Forgejo

**Repository → Settings → Webhooks → Add webhook → Gitea** (or Forgejo). To cover every repository at once, add it to the **organization** instead.

| Field | Value |
|---|---|
| Target URL | `https://patchline.example.com/webhooks/gitea` |
| HTTP method | POST |
| Content type | `application/json` |
| Secret | `PATCHLINE_GITEA_WEBHOOK_SECRET` |
| Trigger on | Custom events → **Pull request** |

## GitHub

**Repository (or organization) → Settings → Webhooks → Add webhook**

| Field | Value |
|---|---|
| Payload URL | `https://patchline.example.com/webhooks/gitea` |
| Content type | `application/json` |
| Secret | `PATCHLINE_GITEA_WEBHOOK_SECRET` |
| Events | Let me select individual events → **Pull requests** |

## What happens

| Event | Patchline |
|---|---|
| Opened, reopened, synchronized, edited | Reads the updates and links matching open findings (see [Renovate](renovate.md)) |
| Closed with merge | Finding → awaiting verification; the merge commit is recorded |
| Closed without merge | Recorded on the timeline; the state stays |
| Other events (ping, push, ...) | Acknowledged with `202` and ignored |

Redelivered events are de-duplicated by delivery id.

## Inventory

The repository's full name (`owner/name`) must be listed as `repo` in the inventory, and its findings must come from a Dependency-Track project mapped to that repository.

## Check

Use **Test delivery** (Gitea/Forgejo) or **Redeliver** (GitHub) on a pull request event: Patchline answers `202`. A `401` means the secret differs.
