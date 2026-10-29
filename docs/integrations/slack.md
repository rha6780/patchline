# Slack

English | [한국어](slack.ko.md)

Patchline posts **one message per finding** and keeps it current: state, due date and fix PRs are edited in place, and every change is added to the message's thread.

## 1. Create the Slack app

1. <https://api.slack.com/apps> → **Create New App** → From scratch.
2. **OAuth & Permissions → Bot Token Scopes**: add `chat:write`, and `chat:write.public` to post in public channels without inviting the bot.
3. **Install to Workspace** and copy the **Bot User OAuth Token** (`xoxb-...`).
4. For private channels, invite the bot: `/invite @your-app`.

## 2. Patchline settings

```sh
PATCHLINE_SLACK_BOT_TOKEN=xoxb-...
PATCHLINE_SLACK_DEFAULT_CHANNEL=#security     # services without slack_channel, unregistered projects
PATCHLINE_NOTIFY_MIN_SEVERITY=medium          # effective severity; critical | high | medium | low | info
PATCHLINE_NOTIFY_LANG=en                      # en | ko
PATCHLINE_DT_UI_URL=https://dtrack.example.com  # adds "Open in Dependency-Track" links
```

Without a token, the same messages are printed to Patchline's log, which is handy for trying things out.

## 3. Channels per service

```yaml
# inventory
services:
  - name: storefront
    slack_channel: "#team-storefront"
```

A finding goes to its service's channel, otherwise to `PATCHLINE_SLACK_DEFAULT_CHANNEL`. With neither, it is not posted (the UI still shows it).

## What gets posted

| Change | In the message | In the thread |
|---|---|---|
| New finding (after its first policy evaluation) | Posted with severity, component, owners, due date | — |
| Analysis decision in Dependency-Track | State | "State: New → In progress (…)" |
| Fix PR opened / merged / closed | Fix PR field | PR, versions, verdict, merge commit |
| Escalation (KEV, EPSS) or due date change | Severity, due date | Reason and new due date |
| Due soon / overdue | Due date | Reminder |
| Resolved / reopened by a rescan | State | Commit and ref |

Findings below `PATCHLINE_NOTIFY_MIN_SEVERITY`, and findings closed before they were ever posted, are not posted.

## Delivery

- Progress is stored per finding, so restarts and Slack outages only delay messages.
- `429` responses pause delivery for `Retry-After`; other errors are retried with backoff.
- The first sync after installing Patchline on a database with many open findings posts all of them that meet the threshold; raise `PATCHLINE_NOTIFY_MIN_SEVERITY` first if that is too many.

## Check

**Integrations → Notification failures** in the UI lists failed deliveries with Slack's error.

| Error | Fix |
|---|---|
| `not_in_channel` | Invite the bot, or add `chat:write.public` for public channels |
| `channel_not_found` | Channel name in the inventory is wrong, or the channel is private and the bot was not invited |
| `invalid_auth` / `not_authed` | Token is wrong or the app was uninstalled |
| `missing_scope` | Add the scope and reinstall the app |
