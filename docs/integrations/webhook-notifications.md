# Webhook notifications

English | [한국어](webhook-notifications.ko.md)

Patchline can POST a JSON request for each finding and each later change to a URL of your choice: a ticketing system, a Teams or Power Automate workflow, an internal event bus. It runs next to Slack, with its own threshold and filters.

## Settings

```sh
PATCHLINE_NOTIFY_WEBHOOK_URL=https://hooks.example.com/patchline
PATCHLINE_NOTIFY_WEBHOOK_SECRET=...            # signs every request (recommended)
PATCHLINE_NOTIFY_WEBHOOK_MIN_SEVERITY=high     # default PATCHLINE_NOTIFY_MIN_SEVERITY
PATCHLINE_NOTIFY_WEBHOOK_SERVICES=storefront,payments   # default: all services
PATCHLINE_NOTIFY_WEBHOOK_ENVIRONMENTS=prod     # default: all environments
PATCHLINE_PUBLIC_URL=https://patchline.example.com      # adds finding.url
```

Slack takes the same filters as `PATCHLINE_SLACK_MIN_SEVERITY`, `PATCHLINE_SLACK_SERVICES` and `PATCHLINE_SLACK_ENVIRONMENTS`. Without Slack and a webhook, messages are printed to stdout.

## Requests

| Header | Value |
|---|---|
| `X-Patchline-Event` | `finding.opened` or `finding.event` |
| `X-Patchline-Delivery` | `42.opened`, `42.9` (finding id, event id). The same on retries, so drop duplicates by it |
| `X-Patchline-Signature-256` | `sha256=` + hex HMAC-SHA256 of the body with the secret (only with a secret) |

- `finding.opened`: a finding reached the threshold for the first time (after its first policy evaluation, so it has a due date).
- `finding.event`: anything that happened later (state, severity or due date change, fix PR, reminder, assignment, request). It has an `event` object.

Both carry the finding's current state:

```json
{
  "schema": "patchline.notification/v1",
  "type": "finding.event",
  "delivery": "42.9",
  "sent_at": "2026-11-03T01:02:04Z",
  "text": "State: 🆕 New → 🛠️ In progress",
  "finding": {
    "id": 42, "url": "https://patchline.example.com/findings/42",
    "vuln_id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "title": "...",
    "severity": "critical", "scanner_severity": "high", "sla_reasons": ["in CISA KEV"], "kev": true,
    "state": "in_progress", "service": "storefront", "registered": true, "owners": ["alice@example.com"],
    "environment": "prod", "repository": "acme/storefront-api",
    "component": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    "assignee": "bob@example.com", "due_at": "2026-11-10T00:00:00Z", "first_seen_at": "2026-11-03T00:00:00Z"
  },
  "event": {"id": 9, "kind": "state_changed", "from_state": "new", "to_state": "in_progress",
            "evidence": {"by_name": "Bob"}, "occurred_at": "2026-11-03T01:02:03Z"},
  "pull_requests": [{"repository": "acme/storefront-api", "number": 12, "url": "...", "state": "open", "to_version": "2.17.1", "verdict": "fixes"}]
}
```

Fields may be added within `v1`; ignore the ones you do not know. `text` is in `PATCHLINE_NOTIFY_LANG`.

## Checking the signature

```python
import hmac, hashlib
def valid(secret: bytes, body: bytes, header: str) -> bool:
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header)
```

Compute it over the raw body, before parsing.

## Delivery

- Any `2xx` is success. `429` and `503` pause delivery for `Retry-After` (30 s without one); other responses and network errors are retried with backoff up to an hour.
- Events are sent in order per finding; a finding's next event waits until the current one succeeds.
- Failed deliveries are listed under **Integrations → Notification failures** with sink `webhook`.
- Setting the URL on a database with many open findings sends all of those that match. Set the filters first.
