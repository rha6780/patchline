# CISA KEV and EPSS

English | [한국어](kev-epss.ko.md)

Two risk signals adjust the **effective severity**, which sets the due date and the notification threshold.

| Signal | Source | Default effect |
|---|---|---|
| CISA Known Exploited Vulnerabilities | CISA JSON feed, refreshed daily | At least `critical` (7-day SLA) |
| EPSS score | Dependency-Track finding API (`epssScore`) | One level up at ≥ 0.5 |

Both are configured in the [policy](../../examples/policy/policy.yaml):

```yaml
escalation:
  kev: critical         # "" disables
  epss_threshold: 0.5   # 0 disables
```

## KEV

```sh
PATCHLINE_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json  # default
# PATCHLINE_KEV_URL=off                                   # disable
# PATCHLINE_KEV_URL=https://mirror.internal/kev.json      # internal mirror
```

- Patchline downloads the catalog once a day and matches each finding's CVE id and aliases.
- When a CVE is added to the catalog, open findings for it are escalated at the next evaluation; the Slack thread says why and shows the new due date.
- Without internet access, mirror the JSON file internally (a scheduled `curl` to a static file server is enough) and point `PATCHLINE_KEV_URL` at it.
- If a refresh fails, Patchline logs a warning and keeps the catalog it has.

## EPSS

Patchline stores the EPSS score Dependency-Track returns with each finding and uses it at the next evaluation. When Dependency-Track has no EPSS data for a vulnerability, the score is simply absent and nothing changes.

## Check

- Patchline logs `kev catalog refreshed` with the catalog version at startup and daily.
- A finding in KEV shows a **KEV** tag in the UI, and its severity reads e.g. `critical (scanner: medium, in CISA KEV)`.
