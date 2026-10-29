# Sign-in and permissions

English | [한국어](access-control.ko.md)

Every page and API call needs a sign-in. There are two ways in:

- **Local admin**: a built-in `admin` account for first-time setup and as a fallback when single sign-on is down. It holds every permission.
- **Single sign-on** with OpenID Connect (FusionAuth, Keycloak, Okta, Entra ID, Google and others) for everyone else. The groups or roles in their ID token decide what they can do:

| Permission | Allows |
|---|---|
| `findings.read` | Open the web UI and `GET /api/v1/*` |
| `findings.assign` | Set or clear a finding's assignee |
| `exceptions.request` | Request a **risk acceptance** or a **due date extension** |
| `exceptions.approve` | Approve or reject other people's requests |
| `settings.webhooks` | View (as hints) and rotate the webhook token and the Git webhook secret |
| `audit.read` | View the audit log |
| `*` | All of the above |

Webhooks (`/webhooks/*`) and health checks never need a session; they authenticate with their own secrets.

## Local admin

On first start Patchline creates the account `admin` with the password `admin`, and logs a warning until it is changed.

1. Open Patchline and sign in as `admin` / `admin`.
2. Choose a new password: at least 12 characters, not `admin`. Until then every page leads to the password form and the API answers `403`.

| | |
|---|---|
| Lockout | 5 failed sign-ins in a row lock the account for 15 minutes |
| Password change | Ends the admin's other sessions |
| Lost password | `patchline reset-admin-password` (with the same `PATCHLINE_DB_PATH`) sets it back to `admin`, to be changed at the next sign-in, and ends its sessions. In the self-hosted setup: `docker compose run --rm patchline reset-admin-password` |
| Turn it off | `PATCHLINE_LOCAL_ADMIN=false` once single sign-on works; its sessions end |

Change the default password **before** exposing Patchline beyond localhost: until then, anyone who can reach the sign-in page can take the account.

`PATCHLINE_ALLOW_ANONYMOUS=true` lets requests without a session read (UI and API), for deployments where an authenticating proxy already guards Patchline. Changes still need a sign-in.

## 1. Register Patchline with the identity provider

Create an OIDC application (confidential client, authorization code flow):

| Setting | Value |
|---|---|
| Redirect URI | `https://patchline.example.com/auth/callback` (`PATCHLINE_PUBLIC_URL` + `/auth/callback`) |
| Grant | Authorization code. Patchline always sends PKCE (S256) |
| Scopes | `openid profile email`, plus whatever puts groups in the ID token |
| ID token claims | `sub`, `email`, `name`, and a groups or roles claim |

### FusionAuth

1. **Applications → Add**: on the **OAuth** tab, set the authorized redirect URL and enable the *Authorization Code* grant. Turn on *Require PKCE* if you like.
2. **Roles** tab: add roles such as `patchline-approver`, `patchline-developer`, `patchline-ops`.
3. Give people roles through **Groups**: a group can grant application roles, so team membership drives access.
4. By default FusionAuth puts roles in the access token, not the ID token. Add a **JWT populate lambda**, and select it as the application's *Id Token populate lambda* (**Applications → Edit → JWT**):

   ```js
   function populate(jwt, user, registration) {
     jwt.roles = (registration && registration.roles) || [];
   }
   ```

5. In Patchline set `PATCHLINE_OIDC_GROUPS_CLAIM=roles` and use the role names in the access policy.

The issuer is `https://<fusionauth-host>` (or `https://<host>/<tenant-id>` when you have several tenants; check `iss` in the discovery document).

### Keycloak

Create a confidential client with the redirect URI. Then add a *Group Membership* mapper (claim `groups`, *Full group path* off, *Add to ID token* on). For realm roles, read `realm_access.roles` instead (`PATCHLINE_OIDC_GROUPS_CLAIM=realm_access.roles`). Issuer: `https://<host>/realms/<realm>`.

### Others

| Provider | Groups claim | Note |
|---|---|---|
| Okta | `groups` | Add a *groups* claim to the ID token (filter, for example, *starts with* `patchline-`) |
| Microsoft Entra ID | `groups` or `roles` | Group claims are object ids; app roles (`roles`) are easier to read in a policy |
| Google | — | No groups in the token; use `users:` entries by email |

## 2. Configure Patchline

```sh
PATCHLINE_PUBLIC_URL=https://patchline.example.com
PATCHLINE_OIDC_ISSUER=https://auth.example.com
PATCHLINE_OIDC_CLIENT_ID=...
PATCHLINE_OIDC_CLIENT_SECRET=...
PATCHLINE_OIDC_GROUPS_CLAIM=groups          # comma-separated; dotted names read nested claims
PATCHLINE_OIDC_SCOPES=profile,email          # besides openid
PATCHLINE_SESSION_TTL=12h
PATCHLINE_ACCESS_POLICY_PATH=/etc/patchline/access-policy.yaml
```

Patchline reads the provider's discovery document at startup and does not start if it cannot. Serve it over HTTPS: the session cookie is `Secure` when `PATCHLINE_PUBLIC_URL` is `https://`.

## 3. Map groups to permissions

```yaml
# access-policy.yaml (example: examples/access/access-policy.yaml)
default: [findings.read]              # everyone who signs in

groups:
  developers:   [findings.assign, exceptions.request]
  sec-team:     [findings.assign, exceptions.request, exceptions.approve, audit.read]
  platform-ops: [settings.webhooks, audit.read]

users:                                 # by email or subject
  admin@example.com: ["*"]
```

- Permissions add up: `default`, then every matching group, then the person's own entry.
- Unknown permissions or fields stop Patchline at startup, so typos do not silently grant or drop access.
- Groups are re-read from the session on every request and the policy at startup. A policy change applies after a restart, without signing in again. A group change in the identity provider applies at the next sign-in.
- Without a policy file, everyone who signs in can read and nothing else.
- Someone who signs in without `findings.read` sees a "no access" page.

The startup log shows who can approve and who can change settings: `policy="exceptions.approve: sec-team; settings.webhooks: platform-ops"`. Each sign-in logs the groups and resulting permissions.

## What people can do

### Assign

On a finding, `findings.assign` sets the **assignee**: the person working on it, by email (or *Assign to me*). The service owners from the inventory stay as they are. The assignee shows on the finding, in the findings list (*Assigned to me*), in the Slack message, and in `GET /api/v1/findings?assignee=`.

### Request and approve

| Request | Approval does |
|---|---|
| **Risk acceptance** (reason) | Writes the analysis to Dependency-Track (`EXPLOITABLE`, response `WILL_NOT_FIX`, suppressed, with the reason and both names in the comment), then marks the finding *risk accepted* |
| **Due date extension** (new date, reason) | Moves the due date to the end of that day |

- People with `exceptions.request` ask from the finding page; approvers see every pending request under **Approvals**.
- **Nobody approves their own request**, even with both permissions. The requester can withdraw a pending request.
- One pending request per kind and finding.
- If Dependency-Track rejects the analysis, nothing is approved and the request stays pending. Patchline's API key then needs `VULNERABILITY_ANALYSIS` in addition to `VIEW_PORTFOLIO` and `VIEW_VULNERABILITY`.
- An extension holds while the effective severity stays at or below the level it was approved at. If the finding is escalated (for example, its CVE enters CISA KEV) or reopened, the policy's due date applies again.
- Requests, decisions and notes appear on the finding's timeline and in its Slack thread.

### Webhook settings

With `settings.webhooks`, **Settings → Webhooks** rotates `PATCHLINE_WEBHOOK_TOKEN` and `PATCHLINE_GITEA_WEBHOOK_SECRET` without a restart. A generated value is shown once. A saved value replaces the environment variable until it is reset; it is stored in Patchline's database, so restrict access to the database file and its backups. The page never shows a whole stored value, only its last characters.

### Audit log

`audit.read` shows every assignment, request, decision and settings change with who and when. Setting values are never logged.

## Security notes

- Sign-in uses the authorization code flow with PKCE, `state` and `nonce`. ID tokens are verified against the provider's keys (issuer, audience, expiry).
- Sessions are random 256-bit cookies (`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS). The database stores only their SHA-256.
- Every form carries a per-session CSRF token.
- Signing out ends the Patchline session. The provider's session stays, as with most SSO applications.
