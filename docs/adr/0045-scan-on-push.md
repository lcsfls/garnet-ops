# ADR 0045: Scan on push

- Status: accepted (2026-11-01)
- Date: 2026-11-01
- Decided by: maintainer (the secret kept by the API, encrypted with a key derived from BETTER_AUTH_SECRET; the webhook entered in
  the forge by hand, or registered through the person's own connected account, section "Registering through a connected
  account")
- Builds on: ADR 0005 (scheduled scans), ADR 0008 (gate tokens: a route without a session), ADR 0030 (private repositories),
  ADR 0043 (inactive repositories), AGENTS.md rule 1 (security first)

## Context

Repositories are scanned at night and when someone asks. A finding that a push brings in shows up the next morning. GitHub, Gitea
and Forgejo can call an address on every push and sign each call with HMAC-SHA256 over the body, using a secret both sides share.

## Decision

1. **Per repository, opt-in.** Owners and admins, or the owner of a private repository, switch it on on the repository page, with a
   recent sign-in. GarnetOps creates a random address (`/api/v1/hooks/<43 random characters>`, never the repository id) and a random
   secret (32 bytes). Both are shown once, to be entered in the forge. Switching it on again replaces both; switching it off deletes
   them and the address answers nobody. All three actions are audited.
2. **The API checks the signature.** The secret is stored encrypted with AES-256-GCM under a key derived from `BETTER_AUTH_SECRET`
   by HKDF (never stored), bound to the webhook's id. The delivery route has no session and no cookies and runs before the same-origin
   check, like the gate API. It reads at most 5 MB, looks up the address, and checks the HMAC in constant time before it parses
   anything. A wrong signature is answered with 401 at once, so the forge's delivery log shows it.
3. **Only a push to the scanned branch counts.** The repository's branch, or the default branch the forge names when the repository
   follows the default branch. Tags, other branches, deleted branches and other events are answered and ignored. An inactive
   repository is not scanned. While a scan is queued or running, no second one is queued. The push's content is never used: the scan
   clones the repository as always.
4. **Limits**: 60 deliveries per webhook and minute and 120 per client address and minute, in the database like the sign-in limits.
5. **Visible.** The last ten deliveries are kept as time, event and a result code (scan started, already waiting, another branch,
   signature does not match, ...), shown on the repository page; never a payload.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Someone guesses or finds the address | 43 random characters; without the secret every delivery is refused before anything is read. |
| The secret leaks (forge compromise, a copy in a ticket) | It can only ask for scans of that one repository: at most one queued at a time, limited per minute. Replace it on the repository page. |
| Hostile payloads (huge, malformed, crafted refs) | 5 MB cap; nothing is parsed before the signature matches; only `ref`, `deleted` and the default branch name are read and compared as strings; the scan uses its own clone. |
| Replays of a captured delivery | A replay can only start a scan that a push would have started anyway, with the same limits. |
| The database leaks | The secrets are encrypted with a key that is not in the database. |
| An attacker floods the endpoint | Limits per webhook and per address, kept across restarts; unknown addresses cost one indexed lookup. |

Remaining risk, accepted: whoever holds `BETTER_AUTH_SECRET` (the API's own secret) can open the webhook secrets. That secret
already signs every session, so it is guarded as the most sensitive value of the API anyway. Changing it makes every webhook need
a new secret, which the documentation says.

## Consequences

- New table `repository_webhook` (migration 0043), new public route `POST /api/v1/hooks/{id}`, new routes
  `GET|POST|DELETE /api/v1/repositories/{id}/webhook`. Nothing existing changes.
- The forge must reach GarnetOps' address. For an internal Gitea or Forgejo that is usually so; for GitHub.com the edge has to be
  reachable from the internet for this one path (`docs/scan-on-push.md`).
- Creating the webhook in the forge through a connected account: added later in this version line, below.

## Registering through a connected account

Added 2026-11-01. Builds on ADR 0030/0031 (personal connections) and ADR 0039 (the pattern: own connection only, the worker
re-checks, the API seals and never opens).

1. **Who and when.** Whoever may switch scan on push on (owners and admins, or the owner of a private repository, with a recent
   sign-in) and has an **own** connection on the repository's forge (host, port and sub-path of its web address) can ask
   GarnetOps to create the webhook in the forge: `POST /api/v1/repositories/{id}/webhook` with `{ "register": true }`. Only the
   caller's own connections are looked at, for admins too. A Gitea/Forgejo sign-in needs its write scope (409
   `connection-write-scope-missing`), a connection whose check failed or that holds no token cannot (409 `connection-failed`),
   none at all is 409 `no-connection`. No standing opt-in like the pull request switch of ADR 0039: each registration is its
   owner's explicit act, and the web app asks for an acknowledgement in a dialog that names the account and what will be
   created. Adding repositories from a connection takes `scanOnPush: true` and does the same for each new repository, through
   that connection, with a recent sign-in; both paths share one function.
2. **The secret travels sealed, once.** The address and secret are made as before. The API seals a copy of the secret for the
   worker in the vault (new purpose `webhook-secret`, bound to the organisation and the secret's record), stores
   `connection_id`, `register_state = 'pending'` and `handover_secret_id` on the webhook (migration 0044, additive), audits
   `repository.webhook_created`/`_replaced` with `via: "connection"`, and queues `repository-webhook.register` with ids only
   (`webhookId`, `organizationId`, `secretId`). The answer still carries address and secret, and `registering: true`; the web
   app does not show them on this path.
3. **The worker re-checks, then registers.** The webhook still exists and is pending with this handover; the connection
   belongs to the webhook's `created_by` in the same organisation and still covers the repository; the write scope as above.
   It opens the token (`accountOf`, with renewal) and the handover, creates the webhook (GitHub `name: "web"`, Gitea/Forgejo
   `type: "gitea" | "forgejo"`; push events only, JSON, the secret; GitHub `insecure_ssl: "0"`) through the forge client of ADR
   0014 (address rules, no redirects, limits, error codes), and stores `forge_hook_id` and `ok`, or `failed` with a short code
   (the forge client's codes, `connection-missing`, `write-scope-missing`, `no-public-url`, `secret-missing`, `expired`, ...).
   The handover is deleted in every outcome. Audited as `repository.webhook_registered` or `_register_failed` with the code.
   No retries: a second attempt could make a second webhook. A webhook switched off while the forge was asked is removed again.
   A sweep ends registrations left pending for 30 minutes as `expired` and deletes old handovers.
4. **Removing.** Switching off or replacing a webhook GarnetOps registered queues `repository-webhook.unregister` (organisation,
   repository, connection, forge hook id, the connection's owner, who asked; ids only) before the row is deleted. The worker
   re-checks that the connection still belongs to that owner and covers the repository, deletes the webhook in the forge (a
   404 counts as done) and audits `repository.webhook_unregistered` or `_unregister_failed`. The cleanup uses the
   registering person's connection even when an admin switches it off: it removes exactly the webhook that connection
   created, which the acknowledgement names. A removed connection or repository leaves the webhook in the forge; it only
   reaches an address that answers nobody, and the documentation says to remove it there.
5. **Visible.** `GET …/webhook` carries `registration` (`state`, `reason`, `connection: { login, kind }`) and `canRegister`
   (`{ login, kind, problem }` of the caller's own connection) for those who may manage it, nothing of it for others.
6. **Forge permissions.** GitHub Apps need the repository permission **Webhooks: Read and write**; Gitea/Forgejo sign-ins
   `write:repository`; on every forge the account needs admin rights on the repository. The forge decides; GarnetOps shows its
   refusal as a code.

| Threat | Mitigation |
| --- | --- |
| One person's token creates or removes a webhook for another person | The API looks only at the caller's own connections; the worker re-checks `connection.user_id = repository_webhook.created_by` (removal: the owner named in the job, which the API took from the row) and the organisation before opening the token; tests cover both. |
| The webhook secret leaks on its way to the worker | Sealed in the vault for the worker only (purpose-bound), never in a job, a log line, an audit entry or an error; deleted after one attempt in every outcome, by the sweep at the latest; the API cannot open it. |
| The token is used for more than this | One request to create, one to delete, only on the repository the webhook belongs to, through the forge client's address rules; the token stays in the worker's memory for the job. |
| A stolen session plants a webhook to an attacker's address | The address is always this installation's own (`PUBLIC_URL` plus a random path); nothing in the request names it. Step-up, rate limit and audit as for the manual path. |
| A connection without write access half-creates something | Gitea/Forgejo sign-ins need `write:repository` before; the forge's refusal is a code; nothing else is written. |
| A webhook stays behind after it is switched off | Removal is queued before the row is deleted; a webhook made while it was switched off is removed at once; failures are audited and the documentation says what to remove by hand. |
| Hostile forge answers | Only an integer id is taken from the answer (`^[1-9][0-9]{0,19}$`), and it is sent back only as a path segment. |

