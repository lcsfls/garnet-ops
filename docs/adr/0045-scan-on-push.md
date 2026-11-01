# ADR 0045: Scan on push

- Status: accepted (2026-11-01)
- Date: 2026-11-01
- Decided by: maintainer (the secret kept by the API, encrypted with a key derived from BETTER_AUTH_SECRET; the webhook entered in
  the forge by hand for now)
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
- Not yet: creating the webhook in the forge automatically through a connected account with write access.
