# ADR 0039: Fix pull requests through connected accounts

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (every person uses their own connection; write is an explicit opt-in per connection)
- Builds on: ADR 0014 (fix pull requests with a separate write credential), ADR 0030 (personal forge connections), ADR 0031
  (signing in to forges), ADR 0004 (vault: the API seals, only the worker opens), AGENTS.md rules 1 and 2

## Context

A fix pull request (ADR 0014) can only be opened with a write token stored per repository by an owner or admin. Most people
already have a connected account on the same forge (ADR 0030/0031), and on the forge they can push to the repositories they
work on. Asking an admin for a second token per repository is friction, and a shared write token hides who asked for a change:
the forge shows the bot user, not the person. Connections are read-only today, and must stay so unless their owner decides
otherwise.

## Decision

1. **Every person uses their own connection.** A member may open a fix pull request with their own forge connection when the
   connection's forge (host, port and sub-path of its web address) matches the repository's address. The pull request is created
   by that account, so the forge shows it as theirs and applies its own permissions. A connection's token is only ever used for
   requests of its owner (`forge_connection.user_id`): the API picks only among the caller's own connections, and the worker
   checks again that the connection belongs to `fix_pr.requested_by` in the same organisation.
2. **Write is an explicit opt-in per connection.** New columns `forge_connection.pull_requests` (default false),
   `pull_requests_at` and `write_scope`. `PUT /api/v1/forge-connections/{id}/pull-requests` with `{ enabled, acknowledged }`:
   only the owner (anybody else gets 404, admins too); switching on needs a recent sign-in (step-up), `acknowledged: true` after
   the dialog that lists what the token will be used for, and for a Gitea/Forgejo sign-in `write_scope`. Switching off needs
   neither. Both are audited (`forge_connection.pull_requests_enabled`, `_disabled`).
3. **Scopes per kind of connection.**
   - Gitea and Forgejo sign-in: signing in asks for `read:repository read:user` as before. Starting a sign-in with
     `write: true` asks for `write:repository read:user` (`SIGN_IN_WRITE_SCOPES`, `authorizeUrl({ write })`); the worker sets
     `write_scope` when such a sign-in completes (`forge_sign_in.write`).
   - GitHub Apps have no scopes; their permissions come from the App registration. The admin gives the App **Contents: Read and
     write** and **Pull requests: Read and write**; otherwise the forge's push check refuses.
   - Pasted tokens: the push check decides; the existing broad-token warning stays.
4. **The switch belongs to the credential it was given for.** Replacing a connection's token (`PUT …/token`) switches pull
   requests off, as does signing in again without write access to Gitea or Forgejo, or signing in on a connection that had a
   pasted token; each is audited with a reason. A new GitHub sign-in keeps it (the App's registration decides).
5. **Creating the pull request.** `POST /api/v1/fixes/prs` takes an optional `via: "connection" | "repository"`. Without it,
   the repository's write token is used as before. With `"connection"` the API picks the caller's own connection on the
   repository's forge that can open pull requests, stores `fix_pr.via = 'connection'` and `fix_pr.connection_id` (foreign key,
   on delete set null), and audits `fix_pr.created` with `via`. Otherwise 409: `no-connection`, `connection-pull-requests-off`,
   `connection-write-scope-missing` or `connection-failed`. `via` is kept apart from `connection_id`, so a request whose connection
   was removed never falls back to the repository's token.
6. **The worker** opens the connection's token with the code that already renews and decrypts it for listing repositories
   (`accountOf`), only after re-checking owner, organisation, host, opt-in and write scope; any mismatch fails the request with a
   reason code (`connection-missing`, `connection-disabled`, `write-scope-missing`). Before writing, the forge's push permission
   for the repository is checked as for a write token (`no-push-access`). Branch, commit, text, cleanup and "never merge" are
   unchanged. The token lives only in memory for the request and is never logged. The status refresh reads the pull request with
   the requester's own connection (reading needs no opt-in), or notes `connection-missing`.
7. **Web.** Settings → Connected accounts: **Pull requests** per connection, with a dialog (what the token will do, the
   acknowledgement; for a Gitea/Forgejo sign-in without write access, **Sign in with write access** first). Fix proposals:
   **Create PR as *account*** when the viewer has a matching connection with pull requests on; **Create PR with the repository
   token** stays when the repository has one. The list carries `connection` and `creatableViaConnection` per proposal.

## Threat model

| Threat | Control |
| --- | --- |
| One person's token is used for another person's request | the API looks only at the caller's own connections; the worker re-checks `connection.user_id = fix_pr.requested_by` and the organisation before opening the token; tests cover both |
| A connection is turned into a write credential without its owner knowing | off by default; only the owner can switch it on, with a recent sign-in and an explicit acknowledgement; audited; a new token or a read-only sign-in switches it off again |
| A stolen session switches it on and opens pull requests | step-up (sign-in within ten minutes) for switching on and for every pull request; rate limits; the pull request is in the person's name and never merged |
| The token is sent to another host | the token goes only to the connection's API address (address rules of ADR 0014, no redirects); the connection must be on the repository's host, port and sub-path |
| A removed or switched-off connection is still used | the worker re-reads the connection when the job runs and fails the request; `via` keeps a request from falling back to the repository's write token |
| A Gitea/Forgejo token without write access, or a token that cannot push, makes a half-finished change | `write_scope` is required before switching on; the forge's push permission is checked before any write; a branch made before a failure is deleted |
| The token leaks through logs, rows or error messages | sealed in the vault, opened only by the worker, kept in memory for one request; failures are stored as short codes; tests check rows, audit entries and logs for the token |

## Consequences

- One additive migration `0036_fix_pr_connections` (columns on `forge_connection`, `forge_sign_in` and `fix_pr`, one foreign key).
  Existing connections stay read-only; existing pull requests are `via = 'repository'`.
- New: `PUT /api/v1/forge-connections/{id}/pull-requests`; `write` on `POST /api/v1/forge-sign-in`; `via` on
  `POST /api/v1/fixes/prs`; `pullRequests`, `pullRequestsAt`, `writeScope`, `needsWriteSignIn` on connections; `connection`,
  `creatableViaConnection` on proposals and `via` on pull requests. Nothing existing changes meaning.
- The repository write token of ADR 0014 stays, for teams that prefer a bot account.
- Not in this version: picking among several connections on the same forge (the most specific one is used), pull requests
  through a connection for plain Git repositories (there is no pull request to open).
