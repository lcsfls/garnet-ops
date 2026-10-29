# ADR 0030: Personal forge connections, the repository picker and private repositories

- Status: accepted (2026-10-29), planned for 0.0.11
- Date: 2026-10-29
- Decided by: maintainer (personal read token per user; repositories added through it are private to that user until shared with
  the organisation; members and above may connect accounts, viewers may not)
- Builds on: ADR 0004 (vault: the API seals, only the worker opens), ADR 0009 (roles, step-up), ADR 0010 (outbound address
  rules, notifications), ADR 0014 (forge kinds, API addresses, token scopes, request limits), ADR 0019 (personal
  notifications), AGENTS.md rule 1 (per-user credentials, least privilege) and rule 2 (existing repositories keep working)

## Context

Adding a repository today means pasting its address and a token or deploy key, one at a time. Most users already have an account
on the forge that hosts their code (GitHub, Gitea, Forgejo) and want to pick repositories from a list.

AGENTS.md rule 1 is specific about such credentials: forge tokens belong to the user who connected them, are encrypted at rest,
scoped to the minimum and never usable by other users, and **a user only sees repositories their own connection grants access to,
unless an admin shares a repository**. Until now every repository of an organisation is visible to every member, which was fine
while only shared repositories existed. A personal connection changes that: what someone adds from their own account may be a
repository the rest of the organisation is not meant to see.

## Decision

### 1. A connection is a personal read token for one forge

**Settings → Connected accounts** lists the signed-in person's own connections; nobody else's appear, admins included. A
connection holds:

- the forge kind (`github`, `gitea`, `forgejo`) and its web address (`https://github.com`, `https://git.example.lan`), from which the
  API address is derived as in ADR 0014 (or typed for a forge under a sub-path, with the same checks);
- a **personal access token**, sealed in the vault with the new purpose `forge-connection-token`, bound to the organisation and the
  connection. The API seals it, **only the worker opens it**, and it is never shown again. Replacing it deletes the old secret;
- the account name the forge reports for the token, its last check and, if the check failed, a short problem code.

Recommended scopes, explained next to the input: GitHub fine-grained token with **Metadata: Read** and **Contents: Read** for the
repositories to monitor (a classic token with `repo` works, but gets the broad-token warning of ADR 0014); Gitea and Forgejo token
with **`read:repository`** and `read:user`. A token that can write is accepted with a warning: GarnetOps never writes with it.
Fix pull requests keep their own, separate write token per repository (ADR 0014).

Members, admins and owners may add connections; viewers may not. Adding, replacing and removing a connection needs a recent
sign-in (step-up, ADR 0009) and is audited (`forge_connection.added`, `.replaced`, `.removed`); the token is never logged or
audited. A person removed from the organisation loses their connections and the sealed tokens with them, and their private
repositories with everything found in them: nobody else could see those, so nothing anyone used is lost.

### 2. The repository list comes from the worker

The API never calls a forge (ADR 0014). **Refresh** queues a worker job that opens the token, checks it (`GET /user`) and reads the
repositories the account can see, page by page (at most 2,000, ADR 0014 limits per request: https only, the address checked on
every connection, no redirects, TLS verification on, 2 MB per answer, error bodies never read). The result is stored per
connection (`forge_connection_repository`: forge id, full name, https clone address, default branch, private or public, archived)
and replaces the previous list. The list is shown only to the connection's owner. Refresh is rate limited (6 per minute per person).

### 3. Picking repositories

The picker lists the stored repositories with a checkbox each, a filter and **Add selected**. The client sends only connection id
and forge ids; the API takes name, address and branch from the stored list, never from the request. Each new repository:

- uses the connection as its credential (`auth_kind` `connection`, a new value; the worker clones over https with the connection's
  token, read only);
- belongs to the person who added it (`owner_user_id`) and is **private** (`visibility` `private`, a new column; every existing
  repository is `organization`);
- is scanned at once, like any new repository.

A repository whose address is already monitored in the organisation is not added twice; the picker marks it as already added (and,
when it is someone else's private repository, says only that it is already monitored and an admin can share it).

### 4. Private repositories and sharing

A private repository, its scans, findings, packages, early warnings, gate runs, fix proposals, AI conversations and statistics are
visible **only to its owner**. Every query that lists or counts repository data applies one visibility condition: the repository is
`organization`, or its owner is the signed-in person. Every lookup by id of a repository or of anything that belongs to one answers
404 when it is not visible, so ids of other people's private repositories cannot be probed.

**Share with the organisation** on a private repository: done at once by an owner or admin who owns it; for a member it becomes a
**share request** that owners and admins see as a list (repository name and who asks, nothing else) and approve or decline. Sharing is
audited (`repository.share_requested`, `repository.shared`, `repository.share_declined`) and cannot be undone by the member; an
admin can make a shared repository private again for its owner (`repository.unshared`). A shared repository keeps using its owner's
connection; when that connection is removed or its owner leaves, scans fail with `connection-removed` and admins are told, like any
other credential problem, until someone replaces the credential.

Organisation-wide destinations never receive private data: notification channels, the weekly digest and the organisation's
counts skip private repositories; the owner's own in-app notifications (ADR 0019) still report them. The audit log (owners and
admins only) names private repositories in its entries, as it names every security-relevant action.

### 5. Existing behaviour

Repositories added by address, token or deploy key, as today, stay `organization` and visible to everyone: nothing changes for
existing installations (rule 2). The public API gains `GET/POST/DELETE /api/v1/forge-connections`, `POST
/api/v1/forge-connections/{id}/refresh`, `GET /api/v1/forge-connections/{id}/repositories`, `POST
/api/v1/forge-connections/{id}/repositories` and the share endpoints; repository objects gain `visibility` and `owner`. Nothing is
removed or renamed.

## Threat model

| Threat | Control |
| --- | --- |
| Theft of stored tokens (database dump, backup) | Sealed with the vault key outside the database (ADR 0004); the API cannot open them. |
| One user using another user's connection or list | Every connection route checks the owner; the worker re-checks owner and organisation of the job's connection before opening the token. |
| Probing other people's private repositories | One visibility condition in every list and count; 404 for invisible ids; the picker reveals only that an address is already monitored, which the person's own forge account already shows them. |
| Private data leaking through organisation-wide views | Channels, digest, overview, statistics and search apply the same condition; tested per view. |
| Server-side request forgery through the forge address | https only, address policy of ADR 0010 on every connection, no redirects, fixed API paths (ADR 0014). |
| Hostile or huge forge answers | Size and page limits, schema validation, names stored as text and always escaped, no HTML rendered. |
| Over-broad tokens | Read scopes recommended; the worker reports broad or writing tokens as a warning on the connection. |
| Abuse of refresh as a scanner of the network | Rate limit, step-up for adding connections, audit log. |

## Consequences

- A visibility condition joins every repository-scoped query. It is one helper used everywhere, and the end-to-end tests check
  each view with a private repository of another member.
- Admins no longer see everything: private repositories stay with their owner until shared. This is intended (AGENTS.md rule 1).
- OAuth sign-in to the forge ("Sign in with GitHub") can follow later as another way to obtain the same token; it needs an OAuth
  application registered per forge and is not part of this decision.
