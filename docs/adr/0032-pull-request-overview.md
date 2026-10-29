# ADR 0032: Pull request overview with gate results

- Status: accepted (2026-10-29), planned for 0.0.12
- Date: 2026-10-29
- Decided by: maintainer (open pull requests of the monitored repositories with their gate result; read with the repository's
  read credential)
- Builds on: ADR 0008 (quality gates, checks of a ref), ADR 0014 (forge client, address rules), ADR 0030 (connections,
  visibility), ADR 0031 (signed-in connections), AGENTS.md rules 1 and 2

## Context

Quality gates (ADR 0008) check a pull request when a CI pipeline asks for it with a gate token. Many teams have no such
pipeline step yet, and nobody sees in one place which open pull requests would bring a vulnerability in. The forge knows the
open pull requests; GarnetOps knows how to check a ref.

## Decision

1. **Reading.** The worker lists the open pull requests of every repository (at most 300 each) every 15 minutes and on demand
   (**Refresh**, members and above, rate limited). It uses the repository's **read** credential, never the write token of
   ADR 0014:
   - a repository added from a connected account: that connection (renewed if signed in, ADR 0031);
   - a repository with an https token: that token;
   - a public repository, or one with a deploy key: no token (public repositories only; a deploy key cannot use the API).
   The forge and its API address come from the connection, else from the fix pull request settings, else from the host
   (`github.com`, `codeberg.org`, host names with `gitea` or `forgejo`); a repository whose forge is unknown is listed as
   such. Every request follows the rules of ADR 0014 (https, checked addresses, no redirects, limits).
2. **Storing.** Number, title, author, branches, head commit, draft flag and the forge's times are stored per repository and
   replaced by every successful read; pull requests that are no longer open go. Titles and names are hostile input: stored as
   text (control characters removed, 300 characters at most), always shown escaped. The link to the pull request is built
   from the repository address (`pullRequestUrl`), never taken from the forge's answer.
3. **Gate result.** Each pull request shows the result of the latest gate run for its head commit, a check that is queued or
   running for it, or "not checked". **Check now** (members and above) queues a check of `refs/pull/<n>/head` expecting that
   commit, exactly like a CI check (reused while one is waiting, audited as `gate.check_requested`). Nothing about the gate's
   behaviour changes (rule 2): the result is the same a pipeline would get.
4. **Visibility.** The overview follows ADR 0030: only repositories the person sees.

The public API gains `GET /api/v1/pull-requests`, `GET /api/v1/pull-requests/sources`, `POST /api/v1/pull-requests/refresh`
and `POST /api/v1/pull-requests/{id}/check`. Nothing is removed or changed.

## Threat model

| Threat | Control |
| --- | --- |
| Hostile pull request titles or branch names (script, control characters, very long text) | stored as text, cut, escaped on output; branch names are never used as refs (the check uses `refs/pull/<n>/head`) |
| A link that leads elsewhere | built from the repository address and the number, not from the forge's `html_url` |
| Using write access to read | only the read credential is used; the write token stays for fix pull requests |
| Someone checks a pull request of a repository they cannot see | the same visibility condition; 404 for invisible ids |
| Flooding a forge | 300 pull requests per repository, 15-minute schedule, rate-limited refresh |
