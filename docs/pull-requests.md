# Pull requests

**Code → Pull requests** lists the open pull requests of the repositories you see, each with the quality gate result of its
latest commit ([ADR 0032](adr/0032-pull-request-overview.md)). You see at a glance which open pull request would bring a
vulnerability in, also for repositories whose pipeline does not ask the gate yet ([quality-gates.md](quality-gates.md)).

## Where the list comes from

The worker reads the open pull requests every 15 minutes, at most 300 per repository. **Refresh** (members and above) asks it
to read them again now; the list updates itself for a minute afterwards.

It reads with the repository's **read** credential, never with the write token of fix pull requests:

| Repository added | Read with |
| --- | --- |
| from a connected account ([connected-accounts.md](connected-accounts.md)) | that account, renewed if you signed in with the forge |
| over HTTPS with a token | that token |
| public, or over SSH with a deploy key | no credential: works for public repositories only (a deploy key cannot use the forge's API) |

GarnetOps needs to know the forge. It takes it from the connected account, else from the repository's fix pull request
settings ([fix-prs.md](fix-prs.md)), else from the host name (`github.com`, `codeberg.org`, and host names that contain
`gitea` or `forgejo`). Repositories it could not read are named above the list with the reason.

## Gate result

| Shown | Meaning |
| --- | --- |
| Passed, With notes, Blocked | the latest gate run for the pull request's head commit, linked to the gate runs |
| Being checked … | a check of that commit is queued or running |
| Not checked | no gate run for that commit yet |

**Check now** (members and above) checks the pull request's head (`refs/pull/<number>/head`) exactly as a CI pipeline
would: the same rules and the same result, and nothing is written to the pull request. A check that is already waiting for
that commit is reused. Every request is in the audit log (`gate.check_requested`).

## Safety

- Titles, author names and branch names come from the forge and are treated as hostile text: control characters are
  removed, they are cut to 300 characters and always shown as text.
- The link to a pull request is built from the repository address and its number, never taken from the forge's answer.
- You only see pull requests of repositories you can see; private repositories stay private
  ([connected-accounts.md](connected-accounts.md)).

## API

- `GET /api/v1/pull-requests` (`repositoryId`, `gate` = `passed` | `notes` | `blocked` | `checking` | `none`, `q`):
  at most 500, most recently updated first; `truncated` says whether there are more.
- `GET /api/v1/pull-requests/sources`: per repository when it was last read and the problem code, if any.
- `POST /api/v1/pull-requests/refresh`: read again (members and above, rate limited).
- `POST /api/v1/pull-requests/{id}/check`: check the head commit (members and above, rate limited); answers the `scanId`.
