# Connected accounts

**Settings → Connected accounts** lets each person connect their own account on GitHub, Gitea or Forgejo and add
repositories by ticking them in a list, instead of pasting addresses and tokens one at a time.
([ADR 0030](adr/0030-personal-forge-connections.md))

## Connecting an account

Members, admins and owners can connect accounts; viewers cannot. Choose **Connect account**, then:

| Field | What to enter |
| --- | --- |
| Forge | GitHub (github.com or GitHub Enterprise Server), Gitea or Forgejo. |
| Address of the forge | The address you open in the browser, for example `https://github.com` or `https://git.example.lan`. Only https. |
| API address (Advanced) | Only for a forge whose API is not at `https://api.github.com`, `<address>/api/v3` (GitHub Enterprise Server) or `<address>/api/v1` (Gitea, Forgejo). |
| Personal access token | A token of your own account, read access only (below). |

What the token needs:

- **GitHub:** a fine-grained personal access token with **Metadata: Read** and **Contents: Read** for the repositories you
  want to monitor. A classic token with `repo` also works, but it can do more than GarnetOps needs; the connection says so.
- **Gitea and Forgejo:** a token with **read:repository** and **read:user**.

Connecting needs a recent sign-in (you may be asked to confirm it is you). The token is stored encrypted, only the worker
opens it, and it is never shown again. Nobody else can see or use your connection, admins included. **Replace token** stores
a new one and deletes the old one; **Remove** deletes it.

After you connect, the worker checks the token and lists the repositories your account can see (at most 2,000). The
connection then shows the account name and how many repositories it lists. **Refresh list** asks again, for example after
you created a repository. A failed check shows a short reason, such as "The forge refused the token".

The worker connects only to the address you entered, over https with certificate checks, without following redirects, and
refuses addresses such as `localhost` or cloud metadata addresses, as for fix pull requests ([fix-prs.md](fix-prs.md)).

## Choosing repositories

**Choose repositories** opens the list with a checkbox per repository, a filter, and **Add**. Repositories that are already
monitored are marked and cannot be added twice. Each added repository:

- is cloned with your connection's token, read only;
- is **private**: only you see it, its findings, scans, packages, statistics and early warnings;
- is scanned at once, and every night with all others.

## Private repositories and sharing

A private repository shows **Private** in the repository list and on its page. Other people, admins included, do not see it
anywhere: not in lists, counts, statistics, search, exports or notification channels. Your own notifications still tell you
about it.

To let the organisation see it, open the repository and choose:

- **Share with the organisation** (owners and admins): shared at once;
- **Ask to share** (members): owners and admins see the request on the **Repositories** page, with the repository's name and
  who asks, and share or decline it.

Admins can make a shared repository that came from a connected account private again for its owner (**Make private again**).
Sharing and every decision are in the audit log.

## Removing a connection, leaving the organisation

**Remove** deletes the connection and its token. Tick **Also remove the private repositories I added through it** to delete
those repositories with their findings too. Shared repositories always stay; until someone gives them another credential,
their scans fail with "The connected account this repository was added through was removed".

When an admin removes a person from the organisation, that person's connections and private repositories are deleted with
the membership.

## API

`GET /api/v1/forge-connections`, `POST /api/v1/forge-connections`, `PUT /api/v1/forge-connections/{id}/token`,
`POST /api/v1/forge-connections/{id}/refresh`, `GET` and `POST /api/v1/forge-connections/{id}/repositories`,
`DELETE /api/v1/forge-connections/{id}?removeRepositories=0|1`; sharing: `POST /api/v1/repositories/{id}/share`,
`POST /api/v1/repositories/{id}/unshare`, `GET /api/v1/share-requests`, `POST /api/v1/share-requests/{id}/approve|decline`.
Repository objects carry `visibility` (`organization` or `private`), `mine` and `shareRequested`.
