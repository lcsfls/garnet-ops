# Connected accounts

**Settings → Connected accounts** lets each person connect their own account on GitHub, Gitea or Forgejo, by signing in
with the forge or with a personal access token, and add repositories by ticking them in a list.
([ADR 0030](adr/0030-personal-forge-connections.md))

## Signing in with the forge

When an admin has set up sign-in for a forge (below), **Connect account** offers **Sign in with GitHub**, **Sign in with
Gitea** or **Sign in with Forgejo** ([ADR 0031](adr/0031-sign-in-to-forges.md)):

- **GitHub** shows a short code and a link to GitHub's device page. Open it, sign in to GitHub if asked (with its own second
  factor), enter the code and approve. GarnetOps continues by itself; **Cancel sign-in** stops it.
- **Gitea and Forgejo** open the forge's own sign-in and consent page. After you agree, the forge sends you back to GarnetOps,
  which finishes the connection.

The tokens the forge issues are stored encrypted, renewed by the worker before they expire, and never shown. If a renewal is
refused (for example after you revoked GarnetOps on the forge), the connection says **The sign-in has expired** and offers
**Sign in again**. **Use a personal access token instead** keeps the token form below.

### Setting up sign-in (owners and admins)

**Settings → Connected accounts → Sign-in with a forge → Add forge**, once per forge address:

| Forge | On the forge | In GarnetOps |
| --- | --- | --- |
| GitHub, GitHub Enterprise Server | Create a **GitHub App** (Settings → Developer settings → GitHub Apps). Permissions: **Metadata**, **Contents** and **Pull requests** set to **Read**, nothing else. No webhook. **Enable Device Flow** on. Install the App for the accounts and organisations whose repositories people should see. | Client ID and a client secret (needed to renew tokens). |
| Gitea, Forgejo | Create an **OAuth2 application** (Settings → Applications) with the **redirect address** GarnetOps shows (`<PUBLIC_URL>/settings/accounts/callback`). | Client ID, and the client secret for a confidential client. |

The client secret is stored encrypted and only the worker uses it; it is never shown again. Removing a forge stops new
sign-ins; connections made with it keep working until their token has to be renewed.

## Connecting an account with a token

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
Repository objects carry `visibility` (`organization` or `private`), `mine` and `shareRequested`. Signing in:
`GET`, `POST`, `PATCH`, `DELETE /api/v1/forge-apps` (owners and admins), `GET /api/v1/forge-apps/available`,
`POST /api/v1/forge-sign-in`, `GET` and `DELETE /api/v1/forge-sign-in/{id}`, `POST /api/v1/forge-sign-in/callback`.
