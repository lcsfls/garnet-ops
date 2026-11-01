# Scan on push

A push to the scanned branch can start a scan at once, instead of waiting for the night
([ADR 0045](adr/0045-scan-on-push.md)). It works with GitHub, Gitea and Forgejo.

## Switch it on

1. Open the repository in GarnetOps. In **Scan on push**, press **Switch on** (owners and admins, or the owner of a private
   repository; GarnetOps asks you to sign in again if your sign-in is older than ten minutes).
2. GarnetOps shows a **webhook address** and a **secret**. The secret is shown only now.
3. Add the webhook in the forge:
   - **GitHub**: Settings, Webhooks, Add webhook. Payload URL and Secret from GarnetOps, content type `application/json`,
     "Just the push event".
   - **Gitea** or **Forgejo**: Settings, Webhooks, Add webhook, Gitea (or Forgejo). Target URL and Secret from GarnetOps, HTTP
     method POST, content type `application/json`, trigger on push events.
4. The forge sends a test (ping) or the next push. The repository page lists the last deliveries with their result.

## Let GarnetOps register it in the forge

If you have your own [connected account](connected-accounts.md) on the repository's forge, GarnetOps can create the webhook
there for you, so nothing has to be copied:

1. On the repository page, in **Scan on push**, press **Switch on and register in *forge***. (The button shows when you may
   switch scan on push on and have a connected account on this forge that can write.)
2. A dialog says what will be created (a webhook on this repository for push events only, calling this installation, with
   a new random secret) and with which account. Tick the confirmation and press **Create the webhook**.
3. The card says **Being registered in the forge …**, then **Registered in the forge by *account***. If it fails, it says why
   (for example "the account may not create webhooks here; it needs admin rights on the repository"); press **Register
   again**, or **New address and secret** to enter it by hand.

When you add repositories from a connected account (**Choose repositories**), **Scan on push for all of them** does the same for
every repository added, with that account.

What the account needs: admin rights on the repository in the forge, and write access for GarnetOps:

- **GitHub App** (signed in): the App needs the repository permission **Webhooks: Read and write**; an admin sets it in the
  App's settings ([connected-accounts.md](connected-accounts.md)).
- **Gitea, Forgejo** (signed in): sign in with write access first (`write:repository`; Settings, Connected accounts, **Pull
  requests**, **Sign in with write access**).
- **Personal access token**: GitHub **Webhooks: Read and write**; Gitea and Forgejo **write:repository**.

Only your own connection is ever used, for admins too. The token stays with the worker; the secret is handed to the worker
encrypted for this one job and deleted right after, whatever happens. **Switch off** and **New address and secret** remove the
webhook GarnetOps created in the forge again, with the same account (best effort; the audit log says whether it worked). If
the connection or the repository was removed first, remove the webhook in the forge yourself.

## What happens

- A push to the branch GarnetOps scans starts a scan. Without a branch set, that is the default branch.
- Pushes to other branches, tags, deleted branches and other events are answered and ignored.
- While a scan is waiting or running, another push starts no second one.
- An inactive repository is not scanned.
- Deliveries with a wrong signature are refused; the list says "Signature does not match the secret". Check the secret in the forge,
  or create a new address and secret.

## Reachability

The forge must reach the webhook address, which is the address users open (`PUBLIC_URL`) plus `/api/v1/hooks/...`. An internal
Gitea or Forgejo usually can. For GitHub.com the address must be reachable from the internet; if you open it, open only the path
`/api/v1/hooks/` in your firewall or reverse proxy. Without a valid secret nothing is read and nothing happens.

## Notes

- The secret is stored encrypted with a key derived from `BETTER_AUTH_SECRET`. If you change that secret, create a new address and
  secret for every webhook.
- Switching it off deletes address and secret at once. Remove the webhook in the forge as well, unless GarnetOps registered it
  (then it removes it itself).
- The API: `POST /api/v1/repositories/{id}/webhook` with `{ "register": true }` registers through your connected account
  (answers `409 no-connection`, `connection-write-scope-missing` or `connection-failed` otherwise); the answer carries
  `registering`. `GET` carries `registration` (`state` pending, ok or failed, `reason`, `connection`) and `canRegister` for
  those who may manage it.
