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
- Switching it off deletes address and secret at once; remove the webhook in the forge as well.
