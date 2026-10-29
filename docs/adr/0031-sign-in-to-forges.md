# ADR 0031: Signing in to forges instead of pasting a token

- Status: accepted (2026-10-29), planned for 0.0.12
- Date: 2026-10-29
- Decided by: maintainer (sign in with the forge's own login; GitHub through a GitHub App with read permissions and the device
  flow, Gitea and Forgejo through an OAuth2 application with PKCE; the personal token stays as the fallback)
- Builds on: ADR 0004 (vault), ADR 0010 and ADR 0014 (outbound address rules, forge requests from the worker only), ADR 0030
  (personal forge connections, private repositories), AGENTS.md rule 1 (least privilege, secrets never in the browser)

## Context

ADR 0030 connects a person's forge account with a personal access token they create and paste. That works everywhere, but it
asks people to find the right token page, pick the right permissions and copy a secret. People expect "Sign in with GitHub".

GarnetOps is self-hosted. A forge only lets an application sign people in when the application is registered with it, and
every installation has its own address. There is no central GarnetOps application that could serve all installations without
routing their sign-ins through us, which rule 1 rules out. So each installation registers its own application, once, and its
people sign in with it.

Two traps decide the shape:

- A classic **GitHub OAuth app** can only reach private repositories with the scope `repo`, which also allows writing. A
  **GitHub App** asks for fine-grained permissions instead; with **Metadata: Read**, **Contents: Read** and **Pull requests:
  Read** its user tokens can read and nothing else. GitHub Apps also offer the **device flow**: GarnetOps shows a short code,
  the person confirms it on GitHub, and no callback address has to be reachable from GitHub.
- **Gitea and Forgejo** have no device flow, but OAuth2 applications with scopes (`read:repository`, `read:user`) and PKCE.
  The forge sends the browser back to GarnetOps with a code; the address only has to be reachable from the person's browser.

## Decision

### 1. Sign-in applications, set up by admins

**Settings → Connected accounts → Sign-in with a forge** (owners and admins, recent sign-in, audited as `forge_app.added`,
`.changed`, `.removed`) lists one application per forge address:

| Forge | What the admin registers there | What GarnetOps stores |
| --- | --- | --- |
| GitHub, GitHub Enterprise Server | a GitHub App with Metadata, Contents and Pull requests set to **Read**, nothing else, "Enable Device Flow" on, no webhook | the App's client id, and its client secret (needed to renew tokens) |
| Gitea, Forgejo | an OAuth2 application with the redirect address GarnetOps shows (`<PUBLIC_URL>/settings/accounts/callback`) | the client id, and the client secret for a confidential client (none for a public one) |

The client secret is sealed in the vault (purpose `forge-app-secret`) and opened only by the worker. Addresses follow the rules
of ADR 0030 (https, no credentials, no forbidden addresses).

### 2. Signing in

In **Connect account**, every configured application offers **Sign in with …**; **Use a token instead** keeps the ADR 0030 form.

- **Device flow (GitHub).** The worker asks the forge for a device code. GarnetOps shows the user code and a link to the
  forge's verification page; the worker polls at the interval the forge asks for (slowing down when told) for at most 15
  minutes, then stores the connection. The device code is sealed (purpose `forge-sign-in`) and deleted afterwards.
- **Authorization code with PKCE (Gitea, Forgejo).** The API creates a random `state` (256 bits, stored as a hash, bound to
  the person and organisation, single use, 10 minutes) and a code verifier (sealed). The browser goes to the forge's authorize
  page with the S256 challenge and the fixed redirect address. The callback page hands `state` and `code` to the API, which
  checks the state, seals the code and queues the exchange; the worker exchanges it with the verifier (and secret) and deletes
  both.

The API never talks to a forge and never sees a token (ADR 0014). Tokens never reach the browser. A sign-in request belongs to
the person who started it; another person, or another session after sign-out, cannot finish or read it.

### 3. Tokens that expire

Signed-in connections hold an access token and a refresh token, both sealed (purpose `forge-connection-token`), and the access
token's expiry. Before every use (listing, cloning) the worker renews an access token that expires within five minutes,
under a row lock so that two jobs never spend the same (rotating) refresh token. A refused renewal marks the connection
failed with `sign-in-expired`; the person signs in again. Everything else of ADR 0030 applies unchanged: private repositories,
sharing, removal.

## Threat model

| Threat | Control |
| --- | --- |
| Login CSRF: an attacker makes a victim's GarnetOps finish the attacker's sign-in | `state` bound to the person and organisation, single use, compared as a hash; PKCE verifier only in the vault |
| Code interception at the redirect | PKCE S256; the code alone is useless; fixed redirect address from `PUBLIC_URL` |
| Over-broad permissions | GitHub App with read permissions only (documented, and the connection shows the account it signed in as); Gitea/Forgejo scopes `read:repository read:user` |
| Leaked refresh token | sealed in the vault, rotated on every renewal, deleted with the connection |
| Device code phishing | the code is shown only to the person who started the request, inside GarnetOps, and expires with the forge's limit |
| Client secret exposure | sealed, opened only by the worker, never returned by the API |
| A forge address that points inside the network or at metadata services | the address rules of ADR 0010/0014 on every request |

## Consequences

- Admins register an application once per forge; the documentation gives the exact steps and the redirect address.
- People sign in with the forge's own page, including its second factor; no token is pasted.
- Pasted tokens keep working; nothing existing changes.
