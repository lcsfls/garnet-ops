# ADR 0007: Docker Compose stack and signed in-app updates (cicd-updater)

- Status: proposed (2026-10-21), implemented, review pending
- Date: 2026-10-21
- Decided by: maintainer (pending)
- Amends: ROADMAP Phase 1 ("Docker Compose stack", "Upgrade test harness"), ADR 0003
  (production runtime)

## Context

GarnetOps ships as a Docker Compose stack inside the customer's network (AGENTS.md).
Self-hosted software tends to fall behind because updates are manual and risky, while
security fixes must reach every installation quickly (rule 1, EU Cyber Resilience Act)
and an update must never break an installation (rule 2). The MVP therefore
includes in-app updates.

[cicd-updater](https://github.com/restow-backup/cicd-updater) (Apache-2.0, same copyright
holder as GarnetOps, derived from Restow's updater) does exactly this for Compose apps: CI builds,
smoke-tests and signs the images and a `release.json`; an optional sidecar on the host
verifies the signatures, backs up the database, installs exactly the published image
digests, checks health and the version, and rolls back only when that is provably safe.
The app decides who may update and shows the state.

## Decision

1. **One Compose stack** (`docker-compose.yml`): `web` (Caddy edge: HTTPS, the web app,
   `/api` to the API, the maintenance page during updates), `api`, `worker`, `db`
   (PostgreSQL 17), `init` (creates the vault key pair once), and `updater` in the
   opt-in profile `updater`. Every image is pinned by digest. App containers run as
   uid 1000 with a read-only root file system, `cap_drop: ALL` and `no-new-privileges`.
   The `internal` network has no route out; only the worker (clones, vulnerability
   data) and the updater (release feed, registry) reach the outside through `egress`.
   The vault's private half is mounted into the worker only (ADR 0004), via volume
   sub-paths.
2. **Two images from one Dockerfile**: `app` (API and worker, Node.js 24 running the
   TypeScript sources with Node's type stripping, so no build step and no `tsx` in
   production; `erasableSyntaxOnly` keeps the code compatible) and `web` (Caddy with
   the built web app). grype and syft come in with pinned SHA-256 checksums.
3. **In-app updates through the cicd-updater sidecar, optional.** Without the profile
   (or with `UPDATER_URL=` empty) GarnetOps works as before and the Updates page shows
   the manual steps.
   - Only owners and admins see and use Updates; scheduling needs a sign-in (password
     and TOTP) from the last ten minutes. The step-up is a real sign-in in a dialog, so
     better-auth's rate limits, lockout and the audit log apply unchanged.
   - Every request carries `requestedBy` (user id and email) and the SHA-256 of the
     `release.json` the admin was shown.
   - The sidecar's token is mounted read-only into the API only, never into the worker
     or the browser. `/api/healthz` reveals the version only to that token.
   - The sidecar's journal is copied into the audit log exactly once (cursor and entry
     in one transaction, unique `(source, event_id)`; migration 0006, additive).
     Denied or refused requests are audited by the API itself.
   - Every signed-in user sees a banner (countdown, progress, result); after a
     successful update the page reloads once.
   - Releases are signed keyless by `.github/workflows/release.yml` at the release tag;
     `updater.yaml` trusts exactly that identity. Trust mode `none` is never used in
     production.
4. **The SDK is vendored** (`vendor/cicd-updater/`), built from a reviewed commit with
   its SHA-256 recorded, because cicd-updater has not published a release yet. The
   workflow actions are pinned to the same commit.

## Consequences

- Installing, updating and recovering are documented in `docs/installation.md` and
  `docs/updating.md`; the runbook for a failed update is the sidecar's own.
- The sidecar needs the Docker socket and is therefore root-equivalent on the host. It
  is opt-in, has no published port, and only the API can talk to it.
- Until cicd-updater publishes signed releases, its image must be built or mirrored by
  the operator; `CICD_UPDATER_IMAGE` stays a value the sidecar never writes.
- The first release needs: branch and tag protection, GHCR packages made public, the
  tag `v0.1.0`; then the smoke test runs the upgrade from the previous release on every
  later release.

## Verified on 2026-10-21

In a sandbox with Docker 29: both images built, the stack started (all services healthy,
CSP and HSTS on the edge), first-run setup and TOTP sign-in in a browser, and a real
update from 0.1.0 to 0.1.1 scheduled on the Updates page: backup, stop, start, health
with the version through the token, smoke check, banner, reload, 0.1.1 running, the
journal in the audit log. Not verified there: signature checking (the sandbox could not
pull cosign, so the test ran unsigned from a local file feed), and the `apk add git
openssh-client` step (Alpine's mirrors were blocked; it was left out of the local build).
