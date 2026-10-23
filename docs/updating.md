# Updating GarnetOps

GarnetOps follows Semantic Versioning and never breaks an installation within a major
version (AGENTS.md rule 2): migrations only add, and a pipeline that passed yesterday does
not fail tomorrow because of an update. Security fixes are published for every supported
version line, free of charge.

**There is no release yet, so there are no signed images.** Until the first release,
every installation runs images built from this repository, and you update the same way.

## Today: images built from source

`docker compose pull` does not apply here: it only fetches published images, and
`garnetops:local` exists only on your host. Instead:

```sh
cd /opt/garnetops
docker compose exec db pg_dump -U garnetops -Fc garnetops > garnetops-$(date +%F).dump
git pull
docker build --target app -t garnetops:local     --build-arg VERSION=0.0.2 .
docker build --target web -t garnetops-web:local --build-arg VERSION=0.0.2 .
docker compose up -d
docker compose ps
```

The API migrates the database when it starts; migrations only add, so your data stays.
Read the `Unreleased` section of [CHANGELOG.md](../CHANGELOG.md) for new `.env` keys first.
Keep `UPDATER_URL=` empty in `.env`: the update service installs signed releases only.

## From the first release on: signed images

Everything below applies once releases are published. Then there are two ways to
update, and both install the signed images of a release, pinned by digest.

### In the app (optional update service)

The update service is the [cicd-updater](https://github.com/restow-backup/cicd-updater)
sidecar (ADR 0007). With it, owners and admins update from **Settings → Updates**:

1. GarnetOps shows the running version and the newest release it may install, with a
   link to its release notes. Releases the service refuses are listed with the reason.
2. Choose when it starts (now, or in 1 minute to 1 hour) and press **Schedule update**.
   GarnetOps asks for your password and a code first if your sign-in is older than ten
   minutes.
3. Everyone who is signed in sees a banner with a countdown and can finish their work.
4. The service verifies the signatures of `release.json` and every image, backs up the
   database, stops API and worker, starts the new version, waits until it reports the
   new version and runs a check through the web edge. During the few minutes the API is
   down, the web address shows a maintenance page that comes back by itself.
5. The page reloads once with the new version. **Acknowledge** clears the result.

Every step is written to the audit log (filter **Updates**), with who asked for it.

#### Set it up

```sh
cd /opt/garnetops
# Verify the sidecar image and pin the verified digest in .env:
cosign verify ghcr.io/restow-backup/cicd-updater:1.0.0 \
  --certificate-identity-regexp '^https://github.com/restow-backup/cicd-updater/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
#   CICD_UPDATER_IMAGE=ghcr.io/restow-backup/cicd-updater:1.0.0@sha256:<verified digest>
sudo chown root:root updater.yaml && sudo chmod 644 updater.yaml
docker compose run --rm --no-deps updater config check
docker compose --profile updater up -d
docker compose exec updater cicd-updater doctor
```

Put `COMPOSE_PROFILES=updater` into `.env` so a plain `docker compose up -d` keeps the
service running.

The service needs the Docker socket, so it is root-equivalent on this host. It has no
published port, only the API can talk to it, and it installs only releases signed by the
GarnetOps release workflow (`trust.keyless` in `updater.yaml`). It never installs an
older version and never updates on its own. Encrypting its database backups with
[age](https://age-encryption.org) is recommended (`hooks.backup.encryption` in
`updater.yaml`); keep the private key off the host.

To switch in-app updates off on one installation without removing the service, set
`UPDATER_URL=` (empty) in `.env`.

### By hand, with release images

```sh
cd /opt/garnetops
docker compose exec db pg_dump -U garnetops -Fc garnetops > garnetops-$(date +%F).dump
# Set APP_IMAGE and WEB_IMAGE in .env to the digests of the new release, then:
docker compose pull
docker compose up -d
```

Read the release notes first: a release can require a minimum version to update from, or
a new `.env` key.

### An update needs attention

If an update fails after the point of no return (services stopped) and going back is not
provably safe, the service stops GarnetOps, keeps the backup and ends the run in
`needs_attention`. Nothing happens automatically from then on. The Updates page and the
banner say so.

1. On the host: `docker compose exec updater cicd-updater recover show` lists what
   happened, the backup file and the recorded recovery commands. Review them before you
   run any.
2. Decide: forward (fix the cause, start the new version) or back (restore the backup,
   start the previous images). The service's runbook explains both:
   [a run ended in needs_attention](https://github.com/restow-backup/cicd-updater/blob/main/docs/backups-and-recovery.md#runbook-a-run-ended-in-needs_attention).
3. Only when GarnetOps runs again, acknowledge the result on the Updates page.

If you need help, write to the address in [SECURITY.md](../SECURITY.md) for security
matters, or open an issue for everything else.
