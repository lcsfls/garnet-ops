# Updating GarnetOps

GarnetOps follows Semantic Versioning and never breaks an installation within a major
version (AGENTS.md rule 2): migrations only add, and a pipeline that passed yesterday does
not fail tomorrow because of an update. Security fixes are published for every supported
version line, free of charge.

Signed releases are published since 0.0.3. An installation that builds its images from
this repository updates by building the newest release tag; one that runs the signed
release images updates with the optional update service or by hand.

## Images built from source

`docker compose pull` does not apply here: it only fetches published images, and
`garnetops:local` exists only on your host. Instead:

```sh
cd /opt/garnetops
docker compose exec db pg_dump -U garnetops -Fc garnetops > garnetops-$(date +%F).dump
git fetch --tags
TAG=$(git tag --list 'v*' --sort=-v:refname | head -n 1)   # the newest release, e.g. v0.0.4
git checkout "$TAG"
VERSION=$(echo "$TAG" | cut -c2-)
docker build --target app -t garnetops:local     --build-arg VERSION="$VERSION" .
docker build --target web -t garnetops-web:local --build-arg VERSION="$VERSION" .
docker compose up -d
docker compose ps
```

The API migrates the database when it starts; migrations only add, so your data stays.
Read the release's section of [CHANGELOG.md](../CHANGELOG.md) for new `.env` keys first.
Keep `UPDATER_URL=` empty in `.env` as long as you build from source: the update service
installs signed release images only.

## Signed release images

There are two ways to update, and both install the signed images of a release, pinned by
digest.

### In the app (optional update service)

The update service is a small sidecar container (ADR 0007). It is maintained in this
repository (`updater/`, ADR 0026; it started as
[cicd-updater](https://github.com/restow-backup/cicd-updater)) and published with every release
as `ghcr.io/lcsfls/garnetops-updater`, signed like the other images. With it, owners and admins
update from **Settings → Updates**:

1. When the service's daily check finds a newer release, owners and admins see a dot at
   **Settings** in the sidebar and the new version next to **Updates**.
   GarnetOps shows the running version and the newest release it may install, with a
   link to its release notes. Releases the service refuses are listed with the reason.
2. Choose when it starts (now, or in 1 minute to 1 hour) and press **Schedule update**.
   GarnetOps asks for your password and a code first if your sign-in is older than ten
   minutes.
3. Everyone who is signed in sees a banner with a countdown and can finish their work.
4. The service verifies the signatures of `release.json` and every image, backs up the
   database, stops API and worker, starts the new version, waits until it reports the
   new version and runs a check through the web edge. During the few minutes the API is
   down, the web address shows a maintenance page that comes back by itself.
5. The page reloads once with the new version. Anyone can close the result banner for
   themselves; the banner of the next update shows again. **Acknowledge** clears the
   result for everyone.

Every step is written to the audit log (filter **Updates**), with who asked for it.

#### Set it up

Run the commands as root, or as a user who may write `/opt/garnetops` and use Docker.
`<version>` is the release you run, for example `0.1.0`. The service image is published with
every release from the one that the [changelog](../CHANGELOG.md) names first; older releases
have none, and their installations keep updating by hand.

```sh
cd /opt/garnetops
VERSION=<version>
# The digest of the sidecar image is in the signed release.json of the release:
curl -fsSL "https://github.com/lcsfls/garnet-ops/releases/download/v$VERSION/release.json" \
  | jq -r '.images.updater.digest'
# Verify the image against the release workflow of this project, at the release tag:
cosign verify "ghcr.io/lcsfls/garnetops-updater:$VERSION@sha256:<digest>" \
  --certificate-identity "https://github.com/lcsfls/garnet-ops/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Pin the verified digest in .env:
#   CICD_UPDATER_IMAGE=ghcr.io/lcsfls/garnetops-updater:<version>@sha256:<digest from the release>
chown root:root updater.yaml && chmod 644 updater.yaml
docker compose run --rm --no-deps updater config check
docker compose --profile updater up -d
docker compose exec updater cicd-updater doctor
```

The service never updates itself, because its container holds the Docker socket. To use a newer
service image, repeat the verification for that release and change `CICD_UPDATER_IMAGE`; a
release that needs a newer service is refused with a clear reason until you do. Leave
`selfCheck` in `updater.yaml` switched off: it would look at the release list of the original
cicd-updater project, not at ours.

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

### Scanner service from 0.0.9

From 0.0.9 syft and grype run in a service of their own, without network, vault key or database
([ADR 0028](adr/0028-scanner-isolation.md)). In-app updates replace the images, not
`docker-compose.yml` and `updater.yaml`, so an installation set up before 0.0.9 keeps scanning
inside the worker until you replace both files; nothing breaks in the meantime, and
**System → Scanners → Isolation** says "In the worker". To switch:

```sh
cd /opt/garnetops
VERSION=<the release you run, 0.0.9 or newer>
cp docker-compose.yml docker-compose.yml.bak && cp updater.yaml updater.yaml.bak
for f in docker-compose.yml updater.yaml; do
  curl -fsSL -o "$f" "https://raw.githubusercontent.com/lcsfls/garnet-ops/v$VERSION/$f"
done
chown root:root updater.yaml && chmod 644 updater.yaml
docker compose up -d
docker compose ps   # scanner and worker should be running, scanner healthy
```

If you changed either file yourself, carry those changes over (compare with the `.bak` copies).
Replace both files together: the update service only updates the services `updater.yaml` lists,
and refuses a list that names a service the Compose file does not have. Installations built from
source get both files with `git checkout` of the release tag.

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
   [a run ended in needs_attention](https://github.com/restow-backup/cicd-updater/blob/b2dd4efd8ff10a5d29ddcfeda762a0ced9a87874/docs/backups-and-recovery.md#runbook-a-run-ended-in-needs_attention)
   (the original project's documentation at the commit that `updater/` was taken from).
3. Only when GarnetOps runs again, acknowledge the result on the Updates page.

If you need help, write to the address in [SECURITY.md](../SECURITY.md) for security
matters, or open an issue for everything else.
