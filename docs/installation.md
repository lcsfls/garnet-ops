# Installing GarnetOps

GarnetOps runs as a Docker Compose stack on one Linux host in your network (ADR 0007).
Nothing is sent outside your network, except what you switch on: vulnerability data
updates (the worker) and release checks (the optional update service).

## Requirements

- Linux, amd64 or arm64, Docker Engine 26 or newer with Compose v2.24 or newer
- 2 CPU cores and 4 GB RAM for a few dozen repositories; more for parallel scans
- A host name your users open, for example `garnetops.example.lan`
- Outbound HTTPS from the host to your Git servers, and to `grype.anchore.io` if the
  worker should update the vulnerability database itself (`GARNETOPS_GRYPE_DB_UPDATE=auto`)
- Only if you switch them on in Settings, Attack overview: outbound HTTPS from the worker to
  `download.db-ip.com` (monthly download of the location data) and to `api.abuseipdb.com` (reputation
  lookup). Both are off by default; the data can also be imported by hand ([attacks.md](attacks.md))
- Only if you switch it on in Settings, Sign-in: LDAPS (usually port 636) or LDAP with StartTLS (port 389) from the
  **worker** to your directory servers ([ldap.md](ldap.md)). The browser never talks to the directory.

## Install

**There is no release yet.** Until the first release, build the images from this
repository as described in the [README](../README.md#getting-started); the rest of this
page (HTTPS, air-gapped operation, what runs) applies to both. The steps below are for
release images and work from the first release on.

### With release images (from the first release on)

```sh
sudo mkdir -p /opt/garnetops && cd /opt/garnetops
# The files of the release you install (same tag for all of them):
for f in docker-compose.yml updater.yaml .env.example deploy/Caddyfile deploy/install.sh; do
  sudo curl -fsSL --create-dirs -o "$f" "https://raw.githubusercontent.com/lcsfls/garnet-ops/v0.0.2/$f"
done
sudo sh deploy/install.sh garnetops.example.lan \
  "ghcr.io/lcsfls/garnetops:0.0.2@sha256:<app digest from the release>" \
  "ghcr.io/lcsfls/garnetops-web:0.0.2@sha256:<web digest from the release>"
sudo docker compose up -d
sudo docker compose logs api   # prints the one-time setup token
```

`deploy/install.sh` writes `.env` (mode 0600) with a random database password and session
secret. Keep a copy of `.env` in your password manager: the backup of the database is of
no use without it, and the vault key (the `vault` volume) belongs to the same backup set.

Open `https://garnetops.example.lan`, enter the setup token, create the first account and
set up its second factor.

Release images are signed; check them before the first start:

```sh
cosign verify ghcr.io/lcsfls/garnetops:0.0.2@sha256:<digest> \
  --certificate-identity "https://github.com/lcsfls/garnet-ops/.github/workflows/release.yml@refs/tags/v0.0.2" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## HTTPS

The `web` service terminates TLS (TLS 1.3 with the hybrid post-quantum key exchange
X25519MLKEM768 where the browser supports it). Set `GARNETOPS_TLS` in `.env`:

| Value | Certificate |
| --- | --- |
| `internal` (default) | Caddy's own certificate authority. Distribute its root (`docker compose exec web cat /data/caddy/pki/authorities/local/root.crt`) to your clients, or use one of the other options. |
| an email address | ACME (Let's Encrypt); needs a public DNS name that reaches this host on port 80 or 443. |
| `/certs/cert.pem /certs/key.pem` | Your own certificate; put both files into `./certs` (or `GARNETOPS_CERTS_DIR`). |

`PUBLIC_URL` must be exactly the address users open (with the port if it is not 443):
sign-in cookies and the cross-site request check depend on it.

## Air-gapped installation

Set `GARNETOPS_GRYPE_DB_UPDATE=off` and import the vulnerability database into the
`vulndb` volume yourself (a grype database archive, version 6):

```sh
docker compose cp vulnerability-db.tar.zst worker:/tmp/
docker compose exec -e GRYPE_DB_CACHE_DIR=/var/lib/garnetops/vulndb worker \
  /opt/scanners/grype db import /tmp/vulnerability-db.tar.zst
```

Our own database build (vunnel) follows on the roadmap.

## What runs

| Service | Image | Notes |
| --- | --- | --- |
| `web` | `garnetops-web` | Caddy; the only published ports (443, 80 redirects) |
| `api` | `garnetops` | migrates the database on start; internal network only |
| `worker` | `garnetops` | clones into a RAM disk, runs syft and grype; holds the vault private key |
| `db` | `postgres:17` | data in the `db-data` volume |
| `init` | `garnetops` | creates the vault key pair once, then exits |
| `updater` | `cicd-updater` | optional (profile `updater`), see [updating.md](updating.md) |

Back up the volumes `db-data` and `vault` together with `.env`.
