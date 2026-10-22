# GarnetOps

Self-hosted security platform for SecOps teams and everyday sysadmins:
repository quality gates, dependency and container update checks, host
monitoring and an XDR view via Wazuh, with AI triage on the customer's own
OpenAI-compatible model. No code, finding or log leaves the customer's network.

Dual-licensed: [AGPL-3.0-only](LICENSE) and a commercial license
([LICENSING.md](LICENSING.md)). Domain: garnetops.com.

**Status:** early development, no release yet. Working today: sign-in with
mandatory TOTP or a passkey, an account page for your password, authenticator app, passkeys
and sessions ([docs/account.md](docs/account.md)), repositories over HTTPS or SSH (generated deploy keys), several
HTTPS repositories at once with one token, dependency scanning with syft and grype
on a local vulnerability database, findings with CVSS/EPSS and export (CSV, XLSX,
PDF, text), repository pages with scan and patch history, package inventory,
nightly scans, a team with invitations and roles, notifications by webhook (Discord,
Slack-compatible) and mail ([docs/notifications.md](docs/notifications.md)), quality gates
with a CI check per pull request
([docs/quality-gates.md](docs/quality-gates.md)), servers inventoried over SSH without an
agent, with a setup script and pinned host keys ([docs/servers.md](docs/servers.md)), a
read-only Proxmox VE view of nodes, VMs and containers with a pinned API certificate
([docs/proxmox.md](docs/proxmox.md)), AI triage of findings with your own OpenAI-compatible model
([docs/ai.md](docs/ai.md)), fix proposals with pull requests that raise a vulnerable dependency to its
fixed version, opened with a separate write token per repository and always left to your review
([docs/fix-prs.md](docs/fix-prs.md)), a read-only XDR page for your own Wazuh with alerts,
MITRE ATT&CK tactics, file integrity, agents and an enrollment helper
([docs/xdr.md](docs/xdr.md)), an attack overview with a world map from local GeoIP data you load yourself
([docs/attacks.md](docs/attacks.md)), audit log, a Docker Compose stack and optional signed in-app updates.

## What GarnetOps is built on

All of it runs inside your network. Scanners and Git run as separate programs, never
linked into GarnetOps; the full list with versions and licences is in
[docs/COMPONENTS.md](docs/COMPONENTS.md).

| Part | Tool | Licence | What it does in GarnetOps |
| --- | --- | --- | --- |
| Package inventory | [syft](https://github.com/anchore/syft) | Apache-2.0 | Lists every dependency of a repository (SBOM) on each scan |
| Vulnerability matching | [grype](https://github.com/anchore/grype) | Apache-2.0 | Matches the inventory against a local vulnerability database (NVD, GitHub Advisories, distribution feeds, CISA KEV) |
| Repository access | git, OpenSSH client | GPL-2.0, BSD | Shallow, read-only clones over HTTPS or SSH with a deploy key |
| Web edge | [Caddy](https://caddyserver.com) | Apache-2.0 | HTTPS (TLS 1.3, post-quantum key exchange), security headers, serves the web app |
| Database and jobs | [PostgreSQL 17](https://www.postgresql.org), [pg-boss](https://github.com/timgit/pg-boss) | PostgreSQL, MIT | Data, and the scan queue with nightly schedules |
| API | [Node.js 24](https://nodejs.org), [Hono](https://hono.dev), [Drizzle ORM](https://orm.drizzle.team) | MIT, MIT, Apache-2.0 | REST API under `/api/v1`, migrations |
| Sign-in | [better-auth](https://www.better-auth.com) | MIT | Accounts, sessions, mandatory TOTP; passwords hashed with Argon2id (`node:crypto`) |
| Web app | [React 19](https://react.dev), [TanStack Router and Query](https://tanstack.com), [Tailwind CSS](https://tailwindcss.com), [Lucide](https://lucide.dev), [i18next](https://www.i18next.com) | MIT, MIT, MIT, ISC, MIT | The interface in English and German, fonts and icons served by GarnetOps itself |
| Attack overview | [DB-IP Lite](https://db-ip.com) (country and ASN), [Natural Earth](https://www.naturalearthdata.com) | CC BY 4.0, public domain | Location of attacking addresses from tables you load yourself (never shipped), and the country shapes of the map. IP geolocation by DB-IP (db-ip.com), CC BY 4.0 |
| Updates (optional) | [cicd-updater](https://github.com/restow-backup/cicd-updater) | Apache-2.0 | Installs signed releases with a backup first, once releases exist |

Secrets you store (access tokens, deploy keys) are sealed with a post-quantum hybrid
scheme (ML-KEM-1024 and X25519, ADR 0004); only the scan worker holds the key to open them.

## Getting started

Until the first release there are no published images, so you build them from this
repository. You need one Linux host (a VM, or an LXC container) with Docker Engine 26 or
newer and the Compose plugin v2.24 or newer, 4 CPU cores, 8 GB RAM and about 40 GB of
disk for the build.

```sh
git clone https://github.com/lcsfls/garnet-ops.git /opt/garnetops
cd /opt/garnetops
docker build --target app -t garnetops:local     --build-arg VERSION=0.0.1 .
docker build --target web -t garnetops-web:local --build-arg VERSION=0.0.1 .

sh deploy/install.sh garnetops.example.com garnetops:local garnetops-web:local
echo 'UPDATER_URL=' >> .env    # in-app updates need signed releases; off for local builds
docker compose up -d
docker compose ps              # every service should become "healthy"
```

`deploy/install.sh` writes `.env` (mode 0600) with a random database password and session
secret. Use the host name your users will open, without a port. Keep a copy of `.env` in
your password manager: database backups are of no use without it.

**In a Proxmox LXC container**, Docker needs `nesting=1,keyctl=1` (for example
`pct create … --unprivileged 1 --features nesting=1,keyctl=1`). GarnetOps clones and scans
untrusted repositories; a VM isolates that better than a container that shares the host
kernel, so prefer a VM where you can.

### First sign-in: setup token and second factor

1. Read the one-time setup token from the API log:
   ```sh
   docker compose logs api | grep -i token
   ```
   The token only works while no account exists. Every API restart before setup prints a
   new one; once the first account exists, there is none.
2. Open `https://<your host name>`, enter the token and create the owner account.
3. Set up the **second factor**. It is mandatory for every account, with no way to skip
   it: scan the QR code with an authenticator app (any TOTP app works), enter the code and
   save the backup codes it shows; each one signs you in once if the app is lost. Until the factor is set up, a session can only set
   it up or sign out.

### HTTPS only (port 443)

GarnetOps serves its web app and API over HTTPS only. Port 443 is the application; port
80 only redirects to HTTPS and answers the container health check. By default the
certificate comes from Caddy's own certificate authority (`GARNETOPS_TLS=internal`); an
email address there switches to Let's Encrypt, and your own certificate works as well
(see [docs/installation.md](docs/installation.md#https)).

**Behind a reverse proxy** (Nginx Proxy Manager, Traefik, another Caddy), forward to
`https://<GarnetOps host>:443`, never to port 80 (that ends in a redirect loop), and send
the host name as TLS server name. In Nginx Proxy Manager:

- Details: scheme `https`, forward host = the GarnetOps host's IP, port `443`
- SSL: your certificate for the public name, "Force SSL" on; leave HSTS to GarnetOps
- Advanced:
  ```nginx
  proxy_ssl_server_name on;
  proxy_ssl_name garnetops.example.com;
  ```

`PUBLIC_URL` in `.env` must be exactly the address users open, because sign-in cookies
and the cross-site request check depend on it. Behind a proxy, GarnetOps currently sees
the proxy's address as the client address (audit log, sign-in rate limits).

### Updating (no signed images yet)

Without a release there are no signed images, so the in-app update service cannot be
used. Update by hand from the repository:

```sh
cd /opt/garnetops
docker compose exec db pg_dump -U garnetops -Fc garnetops > garnetops-$(date +%F).dump
git pull
docker build --target app -t garnetops:local     --build-arg VERSION=0.0.1 .
docker build --target web -t garnetops-web:local --build-arg VERSION=0.0.1 .
docker compose up -d
```

Database migrations run when the API starts; they only add, so your data stays. Read
[CHANGELOG.md](CHANGELOG.md) for new `.env` keys first. Once signed releases exist, follow
[docs/updating.md](docs/updating.md) instead, including in-app updates.

### Adding repositories

**Repositories → Add repository** takes an `https://` address (public or with a
read-only access token) or an SSH address (GarnetOps creates a deploy key you add to the
repository). **Add several at once** takes up to 50 `https://` addresses, one per line,
that share one branch and one token; repositories that are already connected are
skipped. Every repository keeps its own encrypted copy of the token.

## More

- Install with release images: [docs/installation.md](docs/installation.md)
- Update: [docs/updating.md](docs/updating.md)
- Account, passkeys and a lost second factor: [docs/account.md](docs/account.md)

- Security reports: [SECURITY.md](SECURITY.md) (please not as a public issue)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

- Rules for contributors and AI agents: [AGENTS.md](AGENTS.md)
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Components and licenses: [docs/COMPONENTS.md](docs/COMPONENTS.md)
- Architecture decisions: [docs/adr/](docs/adr/)
- Visual mockup: [design/mockup/mockup.html](design/mockup/mockup.html) (open in a browser, works offline)
