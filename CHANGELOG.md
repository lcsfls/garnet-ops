# Changelog

All notable changes to this product are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Security-relevant changes are listed under **Security** in every release.

## [Unreleased]

### Added

- **Sign in with GitHub, Gitea or Forgejo** to connect an account, instead of pasting a token
  ([ADR 0031](docs/adr/0031-sign-in-to-forges.md)). Admins register GarnetOps once per forge under **Settings → Connected
  accounts → Sign-in with a forge**: a GitHub App with read permissions (device flow, no callback address needed) or a
  Gitea/Forgejo OAuth2 application (authorization code with PKCE). The worker renews the tokens before they expire.
  Pasted tokens keep working.
- API: `/api/v1/forge-apps` and `/api/v1/forge-sign-in`; connections carry `authMethod`.
- **Code → Pull requests** ([ADR 0032](docs/adr/0032-pull-request-overview.md), [docs](docs/pull-requests.md)): the open pull
  requests of your repositories with the quality gate result of their latest commit, read every 15 minutes with each
  repository's read credential. **Check now** checks a pull request's head exactly as a CI pipeline would.
- API: `/api/v1/pull-requests`, `/api/v1/pull-requests/sources`, `POST /api/v1/pull-requests/refresh` and
  `POST /api/v1/pull-requests/{id}/check`.
- **Website monitoring** is back as a module, off by default ([ADR 0033](docs/adr/0033-website-monitoring-as-a-module.md),
  [docs](docs/websites.md)). Owners and admins switch it on under **Settings → Modules**; then **Monitoring → Websites** watches
  your own domains, host names and addresses from the outside (certificates and their expiry, DNS, SPF and DMARC, security
  headers). Port checks run only for names whose control you proved with a DNS TXT record or a file, and only after you confirm
  them per name. The checks are those of 0.0.3 (ADR 0023), without location data. Old `/exposure` links lead to the new page.
- API: `GET /api/v1/organization/modules`, `PUT /api/v1/organization/modules/{name}`, `organization.modules` in
  `GET /api/v1/me`, `websites` in `GET /api/v1/search`, and `/api/v1/exposure` again (answers 409 `module-off` while the module is
  off).

### Security

- Website monitoring makes outbound connections to public hosts only after an owner or admin switches the module on (audited).
  While it is off, no check runs and its API refuses every request; switching it off also switches stage 2 off for every website
  and voids the confirmations. The worker checks the switch again before each run and each proof check.

## [0.0.11] - 2026-10-29
<!-- title: Connected accounts, private repositories and interactive statistics -->

### Added

- Statistics: interactive charts. Open findings as stacked areas, found and resolved above and below a baseline, gate results as
  stacked columns. A crosshair names every number of a day or week and moves across the three charts together; the charts work with
  the arrow keys and read their numbers to screen readers. Found, Resolved and Gates passed show their course as a sparkline, time to
  fix and the rankings get bars.
- A click on a day or week of **Found and resolved** (or a number in its table) opens exactly the findings first seen or resolved in
  it. The findings list shows that period as a filter you can remove.
- API: `firstSeenFrom`, `firstSeenTo`, `resolvedFrom`, `resolvedTo` and `tz` on `GET /api/v1/findings`, its counts and its export
  (calendar days in the given time zone, both ends included).
- **Settings → Connected accounts** ([ADR 0030](docs/adr/0030-personal-forge-connections.md)): each person connects their own
  GitHub, Gitea or Forgejo account with a read token and adds repositories by ticking them in a list. The token is sealed
  in the vault, only the worker opens it, and nobody else can use it.
- Private repositories: repositories added from a connected account are visible only to the person who added it, until it is
  shared with the organisation (owners and admins at once, members on request). They never reach notification channels.
  Every repository that exists today stays visible to everyone.
- API: `/api/v1/forge-connections`, `/api/v1/share-requests`, `POST /api/v1/repositories/{id}/share` and `/unshare`;
  repositories carry `visibility`, `mine` and `shareRequested`.

### Security

- Removing a person from the organisation deletes their connected accounts with the sealed tokens, and their private
  repositories.

### Changed

- Every dropdown opens a list in the look of the app, in light and dark mode, where the browser supports customisable selects
  (Chrome and Edge 135 and later); other browsers keep their own list. The chevron turns while the list is open.
- Collapsible sections such as **How grades work** or **Show as table** open and close smoothly, with a turning chevron. Reduced
  motion switches the animation off.

## [0.0.10] - 2026-10-29
<!-- title: Early warnings and channel filters -->

### Security

- zod 4.6.7 instead of 3.25.76 in the API, the worker and the web app (GHSA-mrhx-c7xc-m3w5, high: memory exhaustion while
  validating oversized collections). Validation behaves as before; one zod version remains in the product.
- The update sidecar's build and test tooling: vite 8.3.5 (GHSA-587h-7wmj-h5pm and five more), fast-uri 3.1.9 (four advisories), zod
  4.6.7. None of them is part of the sidecar image except zod. esbuild 0.27.7 stays for the sidecar's bundler (GHSA-g7r4-m6w7-qqqr,
  low): it only affects esbuild's development server, which the build does not start.

### Added

- Notification channels: the new event **New findings** with a minimum severity per channel (high and above unless chosen
  otherwise), and a choice of repositories per channel. **Edit** on a channel changes its events and filters. Existing channels
  keep exactly what they were sent before.
- Discord channels get an embed: a title that links to GarnetOps, a colour per kind of event and the organisation in the footer.
- **Daily → Early warnings** ([ADR 0029](docs/adr/0029-early-warnings.md)): after each update of the vulnerability database,
  the stored package lists of all repositories are matched again, without a clone and without network. New advisories for
  packages a repository uses are listed until the next scan confirms or clears them. They never change findings, grades or
  quality gates. Channels can subscribe to the new event *Early warnings*. API: `GET /api/v1/early-warnings`.

### Changed

- The release workflow sets the title and text of the GitHub release from this changelog; releases are no longer edited by hand.

## [0.0.9] - 2026-10-29
<!-- title: Isolated scanner service -->

### Security

- syft and grype run in a scanner service of their own ([ADR 0028](docs/adr/0028-scanner-isolation.md)): no network at all, no
  vault key, no database address, the clones and the vulnerability database read-only, its own CPU, memory and process limits. A
  repository crafted to exploit a scanner can no longer reach stored tokens and deploy keys or send anything away. Deploy keys,
  git's home directory and the reports stay in the worker; only the clone is shared, in memory, and removed after each scan.

### Added

- **System → Scanners → Isolation** shows where syft and grype run, whether the scanner service answers and whether it runs the
  worker's release. `GET /api/v1/system/status` has the same as `scanners.isolation`.
- New optional `.env` keys `GARNETOPS_SCANNER_CPUS` (default 2) and `GARNETOPS_SCANNER_MEMORY` (default 4g).

### Changed

- `docker-compose.yml` has the new service `scanner` and the in-memory volumes `scan-work` and `scanner-socket`; `updater.yaml` lists
  `scanner` so that updates replace it with the worker. **In-app updates do not change these files**: download both from the release
  to switch ([docs/updating.md](docs/updating.md#scanner-service-from-009)). Until then the worker scans by itself as before, and the
  System status page says so. `GARNETOPS_WORK_TMPFS` now also sizes the clones' volume.

## [0.0.8] - 2026-10-28

### Changed

- The web app runs on SvelteKit with Svelte 5 instead of React ([ADR 0027](docs/adr/0027-web-app-on-sveltekit.md)). Pages, texts,
  colours, icons, links and addresses are the same; bookmarks keep working. Nothing in the API, the database or the configuration
  changes. The browser loads less framework code.

### Fixed

- The repository list showed the Gate, Scanners and Trend columns under the wrong headers on wide screens (1440p and up).
- Switching the nightly scan off was refused with a generic error; it now keeps the stored time and switches the scan off.

### Security

- The Content Security Policy is generated by the web build: `'self'` plus the SHA-256 of the app's one start script and of one fixed
  style attribute of SvelteKit's screen-reader announcer. Nothing inline runs or applies unless it matches those hashes; there is
  still no `'unsafe-inline'`. The web image and the end-to-end suite use the same policy.

## [0.0.7] - 2026-10-28

### Added

- **Statistics** (Daily → Statistics): what was found and resolved, the median time to fix per severity, gate results, merged fix pull
  requests and failed scans over the last 30, 90 or 365 days, counted in your own calendar days (daily bars for 30 days, weekly bars
  from Monday for longer ranges). It also ranks today's open findings by repository and package and lists the oldest open critical and
  high findings. Every number links to the list behind it, and every chart can be shown as a table
  ([docs/statistics.md](docs/statistics.md)). The same data is available as `GET /api/v1/statistics`.

## [0.0.6] - 2026-10-28

0.0.5 was tagged, but its release run failed in the upgrade test, so no images were published for it; 0.0.6 contains everything
listed under 0.0.5.

### Fixed

- The release's upgrade test through the update service gave the service a token volume of its own, so the app never saw the
  service's token, kept its version to itself and the upgrade stopped with `health.version_mismatch`. The test now gives the service
  the project's own shared volume (`updater-shared`), as a real installation does. Installations were not affected.

## [0.0.5] - 2026-10-28

The first published release of the developer pipeline. 0.0.4 was tagged, but its release run failed
(the external update-sidecar image did not exist), so no images were published for it; 0.0.5
contains everything listed under 0.0.4.

### Added

- The update service (the optional sidecar behind **Settings → Updates**) is now part of this repository (`updater/`, Apache-2.0,
  [ADR 0026](docs/adr/0026-maintain-the-update-sidecar-in-this-repository.md)) and is published with each release as
  `ghcr.io/lcsfls/garnetops-updater:<version>`, signed like the other two images, with an SBOM. Its signed digest is in `release.json`
  (`images.updater`). Set it up with `CICD_UPDATER_IMAGE=ghcr.io/lcsfls/garnetops-updater:<version>@sha256:<digest from the release>`
  as described in [docs/updating.md](docs/updating.md#set-it-up). Releases that complete from now on carry it (the release of 0.0.4 did not complete).

### Changed

- `CICD_UPDATER_IMAGE` in `.env.example` points to the GarnetOps image instead of `ghcr.io/restow-backup/cicd-updater`. If you set the
  old value, replace it with the verified GarnetOps image; the old one never existed on the registry.
- The release workflow builds the update service, runs the upgrade test from the previous release on that very image, and uses the
  build, smoke, publish and release.json actions from this repository instead of an external commit.
- `docs/updating.md` and `docs/installation.md`: the commands no longer use `sudo`, the update service is verified against the identity
  of this project's release workflow, and the runbook links point to a fixed commit of the original project.
- CI checks the update service (lint, types, tests, the action bundle, the vendored SDK against its source, the image build for amd64).

### Fixed

- A release could not be made, and in-app updates could not be set up, because the update service image named in the guide
  (`ghcr.io/restow-backup/cicd-updater:1.0.0`) was never published: the release of 0.0.4 stopped in the smoke test with "manifest
  unknown", and installations got "denied". The release no longer depends on an external image.

### Security

- The update service holds the Docker socket and is root-equivalent on the host. Its supply chain now has the same review as the
  application: frozen lockfile, install scripts only for the bundler, a minimum age for new package versions, base images pinned by digest,
  a signed image with an SBOM, and an upgrade test on the exact image that ships. The same release identity now signs the service and the
  releases it installs; the service still never updates itself and runs only the digest you verified and pinned
  ([threat model](docs/adr/0026-maintain-the-update-sidecar-in-this-repository.md#threat-model)).

## [0.0.4] - 2026-10-28

Tagged, but not released (see 0.0.5).

GarnetOps is now a pure **developer pipeline**: security for Git repositories across Forgejo, Gitea and GitHub, self-hosted
([ADR 0025](docs/adr/0025-focus-on-the-developer-pipeline.md)). Everything about infrastructure is removed from the product. It stays
available in the git history and in the tag `v0.0.3`.

### Removed

- **Servers.** The agentless SSH inventory of servers (Infrastructure → Servers), the add-server wizard, the host setup script and its
  one-time links, host key confirmation, server packages, findings, runs and grades, and the CSV import. The repository SSH deploy keys
  and pinned host keys are not part of this and stay.
- **Proxmox VE.** The read-only view of nodes, VMs and containers and its settings section.
- **UniFi.** The network devices view, the IPS preview and its settings section.
- **Wazuh / XDR.** The XDR page, the sync, the live alert feed, the agent enrollment helper and the settings section.
- **Attack overview.** The Attacks page with the globe and the world map, the local GeoIP data (DB-IP import and download), the
  optional AbuseIPDB lookup, the home location, the attack AI summary and the retention job. The map shapes and the d3-geo dependency
  are gone.
- **External exposure.** The Exposure page and assets, proof of control, stage 1 and 2 checks and Certificate Transparency suggestions.
- The **Infrastructure** navigation group, the settings sections Proxmox, UniFi, Exposure, XDR / Wazuh and Attack overview, their rows on
  the System status page (and the GeoIP card), their command search entries, their notification events and settings, and the server
  count in the AI triage context.
- API routes `/api/v1/hosts`, `/host-setup`, `/proxmox`, `/unifi`, `/exposure`, `/xdr` and `/attacks`, and the `servers`, `guests` and
  `assets` fields of `/api/v1/search`. This breaks the API of 0.0.3 within a 0.x line, on purpose.
- Dependencies d3-geo, d3-array, internmap, @types/d3-geo and @types/geojson; `scripts/build-world-map.mjs`; the DB-IP, Natural Earth,
  AbuseIPDB, crt.sh and MaxMind entries of `docs/COMPONENTS.md`.

**Your data.** Migration 0024 **deletes the data of the removed modules** when you update: every row of their tables (servers, inventories,
findings, Proxmox, UniFi, Wazuh and exposure data, GeoIP tables, stored attack events and source IP addresses, OSINT results), and the
personal notifications and notification choices of the removed event types. No table or column is dropped (that waits for 1.0). If you need anything from those modules, export it or take a database backup **before** updating,
while the version that has them still runs; the in-app update takes a backup, and `v0.0.3` is the last version that can read it. Old audit
log entries of the removed actions stay and keep readable labels.

After updating, revoke the credentials you created at the source systems for these modules (the Proxmox API token, the UniFi API key and
IPS user, the two Wazuh users, the public key of the server access key in `authorized_keys` on your servers). GarnetOps no longer has
them, but they still exist there.

### Changed

- The preference matrix of personal notifications has the groups Code, Account and team, and System. The event "A certificate changed"
  now means the certificate of a directory server and is in Account and team; your choice for it is kept.
- The audit log filter lists only groups that still exist. Entries of the removed modules show under **All**.
- The worker removes the job queues and schedules of the removed modules on start.
- Grades are for repositories only.
- Documentation: `docs/servers.md`, `proxmox.md`, `unifi.md`, `xdr.md`, `attacks.md` and `exposure.md` are deleted; the ADRs of the
  removed modules are marked as superseded and stay.

### Fixed

- Settings → Updates, the README and the update guide no longer say that there is no release.
  Without the update service, the manual update now builds the newest release tag, with the
  version taken from the tag instead of a fixed number.

### Security

- The stored credentials of the removed integrations are deleted from the database by migration 0024: the SSH key for servers, the
  Proxmox token, the UniFi API key and IPS password, both Wazuh passwords and the OSINT API key. Repository deploy keys, forge tokens, the
  AI key, notification secrets and the directory secrets are not touched.
- Stored source IP addresses, attack events and reputation results (personal data) are deleted.
- The attack surface shrinks: no more outbound connections to servers, Proxmox, UniFi, Wazuh or the public internet scanners, and no SSH key
  that reaches servers.

## [0.0.3] - 2026-10-23

The first published release, an alpha. Every 0.x release is an alpha: features and screens can
still change, and data stays when you update.

### Fixed

- The release build for arm64 stopped in `pnpm install`, because the development PostgreSQL's
  arm64 package was not allowed to run its install script. Every platform of that package is
  listed now. Because of this, 0.0.2 was tagged but never built or published; 0.0.3 contains
  everything listed under 0.0.2.

## [0.0.2] - 2026-10-23

Tagged, but not released: the release build failed (see 0.0.3). Version 0.0.1 was never
tagged; everything built until then is listed here.

### Added

- **System status** (ADR 0024, `docs/system-status.md`). New page **Admin → System status** (owners and admins; also in the command
  search) answers "is everything current and running?" in one read-only place, refreshed every minute while it is open. **Scanners:**
  grype and syft versions, read by the worker (`grype version`, `syft version`) when it starts and after every scan, and whether each
  equals the version this release pins. **Vulnerability database:** build time and age, schema version, source (Anchore's published
  database or imported by hand), last read, the last update attempt with its result and a short reason (never the tool's output),
  the next update, the providers in the database with the number of advisories each (grype prints no counts; they are counted with a
  read-only query over the database file and omitted, with a note, if that does not work). Limits: stale (amber) after 3 days,
  outdated (vermilion) after 7; scanning with an older database stays allowed and the page says what that costs. **Local database
  build (vunnel and grype-db):** "Not set up (planned)" with a link to the roadmap; the report shape for the future builder (per
  provider: last run, result, records, duration) is fixed in the ADR. **GeoIP:** per dataset the release month, age (stale after 45
  days, outdated after 90), source and the last refused load or download attempt. **Integrations:** Wazuh (sync and live feed),
  Proxmox VE, UniFi (sync and IPS preview), directory sign-in (last account check), external exposure (stage 1, stage 2, proof of
  control), the AI endpoint (last connection test and scope) and notification channels (last delivery): configured or not, last
  success, last attempt and its result, and what blocks it (certificate, unacknowledged privileges, refused service account, lost
  proof, unacknowledged external endpoint) or whether it is paused. **Worker and jobs:** heartbeat with version and start time (late
  after 90 seconds), per queue the waiting, running and failed-in-24-hours jobs and the wait of the oldest, the last nightly run with
  the outcome of its scans and the next run, database size and migration state. **Application:** the running version and the update
  service's phase. Every row has a word and an icon (grey check "as expected", amber triangle, vermilion octagon, dashed circle);
  nothing is green. One column of reading width, two from wide, three from xwide; English and German. The overview's vulnerability data
  card gets an age badge and, for admins, a link. `GET /api/v1/system/status` (owners and admins, `no-store`): numbers, states and
  short codes only. Migration 0023 (additive: `worker_heartbeat`, `system_report`, `ldap_config.last_reconcile_*`,
  `ai_settings.last_probe_*`). No new dependency. Not tested against a real downloaded vulnerability database (the build environment
  cannot reach Anchore), only against fake `grype` and `syft` binaries that print what the real ones print and a SQLite file with the
  columns grype's schema has.
- **External exposure monitoring** (ADR 0023, `docs/exposure.md`). New page **Infrastructure → Exposure** watches your organisation's
  own public domains, host names and single public IP addresses from the outside, run by your own installation. Up to 200 assets per
  organisation; only public names and addresses are accepted (private, loopback, link-local, shared, documentation and reserved ranges
  are refused). **Stage 1, from outside, daily and on request, needs no proof:** DNS (A, AAAA, CNAME, MX, NS, CAA, SPF, DMARC), the TLS
  handshake on 443 (chain, names, expiry, key, protocol, cipher, and whether TLS 1.0 and 1.1 are still accepted), one `GET /` over HTTPS
  (at most 3 redirects, only inside the registrable domain or to verified assets; security headers and `Server` banner kept, the body
  read up to 64 KiB and never stored) and a look at plain HTTP, and GeoIP and ASN from the local tables. Plain-rule findings
  (certificate expired or expiring at 30, 14 and 7 days, untrusted or wrong-name certificate, weak key, old TLS, missing HSTS and other
  headers, a banner with a version, no redirect to HTTPS, no SPF, no DMARC or `p=none`, no CAA, a dangling CNAME), no CVE matching of
  banners and no grade: counts by severity. **Verification:** a DNS TXT record `_garnetops-challenge.<domain>` with
  `garnetops-verify=<token>` or the file `/.well-known/garnetops-verify.txt` (a 256-bit token per organisation and asset; not a secret,
  stored as is); checked daily and before every stage 2 run; a proof that disappears switches stage 2 off at once and tells owners and
  admins. A verified domain covers its subdomains only with "Include subdomains". **Stage 2, light active checks, off by default, only
  for verified assets with an explicit, audited acknowledgement per asset** ("I am authorised to test the infrastructure behind this
  name", shown after a warning that a verified domain does not prove ownership of the CDN, hosting or cloud behind it): a TCP connect
  to a fixed list of 30 common ports, at most 4 at a time, at least 200 ms apart, 3 s connect timeout, at most once per 24 hours per
  asset (daily or weekly), a banner of at most 512 bytes read in 2 s only where the service speaks first, TLS details on TLS ports;
  nothing is ever written to a port apart from the TLS handshake. Findings for risky services (critical Docker API; high Telnet, SMB, RDP,
  VNC, databases, Redis, Elasticsearch, Memcached, ...; medium FTP; low cleartext mail and development ports) and new open ports.
  **Certificate Transparency** (Settings → Exposure; off by default, step-up and an acknowledgement, audited): subdomain suggestions
  from crt.sh for verified domains, with the exact request shown; suggestions are never scanned until added. Pentesting (exploitation,
  brute force, fuzzing, credential testing, denial of service) is out of scope and not built. Four new notification events (Account →
  Notifications; owners and admins; app and email): `exposure.certificate_expiring`, `exposure.verification_lost`,
  `exposure.new_open_port`, `exposure.risky_service`. Navigation entry, command search (the page, its settings section and each asset),
  audit filter **Exposure**, English and German, layout steps at base, wide and xwide. API under `/api/v1/exposure`. Migration 0022
  (additive: `exposure_settings`, `exposure_asset`, `exposure_run`, `exposure_finding`, `exposure_port`, `exposure_discovery`). New
  audit actions `exposure.*`. No new dependency and no scanner binary (`node:dns`, `node:net`, `node:tls`, `node:https`). Not tested
  against the real internet or the real crt.sh, only against local servers, throw-away certificates and a fake resolver. This is not
  legal advice: you are responsible for what you check.

- **UniFi IPS events in the attack overview's "Summarise with AI"** (ADR 0022 section 7.6, `docs/attacks.md`). The summary now
  also receives, as **numbers only**, the UniFi events of each period (blocked and alerted, source addresses, the same figures for
  the period before) and the counts per country code and AS number, in a block apart from Wazuh's so the two are never added up.
  Never sent: an IP address, a signature or category, an organisation, console, site, device or machine name, a port, or any text
  from an event; the only text is our own fixed keys and two-letter country codes. The summary works with UniFi alone, without a
  Wazuh connection. Migration 0021 (additive: `attack_summary.connection_id` may be null). `POST /api/v1/attacks/summary` is accepted
  with either source; the `ai.request` audit entry names the origins. The fixed system prompt gained the description of the two
  origins. No new dependency.
- **UniFi integration, read-only and local** (ADR 0022, `docs/unifi.md`). **Settings → UniFi** (owners and admins) connects UniFi
  consoles (UniFi OS or a self-hosted Network Application, 9.0 or newer) through the **official local UniFi Network API** with an
  API key made on the console; the key is sealed in the vault (new secret purpose `unifi-api-key`) and only the worker opens it. The
  client sends `GET` only, to a short allow-list, with response caps, timeouts and defensive parsers; the console's **certificate is
  pinned on first contact** (an admin confirms the SHA-256 fingerprint with a recent sign-in; a changed certificate blocks the sync
  before any request) exactly like Proxmox; loopback, link-local and metadata addresses are refused, private ones allowed. The cloud
  Site Manager API (`api.ui.com`) is never used. A sync every 15 minutes and on request reads sites, devices (name, model, MAC,
  address, state, firmware version, "update available", uptime) and the **number** of clients per site (no client name, MAC or
  address is read or stored). New tab **Servers → Network devices** with a card per console and a sortable, filterable device table
  (offline devices flagged, "update available" as a neutral maintenance hint: GarnetOps cannot match network firmware against
  vulnerability data, so a device is never called vulnerable), a detail dialog, command search and an audit filter. Three new
  notification events (Account → Notifications; owners and admins; app and email): a UniFi certificate changed, a UniFi device is
  offline (after two syncs in a row, once until it was online again), a UniFi firmware update is available (once per device and
  version). Migration 0020 (additive: `unifi_connection`, `unifi_site`, `unifi_device`, `unifi_sync_run`, `unifi_threat_event`).
  New audit actions `unifi.connection_*`, `unifi.certificate_*`, `unifi.sync_requested`. No new dependency. Not tested against a
  real console, only against a local HTTPS server with synthetic answers.
- **UniFi IPS and threat events, a preview, off by default** (ADR 0022). The official API reports no blocked or detected threats; this
  optional preview reads them from the console's **internal, unofficial** API with a **separate local view-only user** (names such as
  `admin`, `root`, `ubnt` are refused; a login answer that reports rights beyond viewing, such as owner, super administrator or any role that is not view-only, stops the preview before anything is read until an owner or admin acknowledges exactly that list, with a recent sign-in and an audit entry; other rights reported later void the acknowledgement, as with Proxmox and Wazuh). The
  password is sealed (`unifi-ips-password`); each poll is login, read, logout with the cookie and CSRF token kept in worker memory
  only, and the only POST requests the client can send are the console's login and logout. Every 60 seconds by default (30 to 600).
  Events (time, source address, blocked or alerted, signature and category as cleaned plain text, the targeted port; never payload,
  destination address or source port) join the **Attacks** page: the numbers, countries, networks and address table (with the
  part "blocked by UniFi"), the live list and stream (one shared sequence with the Wazuh events), and the **globe**, where blocked
  events are dashed steel-blue lines with the legend "Blocked by UniFi" next to "Observed". Kept for the attack overview's
  retention period (90 days) and at most 20,000 per console; "Delete stored addresses now" deletes them too. The Attacks entry
  now also appears when only the preview is used. May stop working with any UniFi update; the rest of GarnetOps does not depend on
  it. `GET /api/v1/xdr/status` gains `attacks`; `/api/v1/attacks/events`, the stream and the overview gain `source`, `action`,
  `destPort`, `unifi` and `blocked` fields (additive).
- **Globe view and live attack feed** (ADR 0021, `docs/attacks.md`, `docs/xdr.md`). **Attacks → Globe | Map**: an orthographic
  **globe** (the default; the flat map stays, and the choice is remembered in this browser) drawn with `d3-geo` (ISC) from the
  vendored Natural Earth shapes, countries filled on the same single-hue scale, with **lines from each source country to your
  network**: three line widths by count, orange ("Observed") or vermilion above an OSINT abuse score of 80 (only with the
  reputation lookup on), drawn in once within about a second. Drag it or use the arrow keys; it turns slowly by itself until
  touched, never under `prefers-reduced-motion`, with a pause button, and requests no frames while the tab is hidden. Text
  alternative that names the busiest countries; the tables stay. New **home location** (Settings → Attack overview: a country
  and optionally a point with two decimals or the capital; no default, so without it the sources are points; owners and admins,
  audited). **Live attack feed**: the worker polls the Wazuh indexer, read-only, every 30 seconds (15 to 300 and the lowest rule
  level 3 to 15, per connection, audited) with one new fixed query template (at most 50 alerts, eight fields, never `full_log`),
  only while the connection is healthy, with back-off, stores the newest 500 events per connection (subject to the attack
  overview's retention period and to "Delete stored addresses now") and tells browsers over `NOTIFY` on a channel per
  organisation. **Latest events** on the Attacks page and **Latest alerts** on the XDR page, fed by `GET /api/v1/attacks/events`
  and the stream `GET /api/v1/attacks/live` (session auth, organisation scoped, resumes with the last event id, heartbeats, at
  most four streams per person, polling every 30 seconds if the stream fails), each new event draws a live line on the globe,
  and an honest status line ("Live — last event 12 s ago", "Waiting for Wazuh", "Paused: connection blocked", switched off).
  Migration 0019 (additive: `wazuh_live_state`, `wazuh_attack_event`, home columns on `attack_settings`). New audit actions
  `attacks.home_changed`, `attacks.home_removed`, `attacks.live_feed_changed`. New dependencies `d3-geo` 3.1.1, `d3-array`
  3.2.4, `internmap` 2.0.3 (ISC) and `@types/d3-geo` 3.1.0 (MIT, dev), listed in `docs/COMPONENTS.md`. The live feed is on for an
  existing Wazuh connection after the update (one small request every 30 seconds; switch it off in Settings). Not tested against
  a real Wazuh indexer, only a local HTTPS server with synthetic answers.
- In-app notifications, toasts and personal preferences (ADR 0019, `docs/notifications.md`, `docs/account.md`).
  **Bell** in the top bar (left of the account menu) with an unread number ("99+" from a hundred, no animation) and a
  panel of the latest notifications grouped by day in your time zone, relative times, mark one or all read, a link on
  each, "Show older" and a link to your settings. Notifications hold a title key, a few facts (names, counts) and an app
  link, never free text or scanned content, and are kept 90 days or 500 per person. Events: new critical findings, a
  blocked gate, a failed scan, a fix pull request merged or failed, a server's SSH host key changed, a Proxmox VE or Wazuh
  certificate changed or sync blocked, an invitation accepted, your role changed, an update finished or failed; role
  decides who is told. They arrive live over one server-sent event stream (`GET /api/v1/me/notifications/stream`, via
  PostgreSQL LISTEN/NOTIFY on the shared connection, resumes with the last id, at most four streams per person) and fall
  back to polling every 30 seconds. **Account → Notifications**: a matrix per event type with "In app" and "Email" (email
  only with an organisation SMTP or Graph channel), a scope where it makes sense, defaults in app on and email off.
  **Personal mail** goes through the organisation's mail channel to your own address only, summary and link, at most one
  per event type every 15 minutes and a digest after that. **Toasts** (our own, no dependency) for the results of
  actions: bottom right, at most three, errors stay until closed, pause on hover and focus, `role="alert"` and
  `role="status"`, keyboard reachable with Alt+Shift+T without taking focus, no green for plain success, reduced motion
  respected. Settings → Notifications and Account → Notifications explain how organisation channels and personal choices
  relate. Migration 0017 (additive: `user_notification`, `notification_preference`). API (additive):
  `/api/v1/me/notifications` (list, `/{id}/read`, `/read-all`, `/stream`) and `/api/v1/me/notification-preferences`. In
  English and German.
- Grades A to F for repositories and servers (ADR 0018, `docs/grades.md`), display only: they never change a gate
  result, a notification or an alert. The worst open finding decides: F a known exploited vulnerability (CISA KEV)
  with a fix, E a critical with a fix, D a high with a fix or a critical without, C a medium with a fix or a high
  without, B anything milder, A nothing open. Accepted risks do not count while the acceptance lasts and count again
  once it has run out. A repository or server that was never scanned has no grade (not an A); after a failed run the
  grade of the last successful one stays, marked as such. A is neutral, never green. A Grade column on the
  Repositories and Servers lists (letter badge, a note on hover or focus with the reason in plain words and a link to
  the findings behind it), the grade under the title of both detail pages, sorting (F first), a grade filter and a
  short "How grades work" help, in English and German. API (additive): `grade`, `gradeReason` and `gradeStale` on
  `GET /repositories`, `/repositories/{id}`, `/hosts` and `/hosts/{id}`; `sort=grade` and `grade=` on both lists;
  `GET /repositories/grades` and `GET /hosts/grades`; `fixable` and `kev` filters on `GET /hosts/{id}/findings`. The
  server page has the same filters (severity, known exploited, fix available). No migration.
- Account page (avatar menu, then "Account settings"; ADR 0017, `docs/account.md`), readable width with sections on
  the left like Settings: **Profile** (display name; the email address is shown and cannot be changed yet; language and
  time zone saved on the account and applied to shown times), **Password** (current and new password, 12 or more
  characters, Argon2id, other sessions signed out unless you opt out, rate-limited), **Authenticator app** (replace it
  with a QR code, confirmed with the first code before the old secret goes; new backup codes shown once; it can never be
  switched off), **Passkeys** (WebAuthn with user verification required: add, rename, remove, last used; a passkey signs
  in without a password and code and also counts as a second factor, on the sign-in page, the second step and the
  "Confirm it is you" dialog) and **Sessions** (browser and system, address, signed in, last active; sign out one or all
  others). Passkeys use better-auth's `@better-auth/passkey` 1.7.10 with `@simplewebauthn` (MIT); relying party ID and
  origin come from `PUBLIC_URL` only. The Content Security Policy is unchanged.
- Lost second factor: `node apps/api/src/cli.ts reset-second-factor <email> [--yes]` in the API container removes the
  authenticator app and all passkeys of one account and ends its sessions; the password stays and the next sign-in
  leads to a new setup. Audited, not reachable over the network, never offered in the web UI.
- Audit log: filter "Account" and new actions `account.profile_changed`, `account.password_changed`,
  `account.totp_replace_started`, `account.totp_replaced`, `account.backup_codes_regenerated`,
  `account.passkey_registered`, `account.passkey_renamed`, `account.passkey_removed`,
  `account.passkey_removal_refused`, `account.session_revoked`, `account.sessions_revoked`,
  `account.second_factor_reset`, `auth.passkey_sign_in` and `auth.endpoint_refused`, in English and German.
- Migration 0016 (additive: table `passkey`, columns `user.locale` and `user.time_zone`). API: `/api/v1/account`
  (overview, profile, preferences, password, authenticator replacement, backup codes, passkeys, sessions); `/api/v1/me`
  also returns `user.locale` and `user.timeZone`. New dependencies: `@better-auth/passkey` 1.7.10,
  `@simplewebauthn/server` 13.3.3 (through it), `@simplewebauthn/browser` 13.3.0, `@better-auth/utils` 0.5.0 (all MIT;
  see `docs/COMPONENTS.md`).
- Form rows with several fields (`FormRow`, `FormField`): labels, controls and hints line up across the row and the
  fields stack below the width of their card, in Settings, the dialogs and the account page.
- XDR page for your own Wazuh 4.x or 5.x (Infrastructure → XDR, ADR 0015, `docs/xdr.md`),
  shown only once a connection exists: alerts by severity for 24 hours, 7 and 30 days with the
  change against the period before, MITRE ATT&CK tactics, the ten busiest agents, the latest file
  integrity events (paths as plain text), vulnerability counts per agent, a sortable and
  filterable agents table with more columns on wide screens, and a link to your Wazuh dashboard.
  Adapters `wazuh4` and `wazuh5` are chosen by the detected version; 5.x is marked **preview**.
  A worker sync runs every 15 minutes and on demand. GarnetOps only reads: it builds no agent
  and no SIEM, and Wazuh (GPL-2.0) stays a separate program.
- Settings → XDR / Wazuh (owners and admins, with a recent sign-in, audited): the manager API
  (port 55000) and the indexer (port 9200), each with its own read-only user whose password is
  sealed in the vault. Each endpoint is trusted by a **pinned certificate** (read without
  credentials, confirmed by an admin; a changed certificate blocks the sync) or by your own
  **certificate authority**. If a user can do more than read, the sync waits until an admin
  acknowledges it.
- Wazuh agents on Servers: every agent is a read-only row (Servers → Wazuh), can be added as a
  server (`source: "wazuh"`) or linked to an existing server after a suggestion (same address,
  name or short host name) that an admin confirms and that is audited.
- Agent enrollment helper (XDR page, and "Monitor with Wazuh instead" when adding a server): the
  official Wazuh install commands for Debian, RHEL, SUSE, Windows and macOS with your manager
  address, group and name, strictly validated and quoted; a password only as a placeholder.
- "Summarise with AI" on the XDR page (only with AI switched on): the model gets numbers only,
  the answer is labelled **AI suggestion**, rendered without HTML and audited.
- Migration 0014 (additive: `wazuh_connection`, `wazuh_endpoint`, `wazuh_agent`, `wazuh_snapshot`,
  `wazuh_fim_event`, `wazuh_source_ip`, `wazuh_sync_run`, `wazuh_summary`; secret purposes
  `wazuh-api-password` and `wazuh-indexer-password`; queues `xdr.certificate`, `xdr.sync`,
  `xdr.sync-tick`, `xdr.summary`). API: `/api/v1/xdr`; `POST /api/v1/hosts` accepts
  `source: "wazuh"` with `sourceRef`. New audit actions `xdr.*` and an audit filter "XDR".
  Source addresses of alerts are collected (top 100 per period) for a later attack overview. No
  new dependency. Not yet run against a real Wazuh installation.
- Attack overview (Infrastructure → Attacks, ADR 0016, `docs/attacks.md`), listed only while a Wazuh
  connection exists: where failed logins and attacks come from, for 24 hours, 7 and 30 days. Key
  figures with the change against the period before (attack alerts, source addresses, countries, the
  most targeted machines), a **world map** (Natural Earth, public domain; plain SVG shipped with the
  app, no tiles, no map library) filled on a single-hue scale, complete **countries, networks and
  machines lists** as its table alternative, and a sortable, filterable, searchable address table with
  cursor pagination, more columns on wide screens, first and last seen, the machines attacked (linked
  to Servers or XDR) and rule groups. Addresses are plain text with a copy button; private and
  reserved addresses are labelled "Internal" and never looked up.
- **Local GeoIP from DB-IP Lite** (IP to Country Lite and IP to ASN Lite, CC BY 4.0, never bundled;
  attribution on the page): **manual import** of the `.csv.gz` files in Settings → Attack overview
  (streamed, size-capped, validated line by line, replaces the data only when the whole file is valid,
  the last good data stays, release month recorded; owners and admins, recent sign-in, audited) and an
  **opt-in monthly download** by the worker from `download.db-ip.com` (off by default, the exact
  addresses shown, public addresses only, no redirects, size and time limits).
- **Optional reputation lookup** (off by default; AbuseIPDB with your own API key, sealed in the vault
  and opened only by the worker): an explicit warning that public source addresses leave the network,
  two confirmations, a recent sign-in, at most the top N addresses per sync within a daily budget below
  the provider's free tier, results cached 24 hours, only public addresses. Built as a provider
  interface; AbuseIPDB's terms could not be confirmed, so the confirmation is the customer's.
- Retention of source addresses (default 90 days, 1 to 365, configurable): only the latest aggregate
  of each period is kept, an hourly job deletes older rows, and "Delete stored addresses now" erases
  them at once.
- "Summarise with AI" on the Attacks page (only with AI switched on): numbers per country code and AS
  number, never an address, name or organisation; the answer is labelled **AI suggestion**.
- Migration 0015 (additive: `geoip_dataset`, `geoip_country_range`, `geoip_asn_range`,
  `attack_settings`, `attack_osint_result`, `attack_summary`, `wazuh_attack_window`, three columns on
  `wazuh_source_ip`; secret purpose `osint-api-key`; queues `attacks.summary` and `attacks.maintenance`).
  API: `/api/v1/attacks` (`/overview`, `/sources`, `/settings`, `PUT /geoip/{country|asn}`, `/data`,
  `/summary`). New audit actions `attacks.*` and an audit filter "Attacks". The Wazuh sync asks the
  indexer for a few more fixed aggregations. No new dependency.
- Fix proposals and fix pull requests (Code → Fix proposals, ADR 0014, `docs/fix-prs.md`): for
  every open finding with a fixed version, one proposal per package and manifest with the
  lowest version that fixes all its open vulnerabilities (a **major upgrade** is marked),
  severity, vulnerabilities fixed, ecosystem, file and direct or transitive. Transitive and
  unsupported cases say why they are left to you. Sortable, filterable, searchable, extra
  columns and a detail pane on wide screens, a labelled read-only AI suggestion, the pull
  request status, and a history of all pull requests. The version always comes from the
  vulnerability data, never from the AI.
- **Create PR** (members and above, with a recent sign-in; rate limited; audited): the worker
  creates the branch `garnetops/fix-<package>-<version>` through the forge's REST API, changes
  **one version string** in the manifest (npm `package.json`, Python `requirements*.txt`,
  Composer, Go `go.mod`, Cargo; formatting, comments and line endings untouched), and opens a
  pull request with a fixed text. Nothing is cloned or executed, lockfiles are not edited (the
  pull request says so), nothing is merged, approved or pushed to the default branch. A manifest
  that changed since the scan is refused. GitHub (including Enterprise Server), Gitea and Forgejo.
- Write access is an **opt-in per repository** by owners and admins with a recent sign-in (repository
  page, "Fix pull requests"): a separate write token, stored encrypted and opened only by the
  worker, never the read credential. The page shows off or on, by whom and since when, the check
  of the token, and a warning for tokens broader than one repository. Turning it off deletes the
  token. Pull request status (open, merged, closed, failed with a safe reason) is refreshed every 15
  minutes and on demand.
- Renovate configuration: a button on the repository page generates a `renovate.json` (vulnerability
  alerts on, a rule per vulnerable package with the proposed version) for teams that run their own
  Renovate. GarnetOps never runs or bundles Renovate.
- Scans record the dependency manifests of the scanned commit (migration 0013, additive:
  `repository_manifest`, `repository_write_access`, `fix_pr`; secret purpose `forge-write-token`;
  queues `fix-pr.create`, `fix-pr.check`, `fix-pr.refresh`). Repositories scanned before this version
  need one scan before their proposals can be applied. New audit actions `fix_pr.*` and an audit
  filter "Fix PRs". API: `/api/v1/fixes`, `/fixes/prs`, `/fixes/refresh`,
  `/repositories/:id/write-access`, `/repositories/:id/renovate-config`. No new dependency.
- AI triage with your own model (Settings → AI and a panel in every finding, ADR 0013,
  `docs/ai.md`): connect vLLM, Ollama, LiteLLM, LM Studio or anything that speaks the
  OpenAI API. Open a finding and press **Ask AI**: the first answer is a structured triage
  (exploitable, reachable, confidence, summary, recommendation, an upgrade hint and
  references taken from your vulnerability data), then you ask follow-up questions. Answers
  stream as they are written, with Stop, Regenerate, Copy and "What the model saw". From the
  xwide layout step the conversation is a third pane beside list and details; below it, a
  drawer. The conversation belongs to the finding and is shared by the organisation; **Take
  over as note** keeps a suggestion on the finding (author: the person, audited). Off until an
  owner or admin switches it on; "Load models" and "Test connection" included.
- Everything the model writes is an **AI suggestion**: it never changes a severity, a state, a
  gate result or a setting. Markdown is rendered without any HTML path (text is escaped, only
  `http(s)` links, each shown with its host). The model receives metadata of the finding in a
  delimited data block, never credentials, user data, clone URLs or source code.
- Endpoint rules: plain http only works for a model on the same host or Docker network as the
  worker (an address inside a subnet of the worker's own network interfaces, for example a
  Compose service) and inside a VPN overlay (100.64.0.0/10, NetBird and Tailscale); other
  addresses on your network (RFC 1918, IPv6 unique local) need https, because cleartext on a LAN
  exposes the vulnerability list to anyone who can sniff or spoof traffic (error "insecure-private").
  An address outside the network needs https and a per-host confirmation and shows a permanent
  warning; loopback, link-local (cloud metadata), unspecified and multicast addresses are always
  refused. The worker decides on every connection from its own interfaces.
- Limits: 12 requests a minute per person, 40 per organisation, answers at the same time per
  organisation (default 2), question, input and output budgets. Command search finds
  Settings, AI; the audit log has an AI filter (`ai.request` records finding and model, never
  the prompt).
- API: `/api/v1/ai/…` (settings, probes, per-finding thread, triage, questions, stop,
  regenerate, "what the model saw", accept as note, `GET /ai/threads/:id/stream` as
  server-sent events) and `GET /api/v1/findings/:id/notes`.
- Migration 0012 (additive): `ai_settings`, `chat_thread` and `chat_message` (unused until now)
  gain columns and a unique index per finding; new tables `ai_probe` and `finding_note`; queues
  `ai.generate` and `ai.probe`. No new dependency.
- Proxmox VE (Infrastructure → Servers → Proxmox and Settings → Proxmox, ADR 0012,
  `docs/proxmox.md`): connect clusters with a **read-only API token** and see every node,
  virtual machine and container with status, CPU, memory, disk, uptime, OS type, tags, HA
  state, last backup, snapshots, addresses and the node's own pending updates, plus storage.
  Stale guests (stopped for more than 30 days, no backup in 7 days, a snapshot older than 30
  days) and untracked guests (running, no linked server) are flagged. The guest list is
  sortable, filterable by flag, type, status, node, cluster and text, with extra columns on wide
  screens and a detail dialog. **Add as server** opens the usual add-server wizard prefilled
  from the guest and links the new server to it (agentless SSH; nothing is ever run through
  Proxmox). Syncs run every 15 minutes and on request. The settings dialog shows exactly how to
  create the token (a dedicated user, role `PVEAuditor`, privilege separation on, `pveum`
  commands). Command search finds guests; the audit log has a Proxmox filter.
- Migration 0011 (additive): tables `proxmox_cluster`, `proxmox_node`, `proxmox_guest`,
  `proxmox_storage`, `proxmox_sync_run`; secret purpose `proxmox-token`. `POST /api/v1/hosts` accepts
  `source: "proxmox"` and `sourceRef` (`<cluster id>:<vmid>`); servers show the guest they were
  created from.
- Servers (Infrastructure → Servers, ADR 0011, `docs/servers.md`): agentless, read-only
  inventory over SSH. The list shows system, vulnerabilities per severity, pending updates,
  last inventory and status, sortable and searchable, with extra columns on wide screens; a
  server's page has its facts, vulnerabilities (CVSS, EPSS, known exploited, fixed in),
  packages (with the update that is available and whether it is a security update) and the
  inventory history. Inventories run nightly with the repository scans and on demand, and
  are matched against the same local vulnerability database as repositories. A server that
  could not be checked (unknown operating system, no database) is never shown as clean.
- Host setup script ("install via script"): "Add server" is a four-step wizard (address and
  allowed source address, the script, the host key, the first inventory). The script creates
  the account `garnetops`, installs a read-only wrapper and one `authorized_keys` line
  (`restrict,from=…,command=…`, both owned by root), prints the server's host key
  fingerprints, is idempotent and has `--uninstall`. Copy it, download it, or use a one-line
  installer that verifies a SHA-256 before it runs anything (one-time link, 60 minutes,
  stored as a hash, rate limited, audited).
- Host keys are pinned on first contact (`ssh-keyscan`, the admin confirms the fingerprint);
  a changed key stops the server until an admin confirms the new fingerprint.
- CSV import of servers (address, name, port; 500 rows, checked per row, duplicates skipped).
- One SSH access key per organisation, generated by the worker and sealed in the vault
  (purpose `host-ssh-key`); only its public half is stored in clear.
- Command search finds servers; the audit log has a Servers filter.
- Migration 0010 (additive): tables `host`, `host_package`, `host_finding`,
  `host_inventory_run`, `host_access_key`, `host_setup_link`.
- Notifications (Settings → Notifications, ADR 0010, `docs/notifications.md`): webhooks in
  Discord, Slack-compatible (Slack, Mattermost, Rocket.Chat) and generic JSON format, and
  mail via SMTP or Microsoft Graph, for new critical or known exploited vulnerabilities,
  blocked gates and failed scans, with a test button and the last delivery's result.
  Messages hold a summary and a link only. Credentials are sealed in the vault; webhooks go
  over HTTPS only and never to loopback, link-local or metadata addresses.
- Migration 0009 (additive): tables `notification_channel`, `notification_delivery`.
- New dependency: nodemailer (MIT-0) in the worker; MIT-0 joins the allowed licences.
- An "Alpha" badge next to the wordmark in the sidebar, with a short explanation on hover.
- The version is 0.0.1, the first alpha. The sidebar and Settings → About show it as
  "0.0.1 Alpha" (every 0.x release is an alpha) instead of "Development build"; builds
  without a version argument report 0.0.1.
- Team (Admin → Team, ADR 0009): owners and admins invite people by email and role. The
  invitation is a link that works once and for 7 days (shown once, stored as a hash,
  revocable); e-mail delivery follows with the mail module. The invited person sets a
  name and password and must set up a second factor at the first sign-in. Owners manage
  every role, admins only members and viewers; the last owner is protected. Removing
  someone ends their access and every session at once and keeps the account for the
  audit trail. Inviting, changing roles and removing need a sign-in from the last ten
  minutes. Everything is in the audit log (filter Team).
- Migration 0008 (additive): table `invitation`.
- Quality gates (ADR 0008, `docs/quality-gates.md`): rules for critical and high
  vulnerabilities with a fix, known exploited vulnerabilities and denied licences, each
  Off, Report or Block. **Every rule starts as Report or Off; nothing blocks until an admin
  sets it to Block.** Every scan gets a gate result (Passed, With notes, Blocked), shown on
  the new Quality gates page, as a column in the repositories list and on the overview.
- Gate API for CI: per-repository gate tokens (shown once, stored as a hash, revocable,
  audited, rate-limited) request a check of a pull request's exact commit
  (`POST /api/v1/gate/checks`, `GET /api/v1/gate/checks/{id}`) and get the result with rule
  names and counts only. Checks of other refs never change the repository's findings. A
  ready-to-copy pipeline step for Forgejo, Gitea and GitHub Actions.
- Migration 0007 (additive): tables `gate_rule`, `gate_token`, `gate_run`; scans gain `ref`
  and `expected_sha`.
- Sortable columns in the findings, repositories and packages lists: the first click
  sorts in the column's natural order, the second reverses it, the third returns to the
  default; the order is in the URL and page-by-page loading keeps every row exactly once
  (`sort` and `dir` on the list endpoints).
- Quick search (Ctrl K) shows matching repositories, vulnerabilities and packages as you
  type (`GET /api/v1/search`).
- Overview as in the mockup: an Activity feed (repositories added or removed, risks
  accepted or reopened, nightly scans, updates; visible to every member, without sign-ins
  or IP addresses), "Fix available" per severity on the critical and high tiles, the
  advisory sources behind your findings, and the two- and four-column layouts.
- Repositories list as in the mockup: the whole row opens the repository, a "…" menu
  holds Scan now, Deploy key and Remove, open findings as tinted counts, and from the
  xwide step the scanners of the last scan and a 14-day trend line.
- Findings as in the mockup: Scan now in the header (the filtered repository or all),
  rows open the detail, the detail starts with a short title, the CVSS/EPSS/Fixed in
  strip and the advisory text; accepting a risk opens a dialog. From the xwide step list
  and detail sit side by side with the first finding shown.
- README: the tools GarnetOps is built on. Roadmap: read-only Proxmox VE monitoring of
  nodes, VMs and LXC containers.
- Add several repositories at once: up to 50 `https://` addresses, one per line, with one
  branch and one token (`POST /api/v1/repositories/bulk`). Already connected ones are
  skipped and listed; each repository keeps its own encrypted copy of the token, so
  removing one never affects another.
- README: getting started from source, first sign-in with the setup token and the
  mandatory second factor, HTTPS-only operation behind a reverse proxy, and updating
  until signed images exist.
- Docker Compose stack (ADR 0007): `web` (Caddy with HTTPS, the web app and the
  maintenance page during updates), `api`, `worker`, `db` (PostgreSQL 17) and `init`
  (creates the vault key pair once). Images pinned by digest, app containers non-root
  with a read-only file system and no capabilities, an internal network without a route
  out; only the worker and the update service reach the outside. Installation guide in
  `docs/installation.md`, `deploy/install.sh` writes `.env` with random secrets.
- In-app updates (optional): with the cicd-updater sidecar (profile `updater`), owners
  and admins install signed releases from Settings → Updates: release notes, start now or
  later, live progress, cancel, the result to acknowledge, and a guide when an update
  needs attention. Scheduling asks for password and code when the sign-in is older than
  ten minutes. Everyone signed in sees a banner with a countdown and the progress; the
  page reloads once after a successful update. Every step is in the audit log (filter
  Updates), with who asked for it. Without the sidecar the page shows how to update by
  hand (`docs/updating.md`).
- Release workflow (`.github/workflows/release.yml`): builds and smoke-tests both images
  per architecture, including the upgrade from the previous release through the update
  sidecar, then signs images and `release.json` keyless and publishes the release. CI
  workflow for lint, types, unit tests, web build and a gitleaks scan.
- `GET /api/healthz`: readiness for health checks; the version only for the update
  sidecar's token. `GET /api/v1/system` returns the running version.
- Findings export as CSV, Excel (XLSX), PDF or text, with exactly the filters that are
  set, from the findings list and from each repository's page. Dates in the user's time
  zone, column names in the user's language. Cells from scanned data can never become
  spreadsheet formulas. Exports are audit-logged.
- Repository page (click a repository anywhere): open findings per severity, 30-day
  trend, scan history and patch history (which finding was fixed when, the version then
  and now, and how long it was open).
- Overview: 30-day trend chart of open findings by severity (the legend leads to the
  filtered findings), changes against last week, a notice while critical findings are
  open, accepted risks, the vulnerability database and scanner versions of the latest
  scan, "Scan all", refresh and the time of the last update.
- Findings and repositories show counts on their filter tabs; repositories show a
  source column (forge and access) and open findings per severity in columns.
- App shell as in the mockup: collapsible sidebar, breadcrumbs, search (Ctrl K) that
  opens findings, packages or repositories filtered by the text, light and dark theme
  (follows the system until chosen), account menu with language, theme and sign-out,
  open critical findings next to Findings, the running version in the sidebar.
- Settings with sections (Scanning, Updates, About) and short help beside the form.
  About shows the version, the licence and the link to the source of exactly this
  version (AGPL-3.0, section 13).
- The worker can keep the vulnerability database current by itself
  (`GARNETOPS_GRYPE_DB_UPDATE=auto`, daily); off by default.
- Package inventory: every scan builds an SBOM with syft, stores every
  package of the repository (name, version, type, licences, location) and
  lets grype match that same SBOM. New Packages page: search across all
  repositories by name or `name@version`, filter by repository or to packages
  with open findings, and jump to their findings.
- Scans record the real number of packages (it counted only the vulnerable
  ones before). Without syft configured (`GARNETOPS_SYFT_BIN`, optional) the
  worker scans the directory as before and leaves the count empty.
- Findings table: CVSS score, EPSS (probability of exploitation in the next
  30 days), publication date of the advisory and the date it was detected in
  the repository; the detail pane adds the last change of the advisory.
  Publication dates come from the local vulnerability database (the earliest
  of the advisory and the CVEs it aliases) and appear after the next scan.
- SSH repositories with a deploy key generated by GarnetOps (Ed25519): the
  dialog shows the public key to add to the forge as a read-only deploy key,
  and the first scan starts when the user says so. The private key is sealed
  in the vault at once and never shown. Each repository row opens its public
  key and the pinned server host key fingerprint.
- Server host keys are pinned on the first SSH contact (trust on first use)
  and required on every later scan; a changed key fails the scan with a clear
  message. Owners and admins can forget a pinned key (audit-logged with the
  old fingerprints).
- Settings page: switch the nightly scan on or off and set its time and time
  zone (owners and admins; others see it read-only), with the recent nightly
  runs. Zones the database does not know are refused.
- Audit log page for owners and admins: who did what and when, filterable by
  sign-in, repositories, findings and settings, paginated.
- Sign-in events are audit-logged: password step, second factor, backup code,
  start of second-factor setup, sign-out, and refused attempts to switch the
  second factor off; failed attempts included, passwords and codes never.
- Nightly scans: every repository is scanned once a night at 04:00 in the
  organisation's time zone, taken from the owner's browser at setup (UTC for
  organisations created before). Exactly one run per local date, also on the
  nights the clock changes, and with several workers; a scheduled time inside
  the skipped spring hour is caught up. The repositories page shows the
  schedule. After an upgrade the first run of the day starts with the next
  tick if its time has already passed.
- End-to-end scan tests with the real scanner: grype and the local
  vulnerability database scan recorded fixture repositories (vulnerable and
  fixed npm projects), covering new, resolved, reopened and expired-acceptance
  findings, clone failures and the take-over of scans whose worker died.
- Unit tests for the clone hardening (allowed transports, no hooks, symlinks,
  submodules or redirects, token never in arguments, helper scoped to the
  repository's origin) and for safe clone error messages.
- Signed-in app shell with navigation (Overview, Findings, Repositories).
- Overview: key figures for critical and high open findings, known exploited,
  fix available and repositories with critical findings; every figure links
  to the matching filtered list. "Fix first" list and recent scans.
- Repositories: list with latest scan state and open findings per severity,
  filters in the URL, add over HTTPS (optional read-only token), scan now,
  remove (admins).
- Findings: filters for state, severity, repository, known exploited, fix
  available and text, all kept in the URL; cursor pagination with 25/50/100
  per page; detail pane beside the list on wide screens; accept a risk with
  reason and expiry, reopen.
- Form controls (checkboxes, radio buttons, dropdowns) share the look of the
  text inputs in light and dark mode; filter controls keep their position
  when filters are set or cleared.
- Web app (`apps/web`): first-run setup, sign-in, mandatory TOTP enrolment
  with locally rendered QR code and one-time backup codes, second sign-in
  step with authenticator or backup code, and a minimal signed-in shell.
  English and German (`packages/i18n`, ICU messages), following the system
  colour scheme. English is the default for everyone; German is an explicit
  choice in the language picker (remembered in the browser), never taken
  from the browser's language setting.
- End-to-end tests (Playwright) for the whole sign-in flow against the
  production build, plus layout checks at 1920×1080, 1536×864 and 1280×720.
- Monorepo scaffold (pnpm workspaces): `apps/api` (Hono, better-auth),
  `apps/worker` (pg-boss consumer), `packages/core`, `packages/db` (Drizzle
  schema and first migration); `pnpm dev` runs everything locally on an
  embedded PostgreSQL without Docker.
- First-run setup: the first organisation and owner can only be created with a
  one-time setup token printed by the API on start.
- API v1: repositories (manual add over HTTPS, optional token), scans,
  findings with filters, accept-risk with reason and expiry, reopen, and an
  overview endpoint; cursor pagination with page sizes 25/50/100 and errors as
  RFC 9457 problem details.
- Worker: hardened shallow clone, grype scan against the local vulnerability
  database, deduplicated findings that resolve and reopen across scans.
- `scripts/fetch-scanners.mjs`: downloads pinned grype builds and checks
  their SHA-256 checksums.
- ADR 0003 (technology stack) and ADR 0004 (SSH key vault, NetBird, firewall
  monitoring).
- ADR 0005 (time and time zones).
- `LICENSE` (proprietary), `README.md`, `.gitignore`, `.gitattributes`,
  `.editorconfig`.
- ADR 0001 (separate, proprietary product) and ADR 0002 (host connectivity and
  Wazuh XDR integration).

- Project charter and contributor rules in `AGENTS.md`, imported by `CLAUDE.md`.
- `ROADMAP.md` with phases from foundations to hosted offering.
- `CHANGELOG.md` (this file).
- `docs/COMPONENTS.md`: register of every library, tool, dataset, font and
  service with version, license, source URL, status and attribution.
- Requirements: multi-user with organizations and roles, mail delivery via
  SMTP or Microsoft Graph, better-auth with mandatory second factor (passkey or
  TOTP), sign-in via OIDC/OAuth and LDAP with allowed-domain registration,
  per-user forge connections with repository listing, and manual repository add.
- `AGENTS.md` rule 6: visual language follows Restow; wide-screen layout rules
  with container-query breakpoints (base, wide, xwide).
- Visual mockup `mockup.html` covering overview, findings with streamed AI
  triage, repositories, quality gates, fix proposals, servers, live attack
  globe and settings.
- Sign in with **LDAP and Active Directory** (ADR 0020, `docs/ldap.md`). Owners set it up under **Settings → Sign-in**:
  servers (`ldaps://`, or `ldap://` upgraded with StartTLS before anything is sent; plain LDAP does not exist),
  certificate trust (certificate store, own CA, or the pinned SHA-256 of the server certificate confirmed on first
  contact like Proxmox), a read-only service account (its password sealed in the vault, readable only by the worker),
  search base and user filter, mail/name/unique-ID attributes, presets for Active Directory and OpenLDAP, group modes
  (`memberOf`, Active Directory nested groups through the matching rule `1.2.840.113556.1.4.1941`, or a search filter
  for `groupOfNames`/`posixGroup`) and **allowed groups with a role each** (highest role wins; owners are never set by
  the directory). A **connection test** shows every server, whether each group exists, and for a user name the entry,
  mail, unique ID, matched groups and the role the person would get, never a password. Untested settings never go
  live: switching on needs a successful test with a person, and a change to how the directory is reached switches it
  off. The sign-in page offers **Directory account** (user name and password); a person in none of the allowed groups
  gets no account and the same message as for a wrong password. Accounts are linked by the directory's immutable unique
  ID, never by mail address; an existing local account with the same address is refused with an entry for the
  administrators and linked only explicitly by an owner on the Team page. The mandatory second factor is unchanged
  (enrolment at the first sign-in without a password prompt, then code or passkey). Roles are re-read at every sign-in
  and by a check every 15 minutes, which also ends the sessions of someone who left every allowed group, is deleted
  or no longer matches the user filter (nothing changes while the directory cannot be asked). Directory accounts have
  no local password, their role is read-only on the Team page ("Set by the directory groups") and the Team page has a
  Source column (Local, Directory). Migration 0018 (additive: `ldap_config`, `directory_identity`,
  `directory_request`). API (additive): `GET/PUT /api/v1/directory`, `POST /api/v1/directory/{test,lookup,link}`,
  `POST /api/v1/directory/certificates/{scan,confirm}`, public `GET /api/v1/sign-in-options`, `source` on
  `GET /api/v1/team/members`, `profile.source` and `profile.loginName` on `GET /api/v1/account`, and the better-auth
  endpoints `POST /api/auth/sign-in/username` and `GET /api/auth/directory/me`. New audit actions `auth.directory_sign_in`
  and `directory.*` (filter "Directory"). New dependency in the worker: ldapts 9.2.0 (MIT). In English and German.

### Fixed

- Signing out loads the sign-in page at once, without error messages from requests that were still
  running. When a session ends elsewhere (expiry, another tab, signed out from the account page
  or by an admin), the next request leads to the sign-in page with a short notice instead of
  showing errors in place.
- Settings → Scanning: the time and the time zone of the nightly scan sit on one line (the time field no longer drops
  below the zone's hint). The same shared form row fixes the side-by-side fields of notifications (SMTP), AI, updates,
  XDR, attack overview, the Wazuh enrollment helper and the add-server dialog.
- Settings at narrow widths: the help column no longer runs past the right edge. The sections, the form and the help
  follow the width of the content area: a row of sections above the form and the help below it when narrow, sections on
  the left from 48 rem, all three side by side from 1450 px.
- The sidebar footer ("Local only" and the version) no longer wraps onto two lines: the expanded sidebar is 15 % wider
  (a single `--sidebar-width` token) and the version shortens with an ellipsis if it must.
- Pages no longer wait forever or show an empty table when the server cannot be
  reached: every list and page shows loading and error states with a retry, and an
  action that failed says so. The error page reconnects by itself, for example after an
  update restarted the API.
- Removing a repository and forgetting a pinned host key ask in the app's own dialog
  instead of the browser's unstyled one.
- Scan errors are shown in the chosen language, also for scans that ran before.
- The repository table no longer runs out of its card at 1280×720 (150 % scaling);
  a layout test now checks every card on every screen.
- Audit log entries name their details in words, and the removal of a pinned host key
  is labelled.

- Accepted risks now last through the whole chosen day in the user's time
  zone; before, they ended at midnight UTC (01:00 or 02:00 in Berlin) and the
  date picker could offer the wrong day shortly after midnight.
- The open-findings trend counts the viewer's calendar days, including the
  23- and 25-hour days of a daylight-saving change, instead of days in the
  database server's zone.
- "Yesterday" and similar relative times count calendar days, so a 23-hour
  day is still "yesterday".
- The scan worker uses the database clock to start scans and to detect stuck
  ones, so a worker with a wrong or jumping clock cannot take over a running
  scan early or leave a dead one hanging.
- Database sessions always run in UTC, and SQL dates are no longer shifted to
  the server's local midnight when read.

### Changed

- The sign-in page offers "Sign in with a passkey", the second step "Use a passkey instead", and "Confirm it is you"
  "Confirm with a passkey" once an account has one. The step-up text is no longer specific to updates.
- A fresh sign-in (second factor, backup code, passkey) now ends the session it was started from, so the list of
  sessions does not fill up with leftovers of "Confirm it is you".
- Update guides and the Updates page put today's way first: until the first release,
  images are built from the repository; `docker compose pull` and in-app updates apply
  only to signed releases.
- Visual details follow the mockup: badges, dialogs with a separated action row, cards,
  hover on table rows, search fields with an icon, warning banner.
- API and worker run their TypeScript sources directly with Node.js 24 (type stripping)
  in production; `erasableSyntaxOnly` keeps the code compatible.
- Sign-out, language and theme moved into the account menu behind the avatar.

- License: GarnetOps is now dual-licensed under AGPL-3.0-only and a
  commercial license (ADR 0006); added `LICENSING.md`, `TRADEMARKS.md`,
  `SECURITY.md` and `CONTRIBUTING.md`.
- `pnpm dev` reuses a development PostgreSQL that is still running, stops
  whole process trees on exit (on Windows, API, worker and Vite used to keep
  running), reloads API and worker when shared packages change, and explains
  a busy port instead of crashing. New `pnpm dev:stop` stops everything an
  earlier run left behind, touching only processes of this repository; it
  shuts PostgreSQL down gracefully first and removes a lock file left by a
  crash (a lock file alone is not trusted: its PID may belong to another
  program by now).
- Repository lists show the most recent scan in any state (queued, running,
  failed), not only the last successful one.
- Node.js 24.7 or newer is required (was 22), see the amendment in ADR 0003.
- Roadmap reordered: repository monitoring first, then AI
  triage, servers and XDR; cross-cutting UX rules (every tile links to its
  filtered view, cursor pagination everywhere).
- Product name: GarnetOps.
- Moved planning into its own git repository;
  mockup now lives in `design/mockup/`.
- Product is proprietary with pricing on request; English is the primary
  language for product and materials (ADR 0001).
- Mockup uses its own burgundy palette (v1) instead of Restow's blue; critical
  severity moved to a brighter vermilion so it never looks like the brand colour.
- Mockup switched to English; new XDR page (Wazuh) under Infrastructure;
  "Add server" dialog showing the agentless SSH flow (restricted key, host key
  confirmation); neutral placeholder mark instead of Restow's logo.
- Hosts connect agentlessly over restricted SSH by default; Wazuh 4.x and 5.x
  are integrated read-only via manager and indexer APIs as the XDR page
  (ADR 0002).
- Mockup rebuilt on Restow's design tokens, Inter Tight and IBM Plex Mono, and
  shadcn/ui new-york patterns; removed gradients, glow, emoji and greeting copy.
- Mockup uses wide screens: six key figures in one row, three-pane findings
  view, extra table columns and side panels from 1900 px content width
  (1440p and up); verified at 1280×720, 1920×1080 and 2560×1440.
- Security rule 1 extended: "We never compromise security."
- Positioning: separate product from Restow with its own name, visual identity,
  logo and login; modules (quality gates, update checks, host monitoring)
  available in every edition; perpetual paid licenses with renewable feature
  updates and free security fixes; agentless host scan first, Wazuh only as an
  optional API integration.

### Security

- **External exposure is built so that it cannot quietly become a scanner against third parties** (ADR 0023): assets must be public
  names or addresses and every resolved address is checked again before a connection (a mixed answer means no connection at all); stage 2
  needs a proof of control, a per-asset acknowledgement written to the audit log, a fixed port list, fixed rate and concurrency limits and
  a once-a-day limit enforced in the worker, API and schedule; the proof is re-checked daily and before each run and a lost proof stops the
  run between two ports; the code never writes to a port except the TLS handshake (pinned by tests that record every byte); banners,
  headers, certificate names and DNS answers are hostile text, cleaned, cut and shown as text only; the Certificate Transparency
  lookup is opt-in with step-up and acknowledgement.
- UniFi integration (ADR 0022): read-only by construction (a client that can only send allow-listed `GET` requests and, for the
  optional preview, the console's login and logout); the API key and the IPS password are sealed and opened by the worker only;
  the console's certificate is pinned and checked before the first byte of any request, so neither is sent to a console that
  presents another certificate; resolve-check-connect SSRF rules; hostile JSON and attacker-written signatures are cleaned, cut,
  stored and shown as plain text and never sent to a model; clients are a number only. Ubiquiti's API key cannot be narrowed to
  read-only, which the documentation and the dialog state; the preview's user must be view-only and administrator names are refused and rights
  beyond viewing block the preview until acknowledged.
- Live attack feed (ADR 0021): read-only and outbound only (we poll, nothing calls us), one fixed query template whose only
  inputs are a time we parsed ourselves and an integer rule level between fixed bounds, so no alert text ever reaches a
  query; at most 50 alerts and 1 MiB per request, eight fields and never the log line, source port or user name tried;
  polling only while the connection is healthy (confirmed, unchanged certificates, acknowledged privileges), with a pin
  check before the first byte, back-off on errors and an atomic lease against double polling. Alert descriptions and
  agent names are attacker-influenced: cleaned, cut, stored and shown as plain text, never a link, never HTML, never sent
  to a model. Events are source addresses (personal data): the newest 500 per connection, deleted after the attack
  overview's retention period and by "Delete stored addresses now". The browser stream is session-authenticated,
  scoped to the organisation by channel and by query, limited to four per person, ten minutes long, and carries no
  content in the database notices.
- Directory sign-in (ADR 0020): the web-facing API never holds the service account's password or a key for it, only
  the worker opens it, and a typed password lives sealed in one row for about a second and is deleted by the worker
  the moment it takes the request. LDAP injection: user names are limited to a safe character set and escaped per
  RFC 4515 into the filter; exactly one result below the search base counts; the bind DN comes from the directory.
  An empty password is refused in the API and again in the worker (no unauthenticated bind); anonymous binds never
  happen. TLS 1.2+ or StartTLS always, trust decided before the first LDAP byte (store, own CA or pinned leaf), a
  changed pinned certificate refused, audited and announced; the server address goes through the SSRF policy. Failed
  attempts are limited below typical directory lock-outs (3 per name and 20 per address in 15 minutes, only failures
  counted, no directory contact once limited; the service account is paused 10 minutes after a refusal); every refusal
  looks the same and takes at least one second; typed names are never written to the audit log. A directory sign-in
  cannot skip the second factor (the two-factor plugin handles its endpoint). Owners are local accounts and cannot be
  made or linked by a group. A failed periodic check or a directory outage changes nobody.
- Personal notifications (ADR 0019): every query names the signed-in person and organisation, so nobody reads another
  person's or organisation's notifications; the NOTIFY payload carries no content (a stream reads its own rows); role
  decides first who is told, and a stored choice can never widen it; notifications hold no free text and no scanned
  content, parameters are sanitised and shown as text, links must be paths inside the app (checked on write and again
  in the browser); personal mail goes to the person's own sign-in address only, never to a channel's recipient list,
  at most one per event type every 15 minutes, summary and link only; at most four event streams per person, ten
  minutes each, 500 notifications and 90 days per person.
- Development dependencies: Vitest 3.2.7 to 4.1.12 (GHSA-82fw-gwwq-j7x9, GHSA-qxg6-89mg-rqv8, GHSA-xp26-3454-mjgp; it no longer pulls in tinypool 1.1.1 with its
  two critical advisories), and the old esbuild 0.18.20 (GHSA-67mh-4wv8-2f99) that drizzle-kit 0.31 reaches through
  the deprecated `@esbuild-kit` loader is replaced by esbuild 0.25.12 with a scoped pnpm override; no esbuild below
  0.25 remains in the lockfile. None of these packages is part of the shipped images. The recorded test repositories
  in `apps/worker/test/fixtures/` keep their manifests as `package.json.fixture` and `package-lock.json.fixture`, so
  scanners and dependency bots no longer mistake the deliberately vulnerable lodash and minimist for real dependencies
  of the product; the tests copy them under their real names into a temporary directory.
- Accounts (ADR 0017): changing the password, replacing the authenticator app, renewing backup codes, adding or
  removing a passkey need a sign-in from the last ten minutes (and the password again for the authenticator app and
  the password change); the last second factor can never be removed (checked in one database transaction, so two requests
  cannot race it to zero); passkeys count only with **user verification**, which better-auth's plugin does not enforce
  itself (it verifies with `requireUserVerification: false` and asks for "preferred"), so GarnetOps checks the signed
  flag for registration and every sign-in; relying party and origin come from `PUBLIC_URL`, never from a request
  header. better-auth's own endpoints for the same changes (`/change-password`, `/update-user`, session revocation,
  `/two-factor/get-totp-uri`, `/two-factor/generate-backup-codes`, passkey rename, delete and list) are closed and
  answer 403, so nothing goes around the step-up and the audit log; `/change-password` with "sign out everywhere" would
  also have created a session without a second factor. Recovery of a lost second factor is an operator command with
  shell access only, audited.
- The attack overview (ADR 0016) keeps data local by default: location comes from tables on your server;
  the monthly download and the reputation lookup are off, need a recent sign-in to switch on, and are
  audited. GeoIP files are treated as hostile (compressed and inflated size caps counted while
  streaming, 1 KiB lines, validated sorted ranges, one transaction, the last good data survives).
  Outbound calls go to fixed hosts, accept only public addresses, verify TLS, follow no redirects and
  cap size and time. The reputation API key is sealed in the vault and never shown, logged or audited;
  only public addresses are sent. The AI summary sees numbers only. Source addresses are replaced at every
  sync and deleted after a configurable retention period.

- Wazuh integration (ADR 0015) is read-only by construction: both HTTP clients check a method
  and path allow-list before a connection is opened (manager: `GET /`, the agent list with a
  fixed field list, the user's own policies, and the login `POST`; indexer: `GET` of the version
  and the user's own roles, `POST` of `_search` and `_count` on two indices with fixed query
  templates whose only input is a period). Agent keys are never requested. The login token stays
  in the memory of the worker. Passwords are sealed by the API and opened only by the worker. A
  certificate is pinned on first contact (read without credentials), a changed certificate
  blocks the sync, a custom authority is accepted only as certificates without a key. Addresses
  are resolved and checked, the checked address is used, redirects are not followed, and size,
  count and time are limited. Everything Wazuh sends is treated as hostile: validated with a
  schema, cleaned of control and direction-changing characters, shown as text, never as a link or
  HTML. The AI summary sees numbers only.
- Fix pull requests use a **separate write token per repository** (never the read credential),
  sealed in the vault and opened only by the worker; its use is limited to reading the repository,
  creating one branch, changing one file and opening a pull request. The token goes only to the
  stored https API address (private addresses allowed; loopback, link-local and metadata refused;
  resolved address checked and used; no redirects; TLS verification always on; size and time
  limits; error bodies never read). Pull request text puts values from scanned data inside code
  spans that cannot be closed, uses no advisory text and keeps mentions inert. The manifest editor
  is a strict text scanner with refusals instead of guesses and is fuzz-tested.
- AI triage (ADR 0013): only the worker opens the model's API key and makes the calls; the
  API stores messages, queues jobs and relays progress (PostgreSQL LISTEN/NOTIFY, server-sent
  events). The endpoint address is checked when saved and again on every connection (resolve,
  check every answer, connect to the checked address, no redirects, TLS verified, size and time
  limits); loopback, link-local, metadata, unspecified and multicast addresses are refused in
  every notation, a public address needs https and an audited per-host confirmation.
- Model output is untrusted: parsed into a small validated shape (unknown fields dropped,
  references limited to your own vulnerability data, the upgrade hint version-shaped), cleaned
  of control and invisible characters, rendered without HTML, and unable to change a finding,
  a gate or a setting (tested with an injection in advisory text and a model that obeys it).
- Proxmox VE integration is read-only by construction: the HTTP client sends `GET` only, to a
  fixed list of paths, refuses anything else before it connects, follows no redirects, caps every
  answer at 8 MiB and runs one request at a time. Descriptions and cloud-init data of guests are
  never read.
- The Proxmox API certificate is pinned on first contact: the worker reads the leaf certificate
  without sending the token, an admin confirms its SHA-256 fingerprint (step-up, audited), and
  every later request verifies exactly that certificate before any byte of the request is written;
  a different certificate blocks the sync until an admin confirms it. Hosts are resolved by the
  worker, checked against loopback, link-local, metadata and multicast addresses, and the checked
  address is the address it connects to.
- The API token secret is sealed in the vault (purpose `proxmox-token`); only the worker opens
  it. Tokens of `root` are refused. A token with privileges beyond `*.Audit` blocks the sync and
  shows a warning until an admin acknowledges exactly those privileges.
- Servers are read with one SSH key per organisation that can run only a read-only wrapper
  (`restrict`, `from=<allowed source>`, `command=`; wrapper and `authorized_keys` owned by
  root), never as a shell. Host keys are pinned after an admin confirmed the fingerprint and
  checked strictly on every connection; a change blocks the server. Everything a server
  prints is hostile input: parsed with strict per-field patterns, bounded (60 seconds,
  16 MiB, 20 000 packages), never executed and never shown in an error message. Addresses
  are validated (no ssh options, no loopback, link-local or metadata addresses, no numeric
  host name tricks) and checked again after the worker resolved them. Adding, importing and
  removing servers and confirming host keys need a recent sign-in; the setup download link is
  single use, hashed and audited.

- The update sidecar's token reaches only the API (read-only), never the worker or the
  browser; the API alone decides who may update (owners and admins, recent sign-in) and
  the sidecar installs only releases signed by our release workflow, by digest.
- The web edge sends a strict Content Security Policy, HSTS and no server header; TLS
  1.3 prefers the hybrid post-quantum key exchange X25519MLKEM768.
- The vault's private key is mounted into the worker only; the API gets the public half.

- SSH clones ignore user and system ssh configuration, use no agent, no
  forwarding and no password prompts, accept only the repository's own deploy
  key and the pinned host key, and prefer hybrid post-quantum key exchange
  (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) with only classical
  fallbacks accepted by BSI TR-02102-4; SHA-1 key exchanges are never offered.
  The decrypted key exists on disk (mode 0600) only while git runs.
- The second factor cannot be switched off by the user, and "trust this
  device" is refused, so every sign-in asks for it.
- The web app's production build runs under a strict Content Security Policy
  without inline scripts or styles; fonts and icons are bundled, no third
  party is contacted.
- Secrets vault with envelope encryption: the API can only seal secrets with
  the vault public key, only the worker holds the private key (ADR 0004).
  Data keys are wrapped with a hybrid post-quantum scheme (X25519 and
  ML-KEM-1024), so stored secrets resist "store now, decrypt later".
- Passwords are hashed with Argon2id (64 MiB, 3 passes, 4 lanes) instead of
  better-auth's scrypt default.
- TOTP lockout after repeated wrong codes: the two-factor table now has the
  columns better-auth needs for it (migration 0001).
- Mandatory second factor (TOTP) on every API route, open sign-up disabled,
  rate limits stored in the database, same-origin check against CSRF, strict
  security headers, telemetry of better-auth disabled.
- Repository clones ignore user and system git config, allow only https and
  ssh, run no hooks or submodules, refuse HTTP redirects and offer the token
  only to the repository's own origin.
- All mockup assets (fonts, icons, scripts, map data) are self-hosted in
  `vendor/` with their license files; no CDN or font service is contacted.
- Renovate (AGPL-3.0) excluded from the product; Semgrep Registry rules
  excluded because their license forbids competing products.

[Unreleased]: https://github.com/lcsfls/garnet-ops/compare/v0.0.11...HEAD
[0.0.11]: https://github.com/lcsfls/garnet-ops/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/lcsfls/garnet-ops/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/lcsfls/garnet-ops/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/lcsfls/garnet-ops/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/lcsfls/garnet-ops/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/lcsfls/garnet-ops/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/lcsfls/garnet-ops/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/lcsfls/garnet-ops/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/lcsfls/garnet-ops/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/lcsfls/garnet-ops/releases/tag/v0.0.2
