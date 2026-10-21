# Changelog

All notable changes to this product are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Security-relevant changes are listed under **Security** in every release.

## [Unreleased]

### Added

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

### Fixed

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
