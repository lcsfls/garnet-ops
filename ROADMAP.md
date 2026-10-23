# Roadmap

This roadmap describes intent, not promises. Phases are ordered; items inside
a phase are roughly ordered by priority. Every item is subject to the
non-negotiables in `AGENTS.md` (security first, never break user space, clean
licensing, English only, 1080p baseline).

Order set on 2026-10-19: **repository monitoring and
analysis first, AI triage next, then servers (SSH key vault, NetBird,
firewalls), XDR after that.**

Status markers: `[ ]` open, `[~]` in progress, `[x]` done.

## UX requirements that apply to every phase

- **Every tile leads somewhere.** Each key figure, chart segment, badge and
  list entry links to the view that explains it, with the matching filter
  already applied (e.g. "Critical open: 2" opens Findings filtered to open
  critical findings). Filters live in the URL so links can be shared and the
  browser back button works.
- **Clean pagination** on every list: server-side, cursor-based (stable under
  inserts), page size selectable (25/50/100), total count shown, keyboard
  navigable, position kept in the URL.
- **Triage chat** is a first-class feature, not an add-on (Phase 2).
- Calm UI, full-width data views, wide-screen panes (rule 5 and 6).

## Phase 0: Foundations

- [x] `AGENTS.md`, `CLAUDE.md`, `ROADMAP.md`, `CHANGELOG.md`, local git repository
- [x] Visual mockup (`design/mockup/mockup.html`)
- [x] Separate product next to Restow (ADR 0001); AGPL-3.0 plus commercial license (ADR 0006)
- [x] Product name **GarnetOps** (garnetops.com reserved)
- [x] Host connectivity and Wazuh approach (ADR 0002)
- [x] Technology stack (ADR 0003)
- [x] SSH key vault, NetBird, firewall monitoring (ADR 0004)
- [x] Time and time zones (ADR 0005): UTC storage, explicit user zones, one
      clock for deadlines, DST tests
- [x] Components and license register `docs/COMPONENTS.md`
- [ ] Trademark search at DPMA and EUIPO (classes 9 and 42); secure .eu/.io/.de
- [~] Brand identity: burgundy palette v1 and garnet mark draft in the mockup;
      still to do: contrast token tests, final logo and wordmark
- [ ] Edition and maintenance model, legal check against the EU Cyber
      Resilience Act before the first paid release
- [~] Hosting: public GitHub repository `lcsfls/garnet-ops`, AGPL-3.0 plus
      a commercial license (ADR 0006). Still open: branch protection, signed
      commits, the CLA text, legal review
- [ ] Verify every `to verify` entry in `docs/COMPONENTS.md`
- [ ] Threat model v1 (STRIDE), including prompt injection from scanned
      repositories and compromised scanner sandboxes
- [~] CI: lint, typecheck, unit tests, web build and gitleaks on every change; SBOM
      per release (release workflow). Still open: license check, e2e in CI
- [ ] Check every cryptographic parameter against BSI TR-02102-1 (including
      the hybrid post-quantum vault) before the first release

## Phase 1: Repository monitoring and analysis

Goal: an admin signs in with a second factor, links repositories, sees real,
paginated findings, and every number on the overview leads to its details.

- [x] Monorepo scaffold (apps/api, apps/web, apps/worker, packages/db,
      packages/core, packages/i18n), development database without Docker
- [x] Auth: better-auth, local accounts, Argon2id, mandatory TOTP, first-run
      setup creates the first admin, open sign-up disabled; web screens with
      end-to-end tests
- [x] Passkeys (WebAuthn with user verification) as a second factor and sign-in method: add, rename, remove
      (never the last factor), sign-in page, second step and step-up (ADR 0017, `docs/account.md`)
- [x] Account page: profile, language and time zone, password, replacing the authenticator app, backup codes,
      sessions (ADR 0017). Still open: changing the email address
- [x] Recovery for a lost second factor (operator CLI in the API container, audit-logged; never in the web UI)
- [~] Audit log: sign-in events (failed ones included), setup, repository,
      finding and settings changes; read-only view for owners and admins,
      ordered by sequence number. Still open: tamper-evident hash chain
      (ADR 0005), export
- [x] Roles in practice: invitations, member management, role changes (all
      audit-logged), step-up for team changes (ADR 0009). Directory accounts take their role from
      their groups (ADR 0020). Still open: invitation mail (with the mail module), OIDC/OAuth sign-in
- [~] Secrets vault: envelope encryption with hybrid post-quantum key
      wrapping (X25519 + ML-KEM-1024, ADR 0004), used for forge tokens;
      key rotation open
- [~] Repositories: manual add over HTTPS with optional token, and over SSH
      with a generated Ed25519 deploy key and host key pinning on first
      contact (API and web). Still open: a connection test before the first
      scan, deploy key rotation, entering an expected host key fingerprint
      up front instead of trusting the first contact
- [~] Worker: hardened shallow clone into a temporary directory, grype scan
      against the local database, findings stored, resolved and reopened,
      clean up; tested end to end with the real scanner on recorded fixtures.
      SBOM with syft and package inventory per repository (Packages page)
      done. Still open: SBOM download (CycloneDX/SPDX) and the
      container sandbox (non-root, read-only, no network, CPU/memory limits)
      that comes with the Compose stack
- [x] Scanner binaries: pinned versions, checksum-verified download
- [x] Findings: deduplicated per repository, package and vulnerability;
      states open / accepted (with reason and expiry) / resolved; filters in
      the URL; cursor pagination
- [x] Overview: key figures, "fix first" list, recent scans; every tile links
      to its filtered view
- [x] Overview: 30-day trend chart, changes against last week, vulnerability data card
- [x] Repository page: trend, scan history and patch history per repository
- [x] Findings export (CSV, XLSX, PDF, text) with the active filters, per repository
- [~] Grades A to F per repository and server, display only: Grade column, reason note with a link to the findings,
      sorting and filter, detail pages (ADR 0018, `docs/grades.md`). Still open: a grade distribution on the overview
- [~] Scan scheduling: on demand and nightly done (per organisation, local
      time in an explicit zone, one run per local date, DST-tested, ADR 0005),
      settings screen to change it. Still open: scans on push via webhook
      (Forgejo, GitHub) with signature verification
- [x] Quality gate API for CI (token per repository), rules in report-only
      mode by default, status check on the pull request (the pipeline step) (ADR 0008).
      Still open: per-repository rule overrides, secret and SAST rules (Phase 5)
- [ ] Per-user forge connections (OAuth app / GitHub App) with repository
      listing and import
- [ ] Local vulnerability database: vunnel + grype-db build job, offline import. Planned and shown as such on the
      System status page, whose report shape (per provider: last run, result, records, duration) the builder will fill
      (ADR 0024)
- [x] System status page (Admin): scanner versions against the pinned ones, vulnerability database age and update with
      limits (amber after 3 days, vermilion after 7), GeoIP, every integration's last success and blocker, worker
      heartbeat, queues, nightly scan, database and app version; read-only (ADR 0024, `docs/system-status.md`). Still
      open: notifications when something stops, history
- [x] Docker Compose stack, non-root containers, pinned digests, health checks;
      reverse proxy with hybrid post-quantum TLS key exchange (X25519MLKEM768) (ADR 0007)
- [~] In-app updates with the cicd-updater sidecar: signed releases, backup first,
      step-up sign-in, banner, journal in the audit log (ADR 0007). Still open: the first
      signed release (v0.0.3), branch and tag protection, a published sidecar image
- [~] Upgrade test harness: the release smoke test upgrades from the previous release
      through the sidecar; a real 0.0.3 to 0.0.4 update was run by hand (ADR 0007)

## Phase 2: AI triage

Goal: every finding can be discussed with the customer's own model, safely.

- [x] OpenAI-compatible endpoint configuration with connection test; warning
      when the endpoint is outside private networks (ADR 0013, `docs/ai.md`)
- [~] Triage chat per finding, streamed via SSE: persistent threads, markdown
      rendering without raw HTML, code blocks with copy, stop and regenerate,
      token and latency display, resume after a dropped connection (the stored
      text is sent first). Still open: suggested follow-up questions
- [~] Context builder: finding, package path, CVE text and counts of other
      repositories and servers, secrets removed, shown to the user as "what the
      model saw". Still open: an affected code excerpt (needs clones or a read path)
      and CVEfixes examples
- [x] Prompt-injection defenses: untrusted content clearly delimited, model
      output never executed or rendered as HTML, no tool calls from model output
- [x] Structured triage result (reachable yes/no/unknown, confidence, fix
      suggestion) stored separately from the chat and always labelled as AI;
      a human can take it over as a note
- [~] Fix pull requests: done: a separate write credential per repository (sealed, opened only by
      the worker), opt-in by owners and admins with step-up, human review always: nothing is
      merged, approved or pushed to the default branch (ADR 0014, `docs/fix-prs.md`). Still open:
      AI-written code changes as pull requests (today only version bumps), tested against real
      GitHub, Gitea and Forgejo installations (fake forges with recorded request shapes only)
- [~] Version-bump PRs (own implementation; Renovate is AGPL-3.0): Fix proposals page, branch and
      one-line manifest edit through the forge API for npm, Python requirements, Composer, Go and
      Cargo on GitHub, Gitea and Forgejo, status refresh, and a `renovate.json` generator for
      teams that run their own Renovate (ADR 0014). Still open: lockfiles (need a package
      manager), workspaces, Maven/Gradle/Poetry/Pipfile/Bundler/NuGet, Dockerfile base images,
      webhooks, per-user forge connections

## Phase 3: Servers

See ADR 0002 and ADR 0004.

- [~] SSH key vault: Ed25519 keys generated by the worker, private key never
      leaves the platform, sealed at rest (ADR 0011). Still open: rotation with
      verification (the schema has the `retired` state), one key per server group
- [~] Host setup assistant: user, restricted `authorized_keys` line, wrapper
      script with checksum, host key confirmation: a setup script to copy, download or
      fetch with a one-line installer that verifies a SHA-256, with a one-time link
      (ADR 0011). Still open: optional sudoers drop-in (firewall monitoring)
- [ ] NetBird integration: list peers via the management API, add servers from
      that list, connect only via NetBird addresses
- [x] Inventory: OS, packages (dpkg, rpm, apk), pending updates, matched
      against the local vulnerability database (ADR 0011); nightly and on demand. Quality of the
      matching for third-party repositories is a separate item below
- [ ] Linux firewall monitoring: nftables, iptables, ufw, firewalld; snapshots,
      drift with diff, risky states, listening ports versus exposure, approved
      baseline
- [ ] Inventory search across all hosts and sources (agentless SSH and Wazuh
      agents): "where does PHP run, which version, from which source
      (distribution, Ondřej Surý, Remi, container image)"; usable before any CVE
      is published, e.g. to plan a maintenance window for an announced fix
- [ ] End-of-life flags for runtimes and distributions (e.g. PHP 8.1, Debian 11)
      from openly licensed data; EOL hosts sort first
- [ ] Watch list for announced vulnerabilities without CVE yet: an admin enters
      product, severity and release time; GarnetOps lists the affected hosts and
      repositories at once and reports when fixed packages are available
- [ ] Reliable matching for third-party package repositories (Surý, Remi), whose
      versions do not follow the distribution's security data; tested with
      recorded fixtures
- [~] CSV import (done, ADR 0011), jump hosts (open)
- [~] Proxmox VE (ADR 0012, `docs/proxmox.md`): done: connect a cluster with a read-only API
      token (role `PVEAuditor`, privilege separation on, secret sealed in the vault), pinned TLS
      certificate on first contact, warning for a token that can do more than read; list every
      node, VM and LXC container with status, resources, uptime, OS type, tags, HA state, backups
      and snapshot age, addresses and the node's own pending updates; stale and untracked guests
      flagged; guests become servers with one click (agentless SSH; never `pct exec` or other
      root access on the node). Open: configurable thresholds, notifications for stale or
      untracked guests, public-key pinning for certificates that renew, Proxmox Backup Server,
      run against real Proxmox VE 8 and 9 installations (tested with recorded fixtures only)
- [~] UniFi (ADR 0022, `docs/unifi.md`): done: connect UniFi OS consoles and self-hosted Network Applications through
      the official local API with a key sealed in the vault (opened by the worker only), GET-only client with an allow-list,
      pinned TLS certificate on first contact, SSRF rules, sync every 15 minutes, sites, devices (state, firmware status,
      uptime) and the number of clients per site (no client data stored), tab Servers → Network devices, notifications for a
      changed certificate, an offline device (debounced) and a firmware update (once per version). **Preview, off by default:**
      IPS / threat events from the internal API with a separate view-only user (cookie session in worker memory, login and logout
      the only POSTs), joined to the attack overview, live stream and globe (dashed blue "Blocked by UniFi"). Open: run against
      real UniFi OS and Network application 9.x consoles (synthetic fixtures only; field names and the unofficial endpoints are
      assumptions), public-key pinning for renewing certificates, the v2 threat endpoints, per-port and Wi-Fi views.
      Done: UniFi counts (blocked and alerted per country and AS number) in the attack overview's AI summary
- [ ] Post-quantum SSH key exchange (`mlkem768x25519-sha256`): check support
      in the ssh2 library, otherwise document the gap

## Phase 4: XDR (Wazuh)

- [~] XDR page backed by a customer-run Wazuh, read-only via manager and
      indexer APIs; adapters `wazuh4` and `wazuh5` (preview until 5.0 GA) (ADR 0015,
      `docs/xdr.md`). Done: connection with two read-only users sealed in the vault, pinned
      certificate or own CA, method and path allow-lists, sync every 15 minutes, agents linked
      to servers, enrollment helper with the official install commands. Open: run against real
      Wazuh 4.x and 5.x installations (recorded synthetic fixtures only), the 5.x field names
      until 5.0 is generally available, more than one connection per organisation
- [~] Alerts, MITRE ATT&CK tactics, file integrity, agents; AI summaries. Done: counts by
      severity for 24 hours, 7 and 30 days with the change, tactics, busiest agents, latest file
      integrity events, vulnerability counts per agent, "Summarise with AI" on numbers only.
      Open: drill-down of single alerts in GarnetOps (the newest are listed, ADR 0021), notifications for Wazuh alerts
- [ ] Read Wazuh's package inventory and vulnerability states into the same
      host inventory and watch list as agentless hosts
- [~] External exposure (Infrastructure → Exposure; ADR 0023, `docs/exposure.md`): done: assets (domains, host names, single public
      addresses; public only; 200 per organisation), stage 1 from outside (DNS with SPF, DMARC and CAA, the TLS handshake with TLS 1.0 and
      1.1 acceptance, one `GET /` with the security headers and server banner, GeoIP and ASN from the local tables) with plain-rule
      findings and expiry warnings at 30, 14 and 7 days, proof of control by a DNS TXT record or a file (checked daily and before every
      run; a lost proof stops stage 2 at once), stage 2 light active checks (30 fixed ports, 4 at a time, 200 ms apart, once a day at
      most, banners only where a service speaks first; only for verified assets with an audited acknowledgement per asset), opt-in
      Certificate Transparency suggestions (crt.sh), four notification events, API, page, English and German. Pentesting is out of scope
      and not built. Open: run against the real internet and the real crt.sh (local servers, throw-away certificates and a fake
      resolver only), DNSSEC (the Node resolver interface hides it), SPF include chains, a second CT provider, a weekly digest of
      changes, export, IPv6 address ranges, a grade if a defensible definition appears
- [~] Attack overview (Infrastructure → Attacks; ADR 0016, `docs/attacks.md`): world map and tables of the
      aggregated source addresses from Wazuh with local GeoIP (DB-IP Lite country and ASN, CC BY 4.0: manual
      import and an opt-in monthly download, never bundled), internal addresses labelled, retention of source
      addresses (90 days by default), optional AbuseIPDB lookup with the customer's own key (off by default,
      provider interface), AI summary on numbers only. Open: tested with synthetic files and local test
      servers only, not with a real DB-IP file or the real AbuseIPDB service; AbuseIPDB's terms are not
      confirmed; a second OSINT provider; no history of attacks over time (by design)
- [~] Globe view and live attack feed (ADR 0021, `docs/attacks.md`): a globe with lines from the source countries to a
      home location the admin sets (no default), Globe | Map switch; a read-only poll of the Wazuh indexer every 30
      seconds (15 to 300, per connection) with one fixed query template, a bounded table (500 per connection, subject to
      the retention period), a stream to browsers over PostgreSQL NOTIFY, "Latest events" on Attacks and "Latest alerts" on
      XDR, and an honest status line. Open: run against a real Wazuh indexer (a local HTTPS test server with synthetic
      answers only), alerts that are indexed late can be missed, no history or drill-down of single events (by design)

## Phase 5: Breadth, teams and distribution

- [ ] Container image scanning, IaC and secret scanning, SAST (resale-safe rules)
- [~] Mail via SMTP or Microsoft Graph and webhooks (Discord, Slack-compatible, JSON) for
      alerts (ADR 0010). Still open: weekly digest, never sent twice or skipped around a
      clock change (ADR 0005); invitation mail
- [~] In-app notifications: bell, toasts and a per-person matrix with personal mail (ADR 0019,
      `docs/notifications.md`). Still open: quiet hours, a page with all notifications, "update available",
      notifications for new vulnerabilities on servers, cutting an open stream when a session is revoked
- [~] SSO (OIDC/OAuth) and LDAP with allowed-domain registration. LDAP and Active Directory sign-in done: owners'
      settings with a connection test, LDAPS or StartTLS with certificate store, own CA or pinned certificate, a sealed
      read-only service account (opened by the worker only), allowed groups with roles (nested groups for Active
      Directory), accounts linked by the directory's unique ID, explicit linking of existing accounts, mandatory
      second factor, roles re-read at sign-in and every 15 minutes, limits below directory lock-outs (ADR 0020,
      `docs/ldap.md`). Still open: OIDC/OAuth providers with allowed domains, tests against real Active Directory,
      OpenLDAP and FreeIPA (a fake LDAP server only), Kerberos/SASL, several directories, unlinking, an admin-triggered
      check
- [ ] Multi-tenant mode for MSPs, fine-grained permissions
- [ ] Compliance reports (NIS2, ISO 27001 mapping)
- [ ] Signed releases, published SBOM, hosted offering

## Open questions

- Minimum hardware for the local model; behaviour without a GPU
- Whether an identity provider's own MFA (`amr`/`acr` claim) may ever replace
  our second factor; default is no
