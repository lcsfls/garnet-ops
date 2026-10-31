# Roadmap

This roadmap describes intent, not promises. Phases are ordered; items inside
a phase are roughly ordered by priority. Every item is subject to the
non-negotiables in `AGENTS.md` (security first, never break user space, clean
licensing, English only, 1080p baseline).

Order set on 2026-10-19: repository monitoring and analysis first, AI triage
next, then servers and XDR. **Changed on 2026-10-28 (ADR 0025): GarnetOps is a
pure developer pipeline. The infrastructure phases (servers, Proxmox VE, UniFi,
Wazuh/XDR, attack overview, external exposure) were removed in 0.0.4. The last
version that has them is the tag `v0.0.3`. External exposure is back in 0.0.12 as the
module "Website monitoring", off by default (ADR 0033).**

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
- [x] Host connectivity and Wazuh approach (ADR 0002; removed in 0.0.4, ADR 0025)
- [x] Technology stack (ADR 0003)
- [x] Secrets vault (ADR 0004; its server, NetBird and firewall parts were removed in 0.0.4, ADR 0025)
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
      done. syft and grype run in a scanner service of their own: no network,
      no vault key, no database, clones read-only, CPU/memory/process limits
      (ADR 0028, 0.0.9). Still open: SBOM download (CycloneDX/SPDX)
- [x] Scanner binaries: pinned versions, checksum-verified download
- [x] Findings: deduplicated per repository, package and vulnerability;
      states open / accepted (with reason and expiry) / resolved; filters in
      the URL; cursor pagination
- [x] Overview: key figures, "fix first" list, recent scans; every tile links
      to its filtered view
- [x] Overview: 30-day trend chart, changes against last week, vulnerability data card
- [x] Statistics page: found, resolved, time to fix, gate results, fix pull requests and failed scans over
      30, 90 or 365 days in the viewer's calendar days; rankings of today's open findings (`docs/statistics.md`)
- [x] Repository page: trend, scan history and patch history per repository
- [x] Findings export (CSV, XLSX, PDF, text) with the active filters, per repository
- [~] Grades A to F per repository, display only: Grade column, reason note with a link to the findings,
      sorting and filter, detail pages (ADR 0018, `docs/grades.md`). Still open: a grade distribution on the overview
- [~] Scan scheduling: on demand and nightly done (per organisation, local
      time in an explicit zone, one run per local date, DST-tested, ADR 0005),
      settings screen to change it. Still open: scans on push via webhook
      (Forgejo, GitHub) with signature verification
- [x] Quality gate API for CI (token per repository), rules in report-only
      mode by default, status check on the pull request (the pipeline step) (ADR 0008).
      Still open: per-repository rule overrides, secret and SAST rules (Phase 5)
- [x] Per-user forge connections with a personal read token, repository picker, private
      repositories until shared (ADR 0030, 0.0.11); sign-in with a GitHub App (device flow) or a
      Gitea/Forgejo OAuth2 application with PKCE instead of a pasted token (ADR 0031, 0.0.12)
- [x] Inactive repositories: set aside what is not used or maintained, out of nightly scans, early warnings and the
      organisation's views, history kept (ADR 0043)
- [x] Hosts and containers with a host agent, a module off by default (ADR 0034, `docs/hosts.md`, 0.0.12): running containers,
      the packages and vulnerabilities of their images, the link to the repository they were built from, optional check for newer
      images in public registries. Hosts without Docker: a small Go agent as a systemd service reports the host's kernel and
      packages (ADR 0037). Still open: Kubernetes, private registries, notifications about running images, language packages
      outside the distribution's package manager
- [x] Website monitoring as a module, off by default (ADR 0023, ADR 0033, `docs/websites.md`, 0.0.12): certificates, DNS, mail
      authentication and security headers from the outside; proof of control by DNS TXT record or file; port checks only for proven
      names with a confirmation per name; switched on and off under Settings, Modules; DNSSEC checked at the source (ADR 0036);
      optional public DNS next to a slow local resolver (ADR 0035); software versions (PHP, nginx, Apache, WordPress and other CMS)
      judged against end-of-life data (ADR 0038); availability every 1 to 60 minutes with outages and slow answers (ADR 0040).
      WordPress themes and plugins from the home page's asset addresses, judged against wordpress.org (opt-in, ADR 0042).
      Advisories from the Wordfence feed with the organisation's own key, and a GarnetOps WordPress plugin for exact versions
      (ADR 0042)
- [x] Pull request overview: open pull requests of the monitored repositories with the gate result of their head commit,
      read with the repository's read credential, "Check now" as a CI check would (ADR 0032, `docs/pull-requests.md`,
      0.0.12). Still open: review comments on the pull request
- [ ] Local vulnerability database: vunnel + grype-db build job, offline import. Planned and shown as such on the
      System status page, whose report shape (per provider: last run, result, records, duration) the builder will fill
      (ADR 0024)
- [x] System status page (Admin): scanner versions against the pinned ones, vulnerability database age and update with
      limits (amber after 3 days, vermilion after 7), the directory, AI endpoint and notification channels (last success and
      blocker), worker heartbeat, queues, nightly scan, database and app version; read-only (ADR 0024, `docs/system-status.md`). Still
      open: notifications when something stops, history
- [x] Early warnings: after each update of the vulnerability database, the stored package inventories are
      matched again without a clone; new advisories for stored packages are listed until a scan confirms or
      clears them, and channels can be told (ADR 0029, `docs/early-warnings.md`, 0.0.10); for hosts and containers
      (new advisories for what runs, distributions near or past their end) and websites (release lines ending within 90 days,
      ADR 0041)
- [x] Docker Compose stack, non-root containers, pinned digests, health checks;
      reverse proxy with hybrid post-quantum TLS key exchange (X25519MLKEM768) (ADR 0007)
- [~] In-app updates with the update sidecar (cicd-updater, maintained in `updater/`): signed
      releases, backup first, step-up sign-in, banner, journal in the audit log (ADR 0007, ADR 0026).
      The sidecar image is built, smoke-tested and signed with each release. Still open: the first
      release that publishes it, making its package public, branch and tag protection
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
      repositories, secrets removed, shown to the user as "what the
      model saw". Still open: an affected code excerpt (needs clones or a read path)
      and CVEfixes examples
- [x] Prompt-injection defenses: untrusted content clearly delimited, model
      output never executed or rendered as HTML, no tool calls from model output
- [x] Structured triage result (reachable yes/no/unknown, confidence, fix
      suggestion) stored separately from the chat and always labelled as AI;
      a human can take it over as a note
- [~] Fix pull requests: done: a separate write credential per repository (sealed, opened only by
      the worker), opt-in by owners and admins with step-up, human review always: nothing is
      merged, approved or pushed to the default branch (ADR 0014, `docs/fix-prs.md`); or in the
      requester's own name through their connected account, opt-in per connection (ADR 0039). Still open:
      AI-written code changes as pull requests (today only version bumps), tested against real
      GitHub, Gitea and Forgejo installations (fake forges with recorded request shapes only)
- [~] Version-bump PRs (own implementation; Renovate is AGPL-3.0): Fix proposals page, branch and
      one-line manifest edit through the forge API for npm, Python requirements, Composer, Go and
      Cargo on GitHub, Gitea and Forgejo, status refresh, and a `renovate.json` generator for
      teams that run their own Renovate (ADR 0014). Still open: lockfiles (need a package
      manager), workspaces, Maven/Gradle/Poetry/Pipfile/Bundler/NuGet, Dockerfile base images,
      webhooks

## Phase 3: Servers (removed)

Removed in 0.0.4 (ADR 0025); see "Removed in 0.0.4" below.

## Phase 4: XDR (removed)

Removed in 0.0.4 (ADR 0025); see "Removed in 0.0.4" below.

## Removed in 0.0.4 (ADR 0025)

The maintainer narrowed the product to a developer pipeline: security for Git repositories across Forgejo, Gitea and GitHub, self-hosted.
Everything about infrastructure was removed from the product, with its data. It stays available in the git history and in the tag
`v0.0.3`. Nothing below is planned any more. A relaunch on Svelte and Go is planned and will get its own ADR.

What was removed, and the items that were open when it was:

- Servers (ADR 0002, 0004, 0011): the agentless SSH inventory, the host setup script, host keys, server findings and grades, CSV import.
  Open at the time: SSH key rotation, NetBird integration, Linux firewall monitoring, inventory search across hosts, end-of-life flags,
  a watch list for announced vulnerabilities, matching for third-party package repositories, jump hosts, post-quantum SSH key exchange.
- Proxmox VE (ADR 0012): read-only nodes, VMs and containers.
- UniFi (ADR 0022): network devices and the IPS preview.
- Wazuh / XDR (ADR 0002, 0015): the XDR page, alerts, MITRE tactics, file integrity, the agent enrollment helper.
- Attack overview (ADR 0016, 0021): world map, globe, live feed, local GeoIP (DB-IP), the optional AbuseIPDB lookup, the attack AI summary.
- External exposure (ADR 0023): public assets, proof of control, stage 1 and 2, Certificate Transparency suggestions. **Back in 0.0.12 as
  the module "Website monitoring"** (ADR 0033, below); only the location data (GeoIP) stays removed.

## Phase 5: Breadth, teams and distribution

- [ ] Container image scanning, IaC and secret scanning, SAST (resale-safe rules)
- [~] Mail via SMTP or Microsoft Graph and webhooks (Discord, Slack-compatible, JSON) for
      alerts (ADR 0010); per-channel minimum severity and repositories, Discord embeds (0.0.10). Still open: weekly digest, never sent twice or skipped around a
      clock change (ADR 0005); invitation mail
- [~] In-app notifications: bell, toasts and a per-person matrix with personal mail (ADR 0019,
      `docs/notifications.md`). Still open: quiet hours, a page with all notifications, "update available",
      cutting an open stream when a session is revoked
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
