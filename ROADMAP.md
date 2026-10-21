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
- [ ] Passkeys (WebAuthn with user verification) as a second factor
- [ ] Recovery for a lost second factor (admin reset via CLI, audit-logged)
- [~] Audit log: sign-in events (failed ones included), setup, repository,
      finding and settings changes; read-only view for owners and admins,
      ordered by sequence number. Still open: tamper-evident hash chain
      (ADR 0005), export
- [x] Roles in practice: invitations, member management, role changes (all
      audit-logged), step-up for team changes (ADR 0009). Still open: invitation mail
      (with the mail module), SSO and LDAP sign-in
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
- [~] Scan scheduling: on demand and nightly done (per organisation, local
      time in an explicit zone, one run per local date, DST-tested, ADR 0005),
      settings screen to change it. Still open: scans on push via webhook
      (Forgejo, GitHub) with signature verification
- [x] Quality gate API for CI (token per repository), rules in report-only
      mode by default, status check on the pull request (the pipeline step) (ADR 0008).
      Still open: per-repository rule overrides, secret and SAST rules (Phase 5)
- [ ] Per-user forge connections (OAuth app / GitHub App) with repository
      listing and import
- [ ] Local vulnerability database: vunnel + grype-db build job, offline import
- [x] Docker Compose stack, non-root containers, pinned digests, health checks;
      reverse proxy with hybrid post-quantum TLS key exchange (X25519MLKEM768) (ADR 0007)
- [~] In-app updates with the cicd-updater sidecar: signed releases, backup first,
      step-up sign-in, banner, journal in the audit log (ADR 0007). Still open: the first
      signed release (v0.1.0), branch and tag protection, a published sidecar image
- [~] Upgrade test harness: the release smoke test upgrades from the previous release
      through the sidecar; a real 0.1.0 to 0.1.1 update was run by hand (ADR 0007)

## Phase 2: AI triage

Goal: every finding can be discussed with the customer's own model, safely.

- [ ] OpenAI-compatible endpoint configuration with connection test; warning
      when the endpoint is outside private networks
- [ ] Triage chat per finding, streamed via SSE: persistent threads, markdown
      rendering without raw HTML, code blocks with copy, stop and regenerate,
      suggested follow-up questions, token and latency display, retry on
      disconnect (resume by event ID)
- [ ] Context builder: finding, package path, affected code excerpt (limited,
      secrets removed), CVE text, CVEfixes examples; shown to the user as
      "what the model saw"
- [ ] Prompt-injection defenses: untrusted content clearly delimited, model
      output never executed or rendered as HTML, no tool calls from model output
- [ ] Structured triage result (reachable yes/no/unknown, confidence, fix
      suggestion) stored separately from the chat and always labelled as AI
- [ ] Fix pull requests: separate write credential, human review always
- [ ] Version-bump PRs (own implementation; Renovate is AGPL-3.0)

## Phase 3: Servers

See ADR 0002 and ADR 0004.

- [ ] SSH key vault: Ed25519 keys generated by the worker, private key never
      leaves the platform, sealed at rest, rotation with verification
- [ ] Host setup assistant: user, restricted `authorized_keys` line, wrapper
      script with checksum, optional sudoers drop-in, host key confirmation
- [ ] NetBird integration: list peers via the management API, add servers from
      that list, connect only via NetBird addresses
- [ ] Inventory: OS, packages (dpkg, rpm, apk), pending updates, matched
      against the local vulnerability database
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
- [ ] CSV import, jump hosts
- [ ] Proxmox VE: connect a cluster with a read-only API token (role `PVEAuditor`,
      privilege separation on, token secret sealed in the vault) and list every
      node, VM and LXC container with status, resources, uptime, OS type, backups
      and snapshots age, HA state and the node's own pending updates; the API is
      read only, nothing is started, stopped or changed. Guests become servers
      with one click (agentless SSH inventory as above; never `pct exec` or
      other root access on the node); stale or untracked guests are flagged. Pinned TLS fingerprint of
      the Proxmox API on first contact, like SSH host keys
- [ ] Post-quantum SSH key exchange (`mlkem768x25519-sha256`): check support
      in the ssh2 library, otherwise document the gap

## Phase 4: XDR (Wazuh)

- [ ] XDR page backed by a customer-run Wazuh, read-only via manager and
      indexer APIs; adapters `wazuh4` and `wazuh5` (preview until 5.0 GA)
- [ ] Alerts, MITRE ATT&CK tactics, file integrity, agents; AI summaries
- [ ] Read Wazuh's package inventory and vulnerability states into the same
      host inventory and watch list as agentless hosts
- [ ] Attack overview: local GeoIP (DB-IP Lite), optional OSINT enrichment

## Phase 5: Breadth, teams and distribution

- [ ] Container image scanning, IaC and secret scanning, SAST (resale-safe rules)
- [ ] Mail via SMTP or Microsoft Graph; alerts and weekly digest, never sent
      twice or skipped around a clock change (ADR 0005)
- [ ] SSO (OIDC/OAuth) and LDAP with allowed-domain registration
- [ ] Multi-tenant mode for MSPs, fine-grained permissions
- [ ] Compliance reports (NIS2, ISO 27001 mapping)
- [ ] Signed releases, published SBOM, hosted offering

## Open questions

- Minimum hardware for the local model; behaviour without a GPU
- Whether an identity provider's own MFA (`amr`/`acr` claim) may ever replace
  our second factor; default is no
