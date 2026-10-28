# ADR 0025: Focus on the developer pipeline

- Status: accepted (2026-10-28)
- Date: 2026-10-28
- Decided by: maintainer (product focus: GarnetOps becomes a pure developer pipeline)
- Supersedes: ADR 0002, 0011, 0012, 0015, 0016, 0021, 0022 and 0023 completely; ADR 0004 (the server and firewall parts),
  ADR 0018 (the server grades), ADR 0019 and 0024 (the entries of the removed modules) in part
- Builds on: AGENTS.md rules 1 (security first), 2 (we never break user space) and 3 (clean third-party licensing)

## Context

GarnetOps grew in two directions. The first is the one the product started with: security for Git repositories (quality gates, dependency
and container update checks, findings, AI triage, fix pull requests). The second is infrastructure: a server inventory over SSH, Proxmox
VE, UniFi, a Wazuh XDR view, an attack overview with a globe and external exposure monitoring. The second direction is the larger half of
the code, and it has three costs:

- **Maintenance.** Every module talks to a foreign system (SSH hosts, Proxmox, UniFi consoles, Wazuh, the open internet) with its own
  certificate pinning, address policy, hostile-input parsers, fixtures and tests. Each of those systems changes on its own schedule.
- **Attack surface.** The modules store credentials of systems that are far more valuable than a read-only repository token: an SSH key
  that reaches servers, a Proxmox token, a UniFi API key, Wazuh passwords, and the source addresses of attackers (personal data).
  A product that is meant to hold only what a Git forge may read should not hold those.
- **Focus.** The people who use the repository half are developers and the sysadmins who run their pipelines. They do not need a globe.
  The infrastructure half pulled the product towards a SIEM and a monitoring tool, which AGENTS.md said from the start we do not build.

## Decision

### 1. GarnetOps is a developer pipeline

GarnetOps is security for Git repositories across Forgejo, Gitea and GitHub (and plain Git over SSH or HTTPS), self-hosted. What stays:
repositories and their per-user forge connections, dependency scanning (syft, grype), findings, packages, quality gates and the CI
check, fix proposals and fix pull requests, AI triage of findings, grades (for repositories), notifications (channels, bell, personal
preferences), team and invitations, account and passkeys, LDAP and Active Directory sign-in, in-app updates, the system status page and
the audit log. Every non-negotiable of AGENTS.md stays as it is.

### 2. What is removed

Removed completely, in code, user interface, API, worker, documentation and tests:

| Module | Decided in | What it was |
| --- | --- | --- |
| Servers | ADR 0002, 0004, 0011 | Agentless, read-only package inventory over SSH, the host setup script and its one-time links, host keys, server findings and grades, CSV import |
| Proxmox VE | ADR 0012 | Read-only view of nodes, VMs and containers |
| UniFi | ADR 0022 | Network devices and the IPS preview |
| Wazuh / XDR | ADR 0002, 0015 | The XDR page, the live feed, the agent enrollment helper |
| Attack overview | ADR 0016, 0021 | Globe and map, local GeoIP (DB-IP), the optional reputation lookup (AbuseIPDB), the attack AI summary |
| External exposure | ADR 0023 | Public assets, proof of control, stage 1 and 2, Certificate Transparency lookups |

The "Infrastructure" navigation group is gone with them. Three things were shared and are kept, moved to neutral modules:
`checkHostAddress` (the address policy for a host an admin types; the directory sign-in uses it) is now `packages/core/src/net-address.ts`;
the certificate fingerprint helpers the directory sign-in pins with are now `packages/core/src/certificates.ts`; and the repository SSH
deploy key and pinned host key code (`packages/core/src/ssh.ts`, `apps/worker/src/git.ts`) is untouched, because it clones
repositories.

### 3. What happens to the data (AGENTS.md rule 2)

AGENTS.md rule 2 says structures are removed only in a later major version. So:

- **No table, column or index is dropped.** The table definitions stay in `packages/db/src/schema.ts`, each marked
  `Removed in 0.0.4 (ADR 0025); data deleted; table dropped in 1.0.` `pnpm db:generate` reports no change. The tables are dropped in 1.0.
- **One additive migration, `0024_focus_developer_pipeline`, deletes the data** of the removed modules. This is a deliberate exception to
  "never lose data": the maintainer decided that the modules end, and keeping the data of a module that no code can read helps nobody.
  It deletes, in one transaction:
  - all rows of the 39 tables of the removed modules, including the stored source IP addresses, attack events and OSINT results (personal data);
  - every sealed secret whose purpose belongs only to a removed module: `host-ssh-key`, `proxmox-token`, `unifi-api-key`,
    `unifi-ips-password`, `wazuh-api-password`, `wazuh-indexer-password`, `osint-api-key` and the never-used `netbird-token`. Repository deploy
    keys, forge read and write tokens, the AI key, notification secrets and the LDAP secrets are not touched;
  - the personal notifications and the notification preferences of the removed event types.
  It also records one audit entry per organisation (`system.modules_removed`). A fresh installation has no organisation yet and gets none.
- **Audit log entries of the removed actions stay.** The audit page keeps their labels in a small legacy block (`audit.legacy` in the i18n
  files), so old entries stay readable. The filter lists only the groups that still exist; the legacy entries show under "All".
- **Job queues.** pg-boss keeps queues and schedules in the database. On start the worker removes the queues and schedules of the removed
  modules (`apps/worker/src/retired-queues.ts`), so nothing keeps sending jobs that nobody works on.
- **Secret purposes.** The values are removed from the code (`SecretPurpose`) because no code path needs them any more; the migration uses
  the literal strings.
- **Notification events.** `infra.certificate_changed` stays, because the directory sign-in uses it, and moves to the "Account and team"
  group of the preference matrix. The other infrastructure, UniFi and exposure events are gone.

Anyone who needs this data should save it while the version that has the modules is still running: use the export functions that
version offers, or take a database backup (the update service takes one before every update). Nothing of it can be recovered from an
updated installation except by restoring such a backup into a 0.0.3 installation.

### 4. How to get the old modules

The last version that has them is the tag **`v0.0.3`** (and its release images). The source stays in the git history. There is no plan to
bring the modules back into this product; a customer who needs them keeps running 0.0.3 on its own, with the knowledge that security fixes
for it follow the support rules of AGENTS.md only for the supported version lines.

### 5. What comes next

A relaunch on Svelte and Go is planned. It will get its own ADR; this one does not decide anything about it.

## Threat model

- **A smaller surface.** What an attacker can reach after this change is a subset of what they could reach before: five outbound
  integrations, an SSH key that reaches servers and a public-internet scanner are gone. No new endpoint, input or credential is added.
- **Leftover credentials.** The risk of this change is that a credential of a removed integration stays in the database, unused but
  stealable. The migration deletes every sealed secret of those purposes and a test (`packages/db/src/focus-migration.test.ts`) proves it
  against a database filled by the 0.0.3 schema. A restored backup of 0.0.3 contains them again; the update takes such a backup, and
  the operator should rotate those credentials at the source systems (Proxmox token, UniFi key, Wazuh users, the server access key) when the
  modules are retired.
- **Leftover personal data.** Stored source IP addresses and attack events are deleted by the same migration.
- **Dangling schedules.** A schedule that keeps sending jobs into a queue without a consumer would grow the queue table forever. The worker
  removes the retired queues and their schedules on every start.
- **Failure mode.** The migration runs in one transaction with the others at API start. If it fails, the API does not start and nothing is
  half deleted. The deletion is forward-only and cannot be undone except by a backup.

## Consequences

- The codebase, the test suite and the list of third-party components shrink. Dependencies removed: d3-geo (and d3-array, internmap,
  @types/d3-geo, @types/geojson). Data and services no longer needed: DB-IP Lite, Natural Earth, AbuseIPDB, crt.sh.
- The public API loses the `/hosts`, `/host-setup`, `/proxmox`, `/unifi`, `/exposure`, `/xdr` and `/attacks` routes and the `servers`,
  `guests` and `assets` fields of `/search`. This is a break of the API of 0.0.3 inside a 0.x line and it is accepted by the maintainer;
  no integration is known that uses them. After 1.0 such a removal would need a major version.
- Documentation pages of the removed modules are deleted. Their ADRs stay, marked as superseded, because the decisions explain the
  tag `v0.0.3`.
- The 0.0.3 tables remain empty in the database until 1.0.
