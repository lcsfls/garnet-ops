# ADR 0002: How hosts are connected; Wazuh as XDR integration

- Status: accepted (details of the Wazuh 5.x adapter pending its GA release)
- Date: 2026-10-19
- Decided by: maintainer

## Context

Customers want to see their servers next to their repositories: installed
packages, known vulnerabilities, pending updates, and for some of them security
events (failed logins, file integrity, threat detection). Wazuh already
provides a mature XDR and SIEM platform (GPL-2.0). Building our own agent or
SIEM would duplicate it and enlarge our attack surface.

Wazuh 5.0 is at release candidate 1. Compared with 4.x it removes the
inventory endpoints and agent statistics endpoints from the manager REST API;
that data now lives in indices of the Wazuh indexer. Default API users no
longer ship with fixed passwords, and new RBAC actions exist for secrets.

## Decision

Hosts are connected in one of two ways, chosen per host or host group.

### 1. Agentless (default, every edition)

- The admin adds a host by address, or imports a list (CSV) or an inventory
  from Wazuh.
- The platform generates an SSH key pair per installation (Ed25519). The admin
  creates a dedicated, unprivileged user on the host and adds the public key,
  restricted with `from=`, `no-pty`, `no-port-forwarding`, `no-agent-forwarding`
  and a forced command wrapper that only allows the inventory commands.
- The host key is pinned on first contact (trust on first use, shown to the
  admin with its fingerprint for confirmation) and any later change blocks the
  connection until an admin confirms it.
- The platform reads the package inventory (`dpkg-query`, `rpm -qa`, `apk info`,
  OS release, kernel, pending updates) on a schedule and matches it against the
  same local vulnerability database used for repositories. No root, no write
  access, nothing installed.
- Connections originate from a dedicated worker with its own network policy.

### 2. Wazuh integration (optional, "XDR" in the navigation)

- For customers who already run Wazuh. We never bundle, modify or link Wazuh.
- Read-only access with two dedicated service accounts:
  - **Manager REST API** (port 55000, JWT): agents, groups, status, last
    keep-alive, versions.
  - **Indexer API** (OpenSearch-compatible): alerts, vulnerability states,
    inventory, file integrity events.
- Minimal RBAC: read actions only; never `agent:read_secrets` or
  `cluster:read_secrets`. TLS with CA pinning is mandatory.
- One adapter per major version behind a common interface:
  - `wazuh4` for 4.x (supported line: the latest 4.x minor; earlier minors on
    request), inventory partly via the manager API, vulnerabilities via the
    indexer.
  - `wazuh5` for 5.x, all inventory, statistics and vulnerability data via
    indexer indices. Built against the release candidates, marked as preview
    until Wazuh 5.0 is generally available.
- The version is detected at connection time; the UI shows which adapter is in
  use. A Wazuh upgrade from 4.x to 5.x must not lose history in our product.
- Agents enrolled in Wazuh appear in our host list automatically and can be
  linked to an agentless host record for the same machine (matched by
  hostname, IP and machine ID).

### Navigation

- **Infrastructure → Servers:** every host from both sources, with inventory,
  vulnerabilities and pending updates.
- **Infrastructure → XDR (Wazuh):** shown when the integration is configured:
  connection status, alerts by severity, MITRE ATT&CK tactics, file integrity
  events, top agents, with AI summaries. Links to the Wazuh dashboard for deep
  dives instead of rebuilding it.

## Consequences

- No own agent to build, sign, distribute and keep secure in the first phases.
- Agentless scanning needs SSH reachability from the platform to hosts; the
  docs must cover jump hosts and segmented networks.
- Two Wazuh adapters must be maintained while both major versions are in use.
- Wazuh field names and index patterns are an external contract we do not
  control; integration tests run against recorded fixtures of each supported
  version.
