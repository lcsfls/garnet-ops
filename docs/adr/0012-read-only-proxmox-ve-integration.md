# ADR 0012: Read-only Proxmox VE integration

> **Status: superseded by ADR 0025 (removed in 0.0.4).** The module was removed when GarnetOps became a pure developer pipeline. The text below is kept as the record of the decision; it describes the last version that has the module, the tag `v0.0.3`.

- Status: superseded by ADR 0025 (removed in 0.0.4). Earlier status: accepted (2026-10-21)
- Date: 2026-10-21
- Decided by: maintainer (ROADMAP Phase 3, "Proxmox VE")
- Builds on: ADR 0002 (host connectivity), ADR 0004 (vault, SSH), ADR 0011 (servers over SSH)

## Context

Many customers run their servers as virtual machines and containers on Proxmox VE. They want
to see what runs where, what has no backup, what has been stopped for months, and which of
the guests GarnetOps does not know yet. Proxmox VE has a REST API on every node (port 8006),
and API tokens with privilege separation, so this can be done without a root login and without
anything installed on the nodes.

Proxmox VE is free software under the AGPL. We only talk to its REST API over the network; no
Proxmox code, client library or binary is part of GarnetOps, and nothing is added to
`docs/COMPONENTS.md` (the integration uses `node:https`, `node:tls` and `node:crypto`).

Typical Proxmox installations use a **self-signed certificate** (every node creates its own
CA). The API token is a bearer secret; sending it to a server that merely claims to be the
Proxmox server would hand it to an attacker.

## Decision

### 1. Strictly read-only, enforced in code

- The integration reads inventory and nothing else. The HTTP client (`apps/worker/src/proxmox-http.ts`)
  sends **GET only** and only to the paths on one allow-list
  (`READ_PATHS` in `packages/core/src/proxmox.ts`). Any other method or path throws **before a
  connection is opened**. It sends no body, follows no redirects and accepts no query except
  `content=backup` on the storage listing.
- Endpoints read: `/version`, `/cluster/status`, `/cluster/resources` (nodes, qemu, lxc,
  storage), `/cluster/ha/resources`, `/cluster/backup` (jobs), per online node
  `/nodes/{node}/status` and `/nodes/{node}/apt/update` (the node's own cache of pending
  updates; **GET only, never POST, which would refresh the cache**), per guest
  `/nodes/{node}/{qemu|lxc}/{vmid}/config` and `.../snapshot`, for running guests the guest agent's
  `network-get-interfaces` or the container's `interfaces`, and
  `/nodes/{node}/storage/{storage}/content?content=backup`. `/access/permissions` is read for the
  token's own privileges (section 3) and nothing else under `/access`.
- Never read or called: consoles and terminals (`vncproxy`, `termproxy`, `spiceproxy`),
  `agent/exec` and `agent/file-*`, task logs, users, tokens, ACLs, cluster configuration,
  certificates or secrets, and anything under `status/` that starts or stops a guest.
- **No `pct exec`, no `qm guest exec`, no SSH to the node.** Making a guest a server uses the
  agentless SSH flow of ADR 0011 against the guest itself, never the node.
- Free text of a guest (description, notes, snapshot descriptions, cloud-init data, SSH keys,
  mount paths) is never read: the config parser keeps four fields (`ostype`, `template`,
  `agent`, and the static addresses of `net*`/`ipconfig*`) and drops the rest in memory.

### 2. The token and who may use it

- A connection is: name, API URL (`https://host[:port]`, port 8006 by default; plain http,
  credentials in the URL, paths, queries and fragments are refused), token ID
  (`user@realm!tokenid`) and token secret. **Tokens of `root@…` are refused**; GarnetOps never
  asks for a password.
- The secret is sealed in the vault (purpose `proxmox-token`, bound to organisation, record
  and purpose, ADR 0004). **The API only seals; the worker opens it**, for the seconds a sync runs.
  It is never returned, logged, written to an error message, the audit log or a row in clear.
- Owners and admins configure. Creating a connection, changing its address or token,
  removing it, confirming a certificate and acknowledging extra privileges need a **recent
  sign-in** (step-up, ten minutes). Everyone in the organisation reads the inventory; only
  admins see the token ID. Every change is in the audit log.
- Documentation and the "Add connection" dialog tell the admin exactly how to create the
  token: a dedicated user (`pveum user add garnetops@pve`), the role `PVEAuditor` on `/` for
  the user **and** for the token, `--privsep 1` (privilege separation on, so the token has at
  most the privileges of its own ACL). Example names only.

### 3. A token with more than audit privileges

After the certificate is confirmed, every sync starts with `GET /version` and `GET
/access/permissions`. The permissions answer lists the token's effective privileges per path.
Any privilege that is not `*.Audit` (pattern `Word(.Word)*.Audit`: `Sys.Audit`, `VM.Audit`,
`Datastore.Audit`, `Pool.Audit`, `SDN.Audit`, `VM.GuestAgent.Audit`, `Mapping.Audit`) is an
**extra privilege**.

- The extra privileges are stored (`extra_privileges`), written to the audit log
  (`proxmox.privileges_detected`) and shown with a clear warning and a badge.
- **The sync does not run, and nothing but `/version` and `/access/permissions` has been
  asked, until an admin acknowledges exactly those privileges** (step-up, audited,
  `proxmox.privileges_acknowledged`). The acknowledgement names the list the admin was shown;
  if the list changed in the meantime the API refuses (`privileges-changed`). A later sync that finds a
  privilege that was not acknowledged blocks again. A new token or a new address resets the
  acknowledgement.
- Even after the acknowledgement only read requests are ever sent; the client cannot send
  anything else (section 1). The point of the gate is that a stolen token would not be limited
  to reading, and the admin should know.

### 4. Certificate pinning (trust on first use), like SSH host keys

- Adding a connection queues a **certificate read**: the worker opens a TLS connection
  (`node:tls`, TLS 1.2 or newer, HTTP/1.1 only), takes the **leaf certificate** and closes the
  connection **without sending a request, so without the token**. SHA-256 fingerprint, subject,
  issuer, validity and whether it also verifies against the public CA store are stored as a
  **candidate**. Nothing is trusted yet.
- An admin compares the fingerprint with the one on the node (`pvenode cert info`, or the
  certificate page of the node) and confirms it (**step-up**, audited with fingerprint,
  subject and issuer). The API pins exactly the fingerprint that was shown.
- **Every request verifies the pin before the first byte is written.** The client uses its
  own `https.Agent` whose `createConnection` finishes the TLS handshake, compares the leaf's
  SHA-256 with the pin, and only then hands the socket to the HTTP layer. A certificate that
  chains to a public CA is **still compared** with the pin (pinning is never skipped); the CA
  result is shown to the admin for information. (Chain verification is switched off in
  `tls.connect` on purpose, because Node does not even call a custom `checkServerIdentity`
  for a self-signed certificate; the pin is the trust decision.)
- A **different certificate blocks the sync**: status `changed`, the new certificate is kept
  as the candidate, `proxmox.certificate_changed` is audited once, the connection is dropped
  before any request, so the token is not sent. The worker looks at a blocked connection again
  at every tick (handshake only); if the pinned certificate is back, the alarm clears itself.
  Otherwise an admin compares and confirms the new fingerprint (both certificates are shown).
- Trade-off, chosen for safety: a certificate that is **renewed** (for example by an ACME
  client every 60 to 90 days) changes the fingerprint and needs a new confirmation. The docs
  recommend Proxmox's own long-lived certificate or a certificate with a long validity for
  this connection. Pinning the public key instead would survive renewals that reuse the key;
  that is a possible later refinement and is not done silently.

### 5. SSRF and the network

- The address is checked when saved (same rules as servers, `checkHostAddress`: no loopback,
  link-local including cloud metadata, unspecified, multicast; numeric host name tricks such as
  `127.1` refused). The worker **resolves the name itself, checks every answer and connects to the
  checked IP** with the name as SNI and `Host` header (no second lookup an attacker's DNS could
  answer differently). Private ranges stay allowed, because Proxmox lives there.
- No redirects (a redirect is an error). Connection and handshake: 10 s. Every request: 20 s
  (8 s for the guest agent, which may hang). Every answer: at most 8 MiB (declared or
  streamed; the request is aborted at the limit). Concurrency 1, a 25 ms pause between
  requests, at most 6000 requests and 10 minutes per sync, at most 2000 guests, 100 nodes and
  500 storages per connection. The sync stops on repeated timeouts. Connections come from the
  worker only; the Compose stack's `egress` network should allow only port 8006 to the nodes.

### 6. Hostile input

Everything Proxmox sends is parsed by schemas (zod) in `packages/core/src/proxmox.ts`: unknown fields are
ignored, each list entry is validated on its own and dropped if it does not fit (counted as a warning), numbers
arrive as numbers or digit strings, names are stripped of control and bidirectional-override
characters and cut to a length, node and storage names must match a strict pattern before they
are put into a path, vmids are integers. Names are stored as text and rendered as text (React
escapes; descriptions are not read at all). An answer that is not a list, or that lists no node,
**never replaces the stored inventory** (a broken answer cannot empty it). Guests that are not in
a valid answer any more are removed; what could not be read (an offline node, a refused
endpoint) keeps its last known value.

### 7. Data model (additive migration 0011)

`proxmox_cluster` (connection, sealed token reference, certificate pin and candidate, extra and
acknowledged privileges, version, backup readability, last sync and error), `proxmox_node`,
`proxmox_guest` (vmid, type, name, node, status and since when, usage and maximum, uptime,
OS type, tags, template, HA state, whether a backup job includes it, last backup, snapshot
count and newest and oldest time, addresses, first and last seen), `proxmox_storage` and
`proxmox_sync_run` (state, trigger, counts, warnings, error). `host.source = 'proxmox'` with
`host.source_ref = '<cluster id>:<vmid>'` (reserved by ADR 0011, unique per organisation) links a
server to a guest, no schema change. A guest is **tracked** when such a server exists; the link
survives a sync, a rename and a removal of the connection.

### 8. Sync

- pg-boss queues `proxmox.certificate`, `proxmox.sync` and a tick queue. **A tick every 15
  minutes** queues a sync for every enabled connection with a confirmed certificate whose
  extra privileges (if any) are acknowledged, unless a run is waiting or running or one was queued in the
  last ten minutes. An admin can also start a sync (rate limited, audited). 15 minutes keeps status and usage
  current at a cost of about two requests per guest and a handful per node per cycle,
  sequential and paced; the nightly schedule of ADR 0005 is too slow for status.
- One run per connection at a time (state check plus `singletonKey`), claimed atomically; a
  run older than 15 minutes in `running` counts as lost. Failures end as a short message from a
  fixed list (`packages/core/src/proxmox-errors.ts`, translated in the web app). Output of Proxmox
  is never put into a message.
- **Staleness** (constants in `packages/core/src/proxmox-flags.ts`, repeated in SQL): stopped for
  more than **30 days** (Proxmox does not say since when; GarnetOps counts from when it first saw
  the guest stopped), no backup in **7 days** (only when every backup storage could be listed;
  otherwise not flagged, never guessed), a snapshot older than **30 days**. **Untracked**: running,
  not a template, no linked server. Templates are never flagged. Thresholds are fixed constants;
  configurable thresholds are a later item.

### 9. Web

The Proxmox view is a segment of Infrastructure → Servers (no new navigation entry). It shows
one card per connection (version, nodes online, guests, stale, untracked, nodes with updates,
last sync, certificate and token state), the nodes (usage, version, kernel, pending updates
with the count), storage and the guests (sortable and filterable by flag, type, status, node,
cluster and text; more columns at wide and xwide; a detail dialog). "Add as server" opens the
usual add-server wizard prefilled with name and address. Servers that were made from a guest
show a "VM 100" link. Settings → Proxmox (owners and admins) adds, tests, edits and removes
connections and confirms certificates and privileges. Green is not used: a pinned certificate or a finished sync proves nothing.

## Threat model

| Threat | What an attacker gains | Mitigation |
| --- | --- | --- |
| Stolen token (database, backup, memory) | With the vault key: the token. With the token: **audit-only read** of the Proxmox inventory, from an address that can reach the node. No console, no start or stop, no config change. | Secret sealed in the vault, opened by the worker only, never logged or returned; role `PVEAuditor` and privilege separation are required by the docs and checked on every sync (section 3); the token can be revoked on the Proxmox side without touching GarnetOps. |
| Over-privileged token (for example PVEAdmin) | A stolen token could change or stop guests. | `/access/permissions` is checked at every sync; anything beyond `*.Audit` blocks the sync, shows a warning and needs a step-up acknowledgement naming the privileges; `root@…` refused; the client cannot send anything but allow-listed GETs whatever the token can do. |
| Man in the middle on first contact | Receive the token, answer with false inventory. | The token is **never sent before the certificate is pinned**; the admin compares the fingerprint on the node (an independent channel) and confirms with step-up; audit entry. |
| Man in the middle later, or a rebuilt server | Same. | Every connection compares the leaf with the pin before any byte of the request; a mismatch drops the connection, marks the connection `changed`, audits it, and blocks until an admin confirms. |
| Admin points GarnetOps at internal targets (SSRF, port scanning) | Learn whether a service with a TLS certificate exists at an address; the token is sent to that address after a pin only an admin confirmed. | Loopback, link-local, metadata, unspecified, multicast refused at save and again after DNS resolution in the worker, which connects to the checked IP; no redirects; the response is never shown; only a generic error text; admin-only, step-up, audit. |
| Hostile or compromised Proxmox answers (JSON, names, tags) | Parser bugs, stored XSS, SQL or path injection, memory exhaustion. | zod schemas, unknown fields ignored, per-entry validation, strict patterns before anything goes into a path, size caps (8 MiB per answer, 2000 guests), control and bidi characters stripped, stored as text and rendered escaped, descriptions never read; a broken answer cannot empty the inventory; tests with hostile fixtures. |
| Denial of service of the Proxmox API by GarnetOps | Slow or unavailable Proxmox web interface. | One request at a time, 25 ms pause, timeouts, a request budget and a time budget per sync, 15 minute interval, abort on repeated timeouts, `retryLimit: 0` (the next tick is the retry). |
| Denial of service of GarnetOps by Proxmox | Worker memory or time. | Response cap, timeouts, caps on counts, bounded writes in one transaction. |
| Data minimisation | Needless secrets in the database. | No consoles, no cloud-init data, no descriptions, no users or tokens, no task logs; `/access` is read only for the token's own permissions; no guest command is ever executed. |
| A member without rights changes connections | Re-point, remove, pin a certificate. | Role checks on every write, step-up for sensitive ones, organisation scoping on every query, audit log. |
| Guest or node names carry prompt injection | Manipulated AI triage later. | Not used by AI in this change; Proxmox names are untrusted input wherever AI reads them (AGENTS.md rule 1). |
| Linking a server to a guest of another organisation | Information about another tenant's guests. | `source_ref` must name a guest of the same organisation (checked in the API); lookups are organisation-scoped. |

## Consequences

- GarnetOps shows the virtualisation layer next to the servers without a single agent or any
  write access to Proxmox; the price is one dedicated user and token, port 8006 from the worker, and a
  confirmation whenever the certificate changes.
- Certificates that renew often need a re-confirmation each time; the documentation says so and
  recommends a long-lived certificate. Public-key pinning is an option for later.
- Backup age is only as good as the token's right to list backup storage; without it the
  "no recent backup" flag is switched off for that connection, and the UI says so.
- Guest addresses are known only from the guest agent, the container's interface list or a
  static configuration; DHCP guests without an agent have none, and "Add as server" asks for the address.
- Out of scope, tracked on the roadmap: configurable thresholds, notifications for stale or untracked
  guests, Proxmox Backup Server and Proxmox Datacenter Manager, public-key pinning, linking by
  address, ACME-aware renewals.
- Every release is tested as an upgrade; the migration only adds tables and one secret purpose (a text
  value).
