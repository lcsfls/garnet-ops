# ADR 0015: Read-only Wazuh XDR integration

> **Status: superseded by ADR 0025 (removed in 0.0.4).** The module was removed when GarnetOps became a pure developer pipeline. The text below is kept as the record of the decision; it describes the last version that has the module, the tag `v0.0.3`.

- Status: superseded by ADR 0025 (removed in 0.0.4). Earlier status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (ROADMAP Phase 4, "XDR page backed by a customer-run Wazuh")
- Builds on: ADR 0002 (host connectivity and Wazuh), ADR 0004 (vault), ADR 0011 (servers),
  ADR 0012 (Proxmox VE: certificate pinning, GET-only client, hostile JSON), ADR 0013 (AI: worker-only
  model calls and the address policy)

## Context

ADR 0002 decided that Wazuh is an optional, read-only integration with a customer-run Wazuh 4.x or 5.x
(manager REST API and indexer API), shown as Infrastructure, XDR. This ADR makes the decisions that
ADR 0002 left open and records the threat model.

Wazuh is GPL-2.0 free software. We talk to its network APIs only; no Wazuh code, client library,
agent or binary is part of GarnetOps (AGENTS.md rule 3), so nothing is added to the dependencies. The
integration uses `node:https`, `node:tls`, `node:crypto` and the zod that is already there. The
Wazuh row of `docs/COMPONENTS.md` describes it as an external integration.

Two facts shape the design:

- **Everything in an alert is written by someone else.** Rule descriptions, file paths, host and
  agent names, user names, source addresses and log lines come from whoever can make a monitored
  machine log something. An attacker who has a foothold on one machine controls text that arrives
  in GarnetOps.
- **The two service users are bearer secrets.** A stolen password gives its holder whatever the
  Wazuh role allows. What GarnetOps does with the password is read-only, but the role decides what
  a thief can do.

## Decision

### 1. Two endpoints, one adapter chosen by version

A connection (one per organisation today; every table carries the connection id so that more can
follow without migrating data) has two endpoints:

| Endpoint | Default port | Credential | Used for |
| --- | --- | --- | --- |
| Manager REST API | 55000 | user and password, exchanged for a JWT | version, agent list, the user's own policies |
| Indexer (OpenSearch-compatible) | 9200 | user and password, HTTP basic | alert aggregations, file integrity sample, vulnerability states, the user's own roles |

The manager version comes from `GET /` (`api_version`). Major 4 selects the `wazuh4` adapter, major
5 the `wazuh5` adapter, any other major version is refused (`unsupportedVersion`). The indexer's `GET /`
must look like an OpenSearch-style indexer (`version.number` and `cluster_name` or the OpenSearch
tagline). The adapter, the manager version and the indexer version are stored and shown. `wazuh5` is
marked **preview** in the UI until Wazuh 5.0 is generally available (ADR 0002).

Adapters (`packages/core/src/wazuh.ts`, `ADAPTERS`) are the only place that knows Wazuh's index
patterns and field names, because they are an external contract we do not control:

| | `wazuh4` | `wazuh5` (preview) |
| --- | --- | --- |
| Alert index | `wazuh-alerts-*` | `wazuh-alerts-*` |
| Vulnerability state index | `wazuh-states-vulnerabilities-*` | `wazuh-states-vulnerabilities-*` |
| Alert fields | `@timestamp`, `rule.level`, `rule.mitre.tactic`, `rule.groups`, `agent.id`, `agent.name`, `data.srcip`, `syscheck.path`, `syscheck.event` | same assumed |
| Vulnerability fields | `agent.id`, `vulnerability.severity` | same assumed |

The 5.x column was built against the release candidate documentation and has **never been run
against a real Wazuh 5 installation**. If general availability changes a name, one constant changes.
Tests run against synthetic fixtures of Wazuh 4.12 and 5.0 answers (`packages/core/test/fixtures/wazuh`),
in which example names and documentation address ranges replace real data.

An upgrade of Wazuh from 4.x to 5.x does not lose anything stored: agents are keyed by connection and
agent id, the aggregates are replaced window by window, and a window that cannot be read keeps its
earlier values and says when it was read.

### 2. Strictly read-only, enforced in code

- **One method and path allow-list per endpoint** (`isManagerRequestAllowed`, `isIndexerRequestAllowed`).
  Every request of both clients goes through one method that checks it **before a socket is opened**;
  anything else throws.
- Manager: `GET /`, `GET /agents` with a fixed query (limit 500, an offset, one fixed `select` list
  that has no key or secret field, `sort=+id`), `GET /security/users/me/policies`, and the **one
  POST the API defines for logging in**, `POST /security/user/authenticate` (no query, no body).
  Nothing under `/agents/{id}` is ever read (`/agents/{id}/key` returns the agent's key and is
  therefore on no list), nor `/security/users`, `/security/roles`, `/active-response`,
  `/manager/configuration`, `/cluster`, `/logtest` or the inventory endpoints.
- Indexer: `GET /`, `GET /_plugins/_security/authinfo`, `GET /_plugins/_security/api/permissionsinfo`,
  and `POST <index>/_search` or `_count` on exactly the two indices of the adapter (`_count` on the
  alert index, `_search` on both). No other index, no bulk, scroll, `_msearch`, scripts, delete or
  update.
- **The body of an indexer POST is built from a fixed template** (`buildIndexerRequest`) whose only
  input is an enumerated period (`24h`, `7d`, `30d`). There is no way to hand the client a query
  from the web, the database, a setting or an earlier answer; nothing Wazuh sent is ever
  interpolated into a query. The templates are aggregations with small sizes (levels 20, tactics 20,
  agents 10, source addresses 100, vulnerability agents 5000, file integrity events 25), carry a
  20 s search timeout, and ask for no raw alert in bulk. The only documents fetched are the 25
  latest file integrity events with six `_source` fields (no `full_log`).
- No redirects (a redirect is an error). TLS 1.2 or newer. Connection and handshake 10 s, every
  request 20 s, every answer at most 8 MiB (declared or streamed), one request at a time with a
  25 ms pause, at most 200 requests and 5 minutes per sync, at most 5000 agents.
- **The JWT** returned by the login lives in the memory of the worker's client for the length of one
  sync. It is never written to the database, a log or an error message. If the manager answers 401
  to a data request the client logs in once more; a second 401 is an error, not a loop.

### 3. Who may configure, and how the passwords are kept

- Owners and admins configure under **Settings, XDR / Wazuh**. Everyone in the organisation reads
  the XDR page; only admins see addresses, user names and fingerprints.
- A connection is: a name, the manager address, the indexer address, a user name and password for
  each, optionally a PEM certificate authority for each, optionally the address of the customer's
  Wazuh dashboard and the address agents use to reach the manager.
- Both passwords are sealed in the vault (purposes `wazuh-api-password` and `wazuh-indexer-password`,
  bound to organisation, record and purpose, ADR 0004). **The API only seals; the worker opens**, for the
  seconds a sync runs. A password is never returned, logged, put in an error, the audit log or any row
  in clear (tested over every table).
- The default administrative accounts (`admin`, `wazuh`, `wazuh-wui`, `kibanaserver`) are refused as
  service users, like `root` is for Proxmox.
- Creating, re-pointing and removing the connection, changing a user or password, uploading or removing
  a certificate authority, **changing the dashboard address or the enrollment address** (both end up in
  links and commands people trust), confirming a certificate and acknowledging extra privileges need a
  **recent sign-in** (step-up, ten minutes). Renaming and switching the sync off do not. Every change is
  in the audit log (`xdr.*`), without any secret.
- Re-pointing an endpoint or changing how it is trusted forgets its certificate, and a new password
  forgets the privilege acknowledgement.

### 4. Trust: pinned certificate, or your own authority

Wazuh installations normally have certificates from their own authority or self-signed ones. Each
endpoint is trusted in exactly one of two ways:

- **Pinned (default), trust on first use, like SSH host keys and Proxmox (ADR 0012).** Saving the
  connection queues a certificate read per endpoint: the worker connects, takes the leaf certificate
  and closes the connection **without sending a request, so without the password**. The SHA-256
  fingerprint, subject, issuer and validity are shown. An admin compares the fingerprint with the one
  on the Wazuh server (`openssl x509 … -fingerprint -sha256`, shown in the dialog) and confirms it
  (step-up, audited). **Every request verifies the pin before the first byte is written**; a
  different certificate drops the connection, marks the endpoint `changed`, keeps the new one as a
  candidate, audits it once and blocks the sync until an admin confirms. The worker looks again at a
  changed endpoint every tick (handshake only), so the alarm clears itself if the pinned certificate
  returns. A certificate that chains to a public CA is still compared with the pin.
- **A certificate authority you upload.** Paste the PEM of the authority that signed the endpoint
  (one to five certificates, at most 24 KB, **certificates only**: a private key or any other text is
  refused). The handshake then verifies chain and host name itself (`rejectUnauthorized`), so a renewed
  certificate under the same authority needs no new confirmation. An endpoint that does not chain to
  the authority is an error (`caRejected`); there is nothing to confirm. The authority is public
  data and is stored in clear.

The trade-off of the first mode is that a **renewed** certificate needs a new confirmation; the
documentation recommends the second mode for installations whose certificates are renewed often.

### 5. Network and SSRF

The addresses are checked when saved (`checkWazuhUrl`: https only, no credentials, path, query or
fragment; loopback, link-local including cloud metadata, unspecified and multicast refused, numeric
host name tricks such as `127.1` refused) and again by the worker, which **resolves the name itself,
checks every answer, and connects to the checked IP** with the name as SNI and `Host` header (no second
lookup an attacker's DNS could answer differently). Private ranges stay allowed, because Wazuh lives
there. Connections come from the worker only; the Compose stack's `egress` network should allow only
the Wazuh ports. Error messages are a short fixed list of texts (`packages/core/src/wazuh-errors.ts`,
translated in the web app); nothing Wazuh answered is ever put into one.

The dashboard address is **never requested** by GarnetOps. It is only shown as an external link
(`http:` or `https:` only, no credentials, no fragment; `rel="noopener noreferrer"`, new tab), so a
`javascript:` or `data:` value cannot be saved.

### 6. Users that can do more than read

Read-only is also a property of the Wazuh roles, so GarnetOps checks it on every sync, **after the
login and the version and before any data is read**:

- **Manager:** `GET /security/users/me/policies` (available on 4.x and 5.x to any authenticated user)
  returns the user's effective RBAC policies as a map from action to resources to `allow`/`deny`.
  An action counts when at least one resource is allowed. Actions whose verb is `read` or `status` are
  reads; **every other action** (`agent:restart`, `security:create`, `agent:read_secrets`,
  `cluster:read_secrets`, `*:*`, …) is an **extra privilege**. An answer in another shape fails the
  sync (`policiesUnreadable`): "unknown" is never treated as "nothing extra".
- **Indexer:** the user's role names from `authinfo` and, if readable, `has_api_access` from
  `permissionsinfo`. Roles known to be administrative (`all_access`, `security_manager`,
  `manage_snapshots`, `cluster_manager`, `kibana_server`, `wazuh_ui_admin`, `wazuh_admin`, `admin`) and
  access to the security REST API are extra privileges. **Limit:** GarnetOps sees the names of the
  roles, not what a custom role allows, so a custom role with write access is not detected; the
  documentation gives the exact role to use. If `authinfo` cannot be read the sync continues and says so
  (`rolesUnreadable`), because the security plugin may be switched off in custom installations.
- Extra privileges are stored (`xdr.privileges_detected` in the audit log, once per change), shown with a
  warning and a badge, and **the sync reads nothing from Wazuh until an admin acknowledges exactly those
  privileges** (step-up, audited, `xdr.privileges_acknowledged`). The acknowledgement names the list the
  admin was shown; if the list changed in the meantime the API refuses. A later privilege that was not
  acknowledged blocks again. A new password or address resets the acknowledgement.
- Even after the acknowledgement only read requests are sent (section 2). The point of the gate is that a
  stolen password would not be limited to reading, and the admin should know.

The minimal roles are in `docs/xdr.md`: for the manager the action `agent:read` on `agent:id:*` and
`agent:group:*` (the only RBAC-guarded endpoint GarnetOps calls is the agent list; `/` and the user's own
policies need none), for the indexer read-only access to `wazuh-alerts-*` and
`wazuh-states-vulnerabilities-*` and nothing else. The inventory indices (`wazuh-states-inventory-*`,
`wazuh-monitoring-*`) are **not read yet** and are therefore not in the role; the roadmap item that
reads Wazuh's package inventory adds them.

### 7. Hostile input

Everything Wazuh sends is parsed by zod schemas and explicit checks in `packages/core/src/wazuh.ts`:
unknown fields are ignored, each list entry is validated on its own and dropped if it does not fit
(counted as a warning), numbers are bounded and non-numbers become 0, agent ids and group names must
match strict patterns, addresses must be valid IP addresses, tactic names must match a character
whitelist and are cut, rule groups of source addresses must be on the fixed attack/authentication list,
and free text (names, paths) has control, line-separator and bidirectional-override characters removed
and is cut (names 128, paths 500 characters). An agent list or an alert answer that does not parse
**never replaces stored data** (an empty or broken agent list fails the sync; an unreadable window keeps
its earlier values). File paths and names are stored as text, rendered as text (React escapes), **never as
a link**, never as HTML, and never sent to a model. A test replays a path that tries to be markup and a
link, and an alert tactic that is a `<script>`.

### 8. What is stored

Aggregates and a small bounded sample; nothing streams raw alerts or logs into our database.

| Table | Content | Bound |
| --- | --- | --- |
| `wazuh_connection` | name, adapter, versions, privileges found and acknowledged, last sync and error, dashboard and enrollment address | one per organisation |
| `wazuh_endpoint` | per endpoint: address, user name, **vault reference of the password**, trust mode, authority PEM, pinned and candidate certificate | two per connection |
| `wazuh_agent` | agent id, name, address, system, version, status, last keep-alive, groups, vulnerability counts by severity, the confirmed link to a server, a suggested server | at most 5000 |
| `wazuh_snapshot` | alert counts for 24 h, 7 d and 30 d: total and by severity with the previous period, MITRE ATT&CK tactics (20), busiest agents (10), file integrity count, vulnerability totals | one row, numbers only |
| `wazuh_fim_event` | the 25 latest file integrity events (time, agent, path, event) | replaced as a whole |
| `wazuh_source_ip` | source addresses of authentication-failure and attack alerts with count and rule groups, 100 per window | the attack overview (ADR 0016; first and last time and targeted agents were added there) |
| `wazuh_sync_run` | state, counts, warning codes, error text | history |
| `wazuh_summary` | the AI summary of the aggregates | history |

**Severity mapping.** Wazuh rule levels become our four steps (`severityForLevel`): **12 to 15 critical,
9 to 11 high, 6 to 8 medium, 1 to 5 low**; level 0 is "ignored" in Wazuh and has no severity; a level above
15 is treated as 15. The mapping is shown on the XDR page.

### 9. Sync

- pg-boss queues `xdr.certificate`, `xdr.sync`, `xdr.summary` and a tick queue. **A tick every 15 minutes**
  queues a sync for every enabled connection whose two endpoints are confirmed and whose extra privileges (if
  any) are acknowledged, unless a run is waiting or running or one was queued in the last ten minutes. An
  admin can also start a sync (rate limited, audited). One run per connection at a time, claimed
  atomically; a run older than 15 minutes in `running` counts as lost. `retryLimit: 0`: the next tick is the
  retry.
- Order: login, `GET /`, indexer `GET /`, the privilege checks, **stop if unacknowledged**, agents (pages of
  500), then the indexer questions: a `_count` of the alerts (readable at all?), per period one aggregation and
  one aggregation of the previous period, the file integrity sample, the vulnerability counts per agent.
  Every indexer question is optional: a role that lacks one index does not stop the others (warning codes
  `alertsUnreadable`, `fimUnreadable`, `vulnerabilitiesUnreadable`). A lost connection, a rejected password,
  a changed certificate, a rate limit (429) or a redirect ends the sync. After repeated timeouts the sync stops.
- Agents that are no longer listed are removed (with their link); the first-seen time and the link of the
  others survive. Vulnerability counts per agent come from the indexer; an agent the indexer does not list
  has "no data" (shown as a dash), never a false zero.

### 10. Agents and servers

Agents appear on **Infrastructure → Servers** as a source (the *Wazuh* view, next to *Servers* and
*Proxmox*) and on the XDR page, as read-only rows: no SSH is ever configured for an agent that is merely
listed.

- **Suggestion.** After every sync GarnetOps suggests the existing server that is probably the machine behind
  an unlinked agent: the same address, the same name, or the same host name without domain, in that order, and
  **only an unambiguous match** (two servers with the same short name, or two agents suggesting the same
  server, suggest nothing). Servers that are linked already are not candidates. The machine id is not offered
  by the manager API and is not used.
- **Confirmation.** A suggestion is only ever confirmed by an owner or admin (`xdr.agent_linked` in the audit
  log, `xdr.agent_unlinked` for the reverse). A server has at most one agent (unique index); the manager's own
  agent `000` cannot be linked.
- **Add as server.** From an agent without a server, "Add as server" starts the usual add-server wizard
  prefilled with the agent's name and address; the server is created with `host.source = "wazuh"` and
  `host.source_ref = "<connection id>:<agent id>"` and linked to the agent in the same transaction. The server
  is then inventoried over SSH like any other (agentless); Wazuh's package inventory and vulnerabilities are
  **not** merged into the findings model (still open on the roadmap), but Wazuh's vulnerability counts are
  shown per agent.

### 11. AI summary

An optional "Summarise with AI" button on the XDR page, absent unless AI is configured and switched on
(ADR 0013). The API stores a pending summary and queues a job; **the worker, the only process that opens the
model's API key, builds the prompt from the stored aggregates and calls the model** through the same client,
the same address policy, the same limits and the same user and organisation rate limits as AI triage. The
request is audited as `ai.request` (kind `xdr-summary`, model, summary id; never the prompt or the answer).

- **The model receives numbers only** (`packages/core/src/xdr-summary.ts`): alert counts by severity and
  period with the previous period's, file integrity event counts, counts per MITRE ATT&CK tactic (matched
  against the 14 tactic names of the framework; anything else an alert carried is dropped), the alert counts of
  the busiest agents **without who they are**, agent counts by state, vulnerability counts by severity. **No IP
  address, no host or agent name, no group, no path, no rule description or log line.** The data sits in one
  block between random markers with the usual rule that it is data. Tests replay a hostile snapshot (a tactic
  that is an instruction, agent names, addresses) and assert that none of it reaches the model.
- The answer is untrusted (ADR 0013): cleaned of control and invisible characters, cut, stored as text, shown
  labelled **"AI suggestion"** and rendered by the existing safe Markdown renderer (no HTML, no images, no
  `javascript:`). It never changes a setting or a finding. One summary at a time; a lost one is marked failed
  after 15 minutes.

### 12. Agent enrollment helper

On the XDR page ("Enroll an agent") and in the add-server wizard ("Monitor with Wazuh instead"), GarnetOps shows
the **official Wazuh agent installation commands** with the customer's manager address filled in. GarnetOps does
not build, package, sign or ship an agent and does not install anything: the commands are printed for an admin to
run, and they download Wazuh from `packages.wazuh.com` themselves.

- The templates live in one versioned module (`packages/core/src/wazuh-enroll.ts`,
  `ENROLLMENT_TEMPLATES_VERSION`) with tests per operating system: Debian and Ubuntu (key import into
  `/usr/share/keyrings/wazuh.gpg`, `apt` repository, `apt-get install`), RHEL, Rocky and Alma (`rpm --import`,
  `/etc/yum.repos.d/wazuh.repo`, `yum install`), SUSE (`zypper`), Windows (PowerShell download of the MSI, `msiexec`)
  and macOS (the `.pkg` for the architecture, `/tmp/wazuh_envs`, `installer`). The series (`4.x`, `5.x`) and the
  pinned package version come from the detected manager version, because an agent must not be newer than its
  manager. The 5.x commands follow the documentation of the release candidates and are marked preview.
- The manager address is the configured **enrollment address** (which may differ from the API address) or, if
  none is set, the API host. `WAZUH_AGENT_GROUP` and `WAZUH_AGENT_NAME` are optional.
- **Validation and quoting.** The manager address, the group list (at most five names) and the agent name are
  checked against whitelists of characters (`[A-Za-z0-9._-]`; host names and IP addresses for the manager)
  **before** they are put into a command, and are quoted for the target shell (POSIX single quotes, PowerShell
  doubled single quotes) as well. Input that does not pass is refused with an error, never "cleaned". Tests try
  `;`, `$(…)`, backticks, quotes, newlines and option-like values for every field and operating system.
- **The enrollment password** is not an input. If the manager asks for one, the admin ticks a box and the command
  carries the marked placeholder `<ENROLLMENT_PASSWORD>`, which the admin replaces on the machine. GarnetOps never
  stores or shows a password for this.
- The dialog states that Wazuh is GPL-2.0, installed and run by the customer and not part of GarnetOps (rule 3).

## Threat model

| Threat | What an attacker gains | Mitigation |
| --- | --- | --- |
| Stolen manager or indexer password (database, backup, memory) | With the vault key: the password. With the password: whatever the Wazuh role allows, from an address that can reach Wazuh. | Sealed in the vault, opened by the worker only, never logged or returned; the docs give minimal read-only roles; **every sync checks what the users may do and stops until an admin acknowledges more than reading** (section 6); the password can be revoked in Wazuh without touching GarnetOps. |
| Over-privileged service user (the default `admin`, `wazuh` or `wazuh-wui`) | A stolen password could change or delete things in Wazuh. | Default administrative accounts refused by name; policies and roles checked on every sync; extra privileges block until acknowledged with step-up and audit; the clients cannot send anything but allow-listed requests whatever the user can do. |
| Man in the middle on first contact | Receive the password, answer with false data. | The password is **never sent before the certificate is pinned** (or verified against your authority); the admin compares the fingerprint on the server (an independent channel) and confirms with step-up; audit entry. |
| Man in the middle later, or a rebuilt server | Same. | Every connection compares the leaf with the pin before any byte of the request; a mismatch drops the connection, marks the endpoint `changed`, audits it and blocks until an admin confirms. With an authority, TLS verifies chain and host name. |
| A hostile authority upload | Trust for an attacker's certificate; a private key stored by mistake. | Admin only, step-up, audit; PEM must be certificates only (a key is refused); at most 5 certificates and 24 KB; the authority applies to one endpoint. |
| Admin (or a stolen admin session) aims GarnetOps at internal targets (SSRF, port scan) | Learn whether a service with a TLS certificate exists at an address; the password is sent there after a pin an admin confirmed. | Loopback, link-local, metadata, unspecified and multicast refused at save and again after DNS resolution in the worker, which connects to the checked IP; no redirects; the response is never shown; only generic error texts; admin only, step-up, audit. |
| Hostile or compromised Wazuh answers; attacker-controlled alert content (rule text, paths, names, tactics, source addresses) | Parser bugs, stored XSS, SQL or path injection, prompt injection, memory exhaustion. | zod and explicit checks, unknown fields ignored, per-entry validation, strict patterns, size and count caps (8 MiB, 5000 agents, 25 events), control and bidi characters stripped, stored as text and rendered escaped, paths never links; a broken answer cannot empty stored data; tests with hostile fixtures. |
| Prompt injection into the AI summary | The model is talked into advising something harmful. | The model gets **numbers only** (no free text from Wazuh; tactic names only from the framework's fixed list); output is labelled, escaped, never acted on, cannot change any setting; same address policy and limits as ADR 0013. |
| Query injection into the indexer | Read other indices, delete or change data. | No query is built from input: fixed templates with an enumerated period; method and path allow-list (two indices, `_search`/`_count`); a forged period throws; the role limits what a thief could do anyway. |
| Denial of service of the indexer or manager by GarnetOps | Slow or unavailable Wazuh. | Aggregations with small sizes and a search timeout, one request at a time with a pause, a request and time budget per sync, 15 minute interval, abort on repeated timeouts and on 429, `retryLimit: 0`. |
| Denial of service of GarnetOps by Wazuh | Worker memory or time. | Response cap, timeouts, caps on counts, bounded writes in one transaction. |
| Dashboard address used for phishing or script injection | A user clicks a link that is not the Wazuh dashboard. | `http`/`https` only, no credentials, no fragment, never requested by GarnetOps, external link with `noopener noreferrer`; changing it needs step-up and is audited. |
| Enrollment helper used to enroll machines into an attacker's manager, or to inject shell | Agents report to the wrong manager; command execution on a machine whose admin pastes the command. | The enrollment address is set by admins with step-up and audit, validated against a whitelist and quoted; group and name validated and quoted; templates versioned and tested; GarnetOps executes nothing, the admin reads the command before running it. |
| A member without rights changes the connection or a link | Re-point, pin a certificate, link servers. | Role checks on every write, step-up for sensitive ones, organisation scoping on every query, audit log. |
| Linking an agent to a server of another organisation | Information about another tenant. | Link requests name a server of the same organisation (checked in the API); the unique index allows one agent per server. |
| Leaking the password through enrollment | A command containing a real enrollment password is copied around. | The helper has no password input; the command carries a marked placeholder. |

## Consequences

- Migration 0014 (additive): tables `wazuh_connection`, `wazuh_endpoint`, `wazuh_agent`, `wazuh_snapshot`,
  `wazuh_fim_event`, `wazuh_source_ip`, `wazuh_sync_run`, `wazuh_summary`; secret purposes `wazuh-api-password`
  and `wazuh-indexer-password` (text values). New queues `xdr.certificate`, `xdr.sync`, `xdr.summary`; new
  audit actions `xdr.*`; new endpoints under `/api/v1/xdr/…`; `POST /api/v1/hosts` accepts `source: "wazuh"`.
- GarnetOps shows what Wazuh reports without a single agent of its own, without any write access to Wazuh and
  without bundling any Wazuh code. The price is two dedicated users, ports 55000 and 9200 from the worker, and a
  confirmation whenever a pinned certificate changes (unless an authority is used).
- Not done, tracked on the roadmap: Wazuh's package inventory and vulnerability states in the same findings
  model and watch list as agentless hosts; the attack overview with GeoIP is built (ADR 0016); linking by machine id; a custom role with write access on the indexer is not detected; the 5.x
  adapter has not been run against a real Wazuh 5; agents are not synced between several managers (one
  connection per organisation).
- Every release is tested as an upgrade; the migration only adds tables.
