# ADR 0022: Read-only UniFi integration

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (a network device view from UniFi consoles, and an optional preview of intrusion prevention events)
- Builds on: ADR 0012 (read-only Proxmox VE integration: GET-only client, pinning on first contact, SSRF rules, hostile JSON,
  acknowledging privileges beyond reading), ADR 0015 (the same for Wazuh),
  ADR 0016 and ADR 0021 (attack overview, globe and live feed), ADR 0019 (notification catalogue), AGENTS.md rules 1, 3, 5, 6 and 7

## Context

Many customers run their network on Ubiquiti UniFi: a gateway, switches and access points, managed by a UniFi OS console (UDM,
UCG, Cloud Key Gen2 and newer) or by a self-hosted UniFi Network Application. Two questions come up that a server-focused
tool should answer: which network devices exist, are they online, and is their firmware current; and what does the gateway's
intrusion prevention (IPS) block at the edge.

Three facts shape the design:

- **Data must not leave the network.** Ubiquiti also offers a cloud API (Site Manager, `api.ui.com`). Using it would send the
  customer's inventory to a third party. GarnetOps never calls it.
- **The official local API is read and write, and its key cannot be narrowed.** The official local UniFi Network API (Network
  application 9 and newer) is authenticated by one API key per console, created under *Settings, Control Plane, Integrations*.
  Ubiquiti offers no read-only or scoped key; a key has the permissions of the whole official API, which includes actions such as
  restarting a device. We can only promise that GarnetOps itself sends nothing but reads, and say so plainly.
- **The official API does not expose IPS events.** The console's internal, undocumented API does. It is not versioned, it changed
  between releases, and the only way to use it is a console user with a password and a session cookie.

UniFi is proprietary software of Ubiquiti. GarnetOps only talks to the API over the network; no Ubiquiti code, client library or
binary is part of GarnetOps and no dependency is added (`node:https`, `node:tls` and `node:crypto` only). `docs/COMPONENTS.md`
lists UniFi as an external integration, not as a component.

## Decision

### 1. Local only, strictly read-only, enforced in code

- The connection is a console address (`https://host[:port]`, port 443 by default; plain http, credentials, paths, queries and
  fragments are refused) and an API key. Cloud addresses are not special: the integration needs a console in the customer's
  network, and nothing in the code knows `api.ui.com`. The documentation says that the Site Manager API is never used.
- The official client (`apps/worker/src/unifi-http.ts`, `UnifiClient`) sends **GET only**, to the paths of one allow-list
  (`OFFICIAL_READ_PATHS` in `packages/core/src/unifi.ts`), with the only query parameters `limit` and `offset` as plain integers.
  Anything else throws **before a connection is opened**. No body, no redirects.
- **Endpoints of the official API that are assumed** (the names follow Ubiquiti's published "UniFi Network API" reference for
  Network application 9.x, checked offline from what is known of it; there was no console to test against, see Consequences). `{base}`
  is `/proxy/network/integration` on a UniFi OS console and `/integration` on a self-hosted application:

  | Request | Used for | Fields read (everything else is ignored) |
  | --- | --- | --- |
  | `GET {base}/v1/info` | Is this the API; its version | `applicationVersion` |
  | `GET {base}/v1/sites?limit=200&offset=N` | Sites | `data[].id` (UUID), `internalReference` (the short name the internal API uses, for the preview), `name`; `totalCount` |
  | `GET {base}/v1/sites/{siteId}/devices?limit=200&offset=N` | Devices | `data[].id` (UUID), `name`, `model`, `macAddress`, `ipAddress`, `state`, `firmwareVersion`, `firmwareUpdatable`; `latestFirmwareVersion` if a console sends it (not part of the documented schema) |
  | `GET {base}/v1/sites/{siteId}/devices/{deviceId}/statistics/latest` | Uptime of devices that are online | `uptimeSec` |
  | `GET {base}/v1/sites/{siteId}/clients?limit=1` | The number of clients of a site | `totalCount` only |

  Header `X-API-KEY: <key>`. The sync reads sites and devices in pages of 200 (at most 20 pages). The base path is chosen by the
  admin (UniFi OS console, self-hosted application) or **detected**: with *automatic*, the first sync asks `/proxy/network/integration/v1/info`
  and, if the console answers 404, `/integration/v1/info`; what it found is stored with the connection.
- Never called: devices' `actions`, ports' `actions`, vouchers, hotspot, ACL rules, firewall, networks, WiFi, pending devices,
  the client list itself, and anything with another method than GET.

### 2. The key and who may use it

- The key is sealed in the vault (purpose `unifi-api-key`, bound to organisation, record and purpose, ADR 0004). **The API only
  seals; the worker opens it**, for the seconds a sync runs. It is never returned, logged, written to an error message, the audit
  log or a row in clear.
- Owners and admins configure. Creating a connection, changing its address or key, removing it and confirming a certificate need a
  **recent sign-in** (step-up, ten minutes). Renaming, switching sync on or off and choosing the API path do not. Everyone in the
  organisation reads the devices. Every change is in the audit log (`unifi.*`).
- Because Ubiquiti's key cannot be narrowed (see Context), the dialog and the documentation say it plainly: treat the key like a
  password, revoke it on the console to cut access, and GarnetOps sends reads only. There is no privilege check to run (unlike
  Proxmox, the API does not tell what a key may do).

### 3. Certificate pinning (trust on first use), like Proxmox

- Adding a connection queues a **certificate read**: the worker opens a TLS connection (TLS 1.2 or newer, HTTP/1.1), takes the
  **leaf certificate**, and closes the connection **without sending a request**, so without the key. SHA-256 fingerprint, subject,
  issuer, validity and whether it also verifies against the public CA store are stored as a **candidate**. Nothing is trusted yet.
- An admin compares the fingerprint with the one the console shows and confirms it (**step-up**, audited). The API pins exactly the
  fingerprint that was shown.
- **Every request verifies the pin before the first byte is written** (a custom `https.Agent` finishes the handshake, compares the
  leaf's SHA-256 with the pin, and only then hands over the socket). A certificate that chains to a public CA is still compared.
- A **different certificate blocks the sync**: status `changed`, the new one is kept as the candidate, `unifi.certificate_changed` is
  audited once and owners and admins are told once (`unifi.certificate_changed` in the notification catalogue), the connection is
  dropped before any request, so neither the key nor the IPS password is sent. The worker looks at a blocked connection again at
  every tick (handshake only); if the pinned certificate is back, the alarm clears itself.
- Trade-off, as for Proxmox: a certificate that is **renewed** needs a new confirmation. UniFi OS consoles keep one self-signed
  certificate for years unless an admin installs another; the documentation recommends a long-lived one for this connection.

### 4. SSRF and the network

- The address is checked when saved (`checkHostAddress`: no loopback, link-local including cloud metadata, unspecified, multicast;
  numeric host tricks such as `127.1` refused). The worker **resolves the name itself, checks every answer and connects to the
  checked IP** with the name as SNI and `Host` header. **Private ranges stay allowed**, because consoles live there.
- No redirects (a redirect is an error). Connection and handshake 10 s, every request 20 s, every answer at most 4 MiB (declared or
  streamed), one request at a time with a 25 ms pause, at most 3000 requests and 10 minutes per sync, at most 100 sites per
  console and 2000 devices per connection. Connections come from the worker only; the Compose stack's `egress` network should
  allow only the console's port.

### 5. Hostile input and privacy

- Everything a console sends is parsed by schemas (zod) in `packages/core/src/unifi.ts`: unknown fields are ignored, each list
  entry is validated on its own and dropped if it does not fit (counted as a warning), ids must be UUIDs and site references
  `[A-Za-z0-9_-]{1,64}` before they go into a path, names and models are cleaned of control and bidirectional characters and cut,
  MAC addresses, IP addresses, state words and firmware versions must match a pattern. Everything is stored as text and rendered
  as text (React escapes). An answer that is not a list, or lists no site, **never replaces the stored inventory**; the devices of a
  site that could not be read keep their last known state.
- **Privacy: clients are a number.** The clients list holds people's phones and laptops (names, MAC addresses, addresses). GarnetOps
  asks for one entry (`limit=1`) and reads `totalCount` only. No client name, MAC address or address is read into memory beyond
  the JSON parse, stored, logged or shown (tested with a fixture full of them). Devices (gateway, switches, access points) are
  infrastructure and are stored with name, model, MAC, address, state, firmware and uptime.

### 6. Sync and firmware status

- pg-boss queues `unifi.certificate`, `unifi.sync` and a tick queue. **A tick every 15 minutes** queues a sync for every enabled
  connection with a confirmed certificate, unless a run is waiting or running or one was queued in the last ten minutes. An admin
  can also start a sync (rate limited, audited). One run per connection at a time, claimed atomically; a run older than 15 minutes in
  `running` counts as lost; failures end as a short message from a fixed list (`packages/core/src/unifi-errors.ts`, translated in the
  web app); output of the console is never put into a message.
- **Firmware status is a maintenance hint, never a finding.** The official API says whether a newer firmware exists
  (`firmwareUpdatable`) and, rarely, which one. GarnetOps shows "Update available", "Up to date" or "Not reported". It does **not**
  match network firmware against vulnerability data: grype cannot, there is no package inventory. A device is therefore never called
  *vulnerable*, and the page says so. Offline devices are flagged (state `OFFLINE`, `CONNECTION_INTERRUPTED`, `ISOLATED`);
  devices that are updating or waiting for adoption are not.

### 7. The IPS / threat event preview (optional, off by default, "preview")

#### 7.1 What it uses, and why it is a preview

The internal API of the console is unofficial. The paths below are **assumptions**; the feature is built so that they live in one
file (`packages/core/src/unifi-ips.ts`) and a change is a change of that file:

| Request | Console | Purpose |
| --- | --- | --- |
| `POST /api/auth/login` (JSON `{username, password, remember:false}`) | UniFi OS | Login. The answer sets a cookie (`TOKEN`) and a CSRF token (header `X-CSRF-Token`) |
| `POST /api/login` (same body) | self-hosted application | Login. Cookie `unifises`, CSRF token in the cookie `csrf_token` |
| `GET /proxy/network/api/s/{site}/stat/ips/event?start=<ms>&end=<ms>&_limit=100` | UniFi OS | Events; `{site}` is the site's `internalReference` |
| `GET /api/s/{site}/stat/ips/event?...` | self-hosted application | Same |
| `POST /api/auth/logout` or `POST /api/logout` | both | Logout after every poll |

Fields read from an event (aliases in brackets): the time (`timestamp`, `time`, `ts`, `datetime`), the source address (`src_ip`),
the action (`inner_alert_action`, `action`), the signature (`inner_alert_signature`, `msg`), the category (`inner_alert_category`,
`catname`), the destination **port** (`dest_port`), the protocol (`proto`) and an id (`_id`). The answer may be `{ data: [...] }` or a
plain list. Other endpoints that carry threat data on newer releases (the v2 `traffic-flow` and `system-log` queries) use POST
bodies for their filters, which this client may not send, so they are **not used**; if the legacy GET endpoint disappears, the preview
reports "ipsEndpointMissing" and stops, and the rest of GarnetOps is unaffected.

#### 7.2 The separate, view-only user

- The preview needs its **own local console user** with the *View Only* role. Never an owner or an administrator. The API refuses
  names such as `admin`, `administrator`, `root`, `ubnt`, `ui`, `unifi`, `owner`, `superadmin` (case-insensitive, also as the part before
  an `@`). The user must not use two-factor sign-in (a cookie login cannot).
- The password is sealed in the vault (purpose `unifi-ips-password`); the API only seals it and the worker opens it for the seconds of
  a poll. Switching the preview on, setting or changing the user or password need a recent sign-in and an explicit acknowledgement that
  this is a preview using an unofficial API; every change is audited without the password. Switching off needs no step-up.
- **Rights beyond viewing block the preview until an admin acknowledges exactly that list** (the pattern of ADR 0012 and ADR 0015:
  AGENTS.md rule 1 does not accept a warning for a credential that can do more than we use). Every login answer is parsed into a
  sorted list of labels: `owner` (`isOwner`), `super_admin` (`isSuperAdmin`, `is_super`) and `role: <name>` for every role whose name
  is not recognisably view-only (`view only`, `read only`, `readonly`, `viewer`); an unknown role name therefore counts. If the list
  is not empty and no admin has acknowledged exactly this list, the worker ends the session straight after the login (login and
  logout, no read request), stores the list (`ips_rights`), writes the audit entry `unifi.ips_rights_detected` (user and list) and
  tells owners and admins once (notification title `unifiIpsBlocked`, event `infra.sync_blocked`). While blocked it looks again only
  every ten minutes, so a user that was changed to view-only on the console clears itself without a question.
  Settings → UniFi shows the badge and the list; an owner or admin acknowledges it in a dialog that lists exactly the rights
  (`POST /api/v1/unifi/connections/:id/ips/rights/acknowledge`, owner/admin, step-up, audit entry `unifi.ips_rights_acknowledged`).
  The API refuses a list that differs from the stored one (409 `rights-changed`) and compares again in the update, so an
  acknowledgement never covers rights the admin did not see. The acknowledgement is valid only for the exact list: the worker clears
  it whenever the reported list changes (more, fewer or other rights, including a pass through "none"), and a new user or password,
  re-pointing the console or removing the user clears the list and the acknowledgement as well. The poll starts at once after the
  acknowledgement. The check is best effort and says so: a login answer in a shape we do not know reports no rights, and the
  documentation tells admins to create the user with the view-only role regardless.

#### 7.3 Session handling

- The session cookie and the CSRF token live in an `IpsSession` object in worker memory. They are **never stored**, logged or sent
  anywhere but back to the console, and the object forgets them at logout. Every poll is **login, read, logout**, with the logout
  in a `finally`, so a failed read still ends the session.
- **The only POST requests the client can send are the console's login and logout paths, exactly** (`isIpsRequest`: no query, no
  other path, no other method); the only GET is the events path of a site with numeric `start`, `end` and `_limit`. Anything else
  throws before a socket is opened. The password is only ever in the login body.
- The same pin check as for the official API applies before the first byte of the login, so the password never reaches a console
  with another certificate. Login rate limits (UniFi OS answers 429 after many logins) are an ordinary error with back-off.

#### 7.4 Polling and storage

- The worker looks every 10 s for preview connections that are due and polls each at its own interval: **60 s by default, 30 to 600 s**
  (database check). A **row lease** (`ips_next_poll_at`) makes two workers poll once. Only while healthy: preview on, connection
  enabled, certificate confirmed, a sync has run (the kind of console and the sites are known), user and password present. Errors
  back off (interval times 2^failures, ten minutes at most). The error is stored as a short text of the fixed list.
- A poll reads at most 100 events per site (a response cap of 2 MiB), from the **cursor** (`pollSince`, `nextCursor` of ADR 0021: the
  first poll starts five minutes back, a poll never reaches back more than 15 minutes, the query includes the cursor time and the unique
  `(connection, doc id)` removes duplicates). A console that answers newest first and has more than 100 events in the window loses
  the older ones: the feed is a window, as for Wazuh.
- **What is stored** (`unifi_threat_event`, migration 0020, a sibling of `wazuh_attack_event`): the time, the source address,
  `action` (`blocked` or `alerted`, from the console's own action), the **signature** (200 characters) and **category** (80), the
  **destination port**, the protocol, and the site's name. Signature and category are attacker-influenced text: cleaned of control
  and bidirectional characters, cut, stored and shown as plain text (React escapes), never a link, never Markdown or HTML, and
  **never sent to a model**. **Not stored, not even read into a variable we keep:** the payload or packet, the destination address
  and host (they are internal addresses of the customer's own devices and, for client traffic, can identify a person), the source port,
  user names, URLs. The destination port is kept because "port 22 versus port 443" is what an admin needs to read an attack, and a
  port identifies nothing.
- **Retention** follows the attack overview: events older than the organisation's retention period (default 90 days) are deleted by the
  hourly sweep of ADR 0016, "Delete stored addresses now" deletes them too (the cursor stays, so they do not come back), removing the
  connection deletes them by cascade, and at most **20,000 events per connection** are kept (trimmed in the insert's transaction).
  Source addresses are personal data.
- **The sequence number is shared** with `wazuh_attack_event` (`nextval('wazuh_attack_event_seq_seq')`), so the live stream orders and
  resumes the events of both sources with one number. After the insert the worker runs `NOTIFY` on the organisation's channel in the
  same transaction; the notice carries a sequence number only.

#### 7.5 The attack overview

- Events **join the aggregates** when read: the sources of a period are the Wazuh sources plus the UniFi sources (grouped by address
  from the stored events), merged by canonical address (counts added, groups joined, earliest first seen, latest last seen), then
  enriched with the same local GeoIP tables. The numbers (alerts, distinct sources, the previous period) add up; an address that both
  saw is one distinct source in the list and approximated in the total (the total of distinct sources is Wazuh's figure plus the UniFi
  addresses that are not in Wazuh's list; the page already says its lists cover the busiest 100). The page works with UniFi alone: it
  is shown when a console has the preview on or events are still stored; the Attacks navigation entry follows the same rule.
- **The globe** draws, per country, the observed part as before (orange, or vermilion above an OSINT score of 80) and the part that a
  console blocked as a **dashed steel-blue line** (the colour of the map's scale and of "information", never a severity colour and never
  green: blocking an attack is not proof of anything). Legend: "Observed", and "Blocked by UniFi" when something was blocked. A
  blocked live event draws a dashed live line. Lists show "Blocked by UniFi" as a badge with a word, so colour is never the only signal.
- The AI summary of ADR 0016 also reads aggregated UniFi numbers (section 7.6); signatures and categories never reach a model.
- The live list shows UniFi events with the signature as the title, the address, the country, "Blocked by UniFi" or "Observed", the
  site and the target port. A second status line, "UniFi IPS preview: live — last event 12 s ago", is neutral and always says preview.

#### 7.6 The AI summary includes UniFi counts (numbers only)

Decision (maintainer, 2026-10-22): "Summarise with AI" on the Attacks page (ADR 0016 section 7) now includes the UniFi IPS
events, as **aggregated numbers only**. This replaces the earlier "Wazuh only" boundary of this ADR.

- **What the model receives**, per window (24 hours, 7 days, 30 days), in two separate blocks that are never merged: `wazuh`
  (as before: attack alerts, distinct sources, previous values, alerts and sources per country code and AS number) and `unifi`:
  events, `blocked`, `alerted`, distinct sources, the same four figures for the previous period, events in the listed (busiest
  100) sources, events and sources per **ISO country code** and per **AS number** (each with its blocked and alerted part),
  the events of unlocated and of internal sources. The keys are our own fixed labels; the system prompt says what they mean
  and tells the model not to add the two origins together, because they come from different systems and an address can be in
  both. The UniFi block is present when the organisation has any stored event in the last 60 days; the summary also works
  without a Wazuh connection.
- **Data minimisation statement.** The prompt contains integers, the fixed keys, and country codes that match `^[A-Z]{2}$`.
  It **never** contains: an IP address; a signature or category; an organisation name from the GeoIP data; a console, site,
  device, agent or machine name; a port or protocol; a rule group; any text that came from an event or a data file. Facts are
  built from typed numbers (`packages/core/src/attack-summary.ts`) and copy no field they do not name, so a new column in an
  event cannot leak by accident. The system prompt is fixed text; the data stays between the random markers of ADR 0013 and
  is declared as data, not instructions. A model answer stays untrusted ("AI suggestion", safe Markdown, never executed, never
  able to change a setting or a gate).
- **Tests.** A core unit test builds the context from sources that carry an injection attempt in the signature, category and
  site name and asserts that none of it, and no address, is in the message, and that every string in the data block is a fixed
  key or a country code. A worker test seeds stored UniFi events with a hostile signature and runs the job against a fake model;
  an end-to-end test asks for a summary with UniFi data alone.
- **Data model.** `attack_summary.connection_id` becomes nullable (migration 0021, a relaxing and therefore expand-only change):
  a summary asked for when only the UniFi preview exists belongs to the organisation. Older code that always wrote the column keeps
  working. The audit entry `ai.request` names the origins (`wazuh`, `unifi`), never data.
- **API.** `POST /api/v1/attacks/summary` is accepted when a Wazuh connection or the UniFi preview exists; it answers 409
  `no-data` when neither has stored anything. No field is removed or changed in meaning.

### 8. Notifications (ADR 0019)

Three new events in the catalogue, group Infrastructure, owners and admins, in app and email per the personal matrix, not in the
organisation channels: `unifi.certificate_changed` (once per change, with the audit entry), `unifi.device_offline` (a device must be
offline in **two syncs in a row** (about 15 to 30 minutes), then one message per sync listing the count and the first name; not again
until the device was online), and `unifi.firmware_update_available` (once per device and installed firmware version; one message per
sync). Parameters are the connection name, a device name and a count; nothing else.

### 9. Data model (migration 0020, additive)

`unifi_connection` (connection, sealed key reference, certificate pin and candidate, base path, version, last sync and error, and the
IPS columns: enabled, user, sealed password reference, interval, cursor, lease, last poll/event/error, failures, the reported rights, the acknowledged list and who acknowledged it when),
`unifi_site` (with the client count), `unifi_device`, `unifi_sync_run` and `unifi_threat_event`; secret purposes `unifi-api-key` and
`unifi-ips-password` (text values). Nothing existing changes.

### 10. Web

A **Network devices** tab on Infrastructure → Servers (no new navigation entry): one card per console (version, devices online,
offline, firmware updates, sites, clients as a number, last sync, certificate state, preview badge, warnings of the last run), then the
devices (sortable and filterable by flag, console, site, status and text; more columns at wide and xwide; a detail dialog). Settings →
UniFi (owners and admins) adds, edits and removes consoles, confirms certificates and runs the preview dialog (how to create the view-only
user, the acknowledgement, the interval). Green is not used anywhere: a pinned certificate or a finished sync proves nothing.

## Threat model

| Threat | What an attacker gains | Mitigation |
| --- | --- | --- |
| Stolen API key (database, backup, memory) | With the vault key: the key. With the key: **the whole official local API of the console**, from an address that can reach it. Ubiquiti offers no read-only key, so this includes actions such as restarting devices. | Sealed in the vault, opened by the worker only, never logged or returned; GarnetOps itself can only send allow-listed GETs; the documentation and the dialog say what a key can do; revoking it on the console ends the access without touching GarnetOps. This residual risk cannot be reduced on our side. |
| Over-privileged IPS user | A stolen password could change the console's configuration. | A separate local user with *View Only* is required by the documentation and the dialog; administrator names are refused; the login answer is checked and warns (best effort); the client can only send the login, one read and the logout; the password is sealed and opened by the worker only. |
| Man in the middle on first contact | Receive the key or the password, answer with false inventory or events. | Neither is **ever sent before the certificate is pinned**; the admin compares the fingerprint through another channel and confirms with step-up; audit entry. |
| Man in the middle later, or a replaced console | Same. | Every connection compares the leaf with the pin before any byte of the request; a mismatch drops the connection, marks the connection `changed`, audits and announces it, blocks until an admin confirms. |
| Admin points GarnetOps at internal targets (SSRF, port scanning) | Learn whether a TLS service exists at an address; the key is sent to that address after a pin an admin confirmed. | Loopback, link-local, metadata, unspecified, multicast refused at save and again after DNS resolution in the worker, which connects to the checked IP; no redirects; the response is never shown; only a generic error text; admin-only, step-up, audit. Private addresses are allowed on purpose. |
| Hostile or compromised console answers (JSON, device names, signatures) | Parser bugs, stored XSS, SQL or path injection, memory exhaustion, prompt injection. | zod schemas, unknown fields ignored, per-entry validation, patterns before anything goes into a path, size caps (4 MiB, 2 MiB for events), control and bidi characters stripped, stored as text and rendered escaped, signatures never a link and never sent to a model; a broken answer cannot empty the inventory; tests with hostile fixtures. |
| Personal data of clients | Names, MAC addresses and addresses of people's devices in the database or in logs. | Clients are read as a **number only** (`limit=1`, `totalCount`); tested with a fixture full of client data; the preview stores no destination address. |
| Personal data in threat events (source addresses) kept too long or shown to the wrong people | GDPR exposure, disclosure across tenants. | Retention period of the attack overview, a cap of 20,000 per connection, erasure on demand, organisation scoping on every read, a channel per organisation, notices without content, the audit log holds counts only. |
| Session theft in the worker (cookie, CSRF token) | Act as the view-only user for a while. | Held in memory for the seconds of a poll, never stored or logged, forgotten at logout; the session belongs to a view-only user. |
| Denial of service of the console by GarnetOps | Slow or unavailable web interface or gateway. | One request at a time, 25 ms pause, timeouts, a request budget and a time budget per sync, 15 minute interval, `retryLimit: 0`; the preview polls at most every 30 s, with back-off on every error and a login/logout per poll that UniFi OS may rate limit (429 is an ordinary error). |
| Denial of service of GarnetOps by a console | Worker memory or time. | Response caps, timeouts, caps on counts, bounded writes in one transaction, a row lease against double polling. |
| Instability of the unofficial API | Silent wrong data, or a feature that breaks after a console update. | Marked preview in the interface and the documentation; one file holds the assumptions; the parser rejects shapes it does not know (the poll fails with a short code instead of storing nothing silently); the rest of GarnetOps does not depend on it. |
| The IPS user has more than viewing rights (wrong role, or the role changed later) | A stolen password would not be limited to reading events. | The login answer is parsed into a rights list; with any right beyond viewing the worker logs out without reading anything until an owner or admin acknowledges exactly that list (step-up, audit); the acknowledgement is void when the reported list changes; best effort where the console does not report rights, hence the documented view-only role. |
| A member without rights changes connections | Re-point, remove, pin a certificate, switch the preview on. | Role checks on every write, step-up for sensitive ones, organisation scoping on every query, audit log. |
| Device or site names carry prompt injection | Manipulated AI triage later. | Not used by AI; console text is untrusted input wherever AI reads it (AGENTS.md rule 1). |
| Event text (signature, category, site) tries to talk to the AI summary | Manipulated summary, leaked context. | Only counts, fixed keys and country codes are built into the prompt (section 7.6); the text fields are never read by the summary job; tested with injection text in every field; the answer is untrusted text. |

## Consequences

- GarnetOps shows the network layer next to the servers without an agent or any write access of its own; the price is one API key
  (whose scope Ubiquiti fixes), port 443 from the worker, and a confirmation whenever the certificate changes.
- **Not tested against a real console.** The official endpoints and the unofficial ones are assumptions checked against Ubiquiti's
  documentation and public knowledge of the internal API, and exercised with a local HTTPS server that replays synthetic answers. The
  field names, the login answer, the CSRF handling and the events endpoint can differ per UniFi OS or Network application version.
  The first tests on a real console may need small changes to the parsers; they are confined to `packages/core/src/unifi*.ts`.
- Migration 0020 is additive: tables, one sequence default, two secret purposes. Rollback is not needed; the preview and the sync
  are off until an admin configures them. The migration needs the sequence of migration 0019 (`wazuh_attack_event_seq_seq`); a later
  contract step that replaces `wazuh_attack_event` must keep the sequence.
- Out of scope, on the roadmap: reading firmware release notes or versions from the cloud (never), restarting or upgrading devices
  (never), per-port or per-client views, WiFi and traffic statistics, the v2 threat endpoints (POST), public-key pinning for renewing
  certificates, a real-console test.
