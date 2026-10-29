# ADR 0024: System status page

> **Status: partly superseded by ADR 0025.** The rows of the removed modules (GeoIP, Wazuh, Proxmox VE, UniFi, external exposure) are superseded by ADR 0025 (removed in 0.0.4). The page keeps scanners, the vulnerability database, the local build, the directory, AI and notification channels, the worker and the application.

- Status: accepted (2026-10-23); partly superseded by ADR 0025 (removed in 0.0.4)
- Date: 2026-10-23
- Decided by: maintainer (one read-only place that answers "is everything current and running?")
- Builds on: ADR 0005 (time and time zones), ADR 0007 (updates), ADR 0012, 0015, 0020, 0022 and 0023 (the integrations), ADR 0013 (AI
  endpoint), ADR 0016 (GeoIP), AGENTS.md rules 1, 2, 5, 6 and 7

## Context

A sysadmin who relies on GarnetOps has one question before every other: is it working, and is what it tells me current? The answer was
spread over many places. The overview showed the build time of the vulnerability database of the last scan, Settings showed the state of
each integration, the audit log showed what happened, and "is the worker alive?" could only be told by noticing that nothing moved.

Three facts make this more than a list of timestamps:

- **Old data fails silently.** A vulnerability database that is a week old still scans and still finds things. The missing findings are
  the ones nobody sees. A security product must say loudly that it is working on old data.
- **The API cannot see most of it.** Scanner versions come from binaries only the worker runs, the database file sits in the worker's
  volume, and the integrations are synced by the worker. The API must stay a thin reader (ADR 0004: the worker is the only process that
  touches remote systems and tools).
- **Colour cannot carry the message.** AGENTS.md rule 6: green means proof. A worker that is running or a database that is current proves
  nothing about the user's code, so the page has no green, and no state is shown by colour alone.

## Decision

### 1. What is shown

One page, **Admin → System status**, for owners and admins, and one endpoint, `GET /api/v1/system/status`, for the same people. It is
read-only: it changes nothing and has no button that does (the one button reads again). Sections:

| Section | Facts | Source |
| --- | --- | --- |
| Scanners | grype and syft version, whether it equals the version this release pins, when it was reported | worker report `scanners` |
| Vulnerability database | build time and age, schema version, source (Anchore's published database, imported by hand, later: local build), last read, last update attempt with result and a short code, next scheduled update, providers with advisory counts | worker reports `vulndb` and `vulndb_update` |
| Local database build | "not set up (planned)" with a link to the roadmap, until a builder reports per provider | worker report `vulndb_build` |
| GeoIP | per dataset (country, ASN): release month, age, rows, source (import or monthly download), the last refused load, the last download attempt | `geoip_dataset`, `attack_settings` |
| Integrations | Wazuh (sync and live feed), Proxmox VE, UniFi (sync and IPS preview), directory sign-in (last account check), external exposure (stage 1, stage 2, proof of control), AI endpoint (last connection test, scope), notification channels (last delivery): configured or not, last success, last attempt and its result, and what blocks it | the integrations' own columns and run tables |
| Worker and jobs | heartbeat with version and start time, per queue the waiting, running and failed-in-24-hours counts and the wait of the oldest job, the last nightly run and the next one, database size and migration state | `worker_heartbeat`, pg-boss tables, `scan_schedule_run`, `pg_database_size`, the migration table |
| Application | the running version ("0.0.9 Alpha"), the update service's phase and the newest release it knows | the update sidecar, if one is set up |

The vulnerability data card of the overview gets a small badge with the age state and, for admins, a link here. The badge is computed in
the browser from the build time the overview already has, with the same limits.

### 2. Thresholds and states

Constants in `packages/core/src/system-status.ts`, documented in `docs/system-status.md` and tested:

| What | Amber ("stale") | Vermilion ("outdated" / failed) | Why |
| --- | --- | --- | --- |
| Vulnerability database | older than 3 days | older than 7 days | Anchore publishes a database every day. Three days is two missed updates; a week is a gap an attacker could have used. |
| GeoIP dataset | older than 45 days | older than 90 days | DB-IP publishes monthly and the dataset's date is the first of its month. 45 days means a month was skipped. |
| Worker heartbeat | no beat for 90 seconds | no beat at all | It beats every 30 seconds; 90 is three missed beats. |
| A sync | no success for 3 of its own intervals | the last attempt failed | Proxmox, UniFi, Wazuh and the directory check run every 15 minutes, the exposure runs daily. |
| A queue | a job failed in the last 24 hours, or the oldest ready job waited over 15 minutes | – | |

**Scanning with a stale or outdated database stays allowed.** The page says so ("scans keep running, but they cannot find advisories
published after the build"). Blocking scans would be a quality gate change nobody opted into (rule 2) and would turn a network outage
into a second outage.

Every row is one of four **levels**, each with its own icon and always a word: *as expected* (grey check, never green), *needs a look*
(amber triangle), *failed* (vermilion octagon) and *not active* (dashed circle: not configured, paused, planned). The integration states
are `not configured`, `paused`, `blocked`, `failed`, `stale`, `waiting` and `current`; `blocked` (a certificate that waits for an admin,
a privilege nobody acknowledged, a refused service account, a lost proof of control, an external AI endpoint nobody acknowledged)
outranks `failed`, because nothing happens until an admin acts. For several connections the worst state stands for the row and up to five
connections that need a look are named (the labels an admin gave them, which Settings shows to admins as well).

### 3. How the facts get here

- **The API never runs a binary and never talks to the worker or to an integration.** It reads the database. This keeps the API's
  privileges as small as they were and means a hostile integration cannot influence it through this page.
- **The worker reports.** New additive tables (migration 0023): `worker_heartbeat` (one row per worker process: version, start time,
  beat time, rewritten every 30 seconds, removed on a clean stop, rows of workers that stopped long ago are removed at the next start) and
  `system_report` (one JSON document per key: `scanners`, `vulndb`, `vulndb_update`, `vulndb_build`). Every document has a schema in
  `packages/core/src/system-status.ts`; the API validates it on every read and treats a damaged or unknown document as "not reported".
- **Scanner versions:** the worker runs `grype version` and `syft version` when it starts, and every successful scan refreshes the
  entry from the version the scan's own output names. The pinned versions are constants next to the thresholds; a test compares them
  with `scripts/fetch-scanners.mjs`, which downloads and checksum-verifies exactly those versions. A different version is shown as
  "differs from pinned", never refused.
- **The database:** `grype db status -o json` and `grype db providers -o json` (both local, neither touches the network; the field names
  were checked against the pinned binary, `db status` was also run offline against an empty cache directory) give schema, build time, validity and the providers. grype exposes **no record counts**, so the
  counts per provider are a `select provider_id, count(*)` over the database file opened **read-only**, once per database. If that fails
  the providers are listed without counts and the page says so. The worker reads the metadata at start, after every update and every 15
  minutes, so a database imported by hand shows up without a restart.
- **The update:** the worker's daily update records its attempt time, result and a **short code** (`network`, `timeout`, `checksum`,
  `storage`, `not_started`, `failed`), mapped from the error; nothing the tool printed is stored. The next update is the attempt plus 24
  hours. With `GARNETOPS_GRYPE_DB_UPDATE=off` the page says "automatic updates are off" and the source is "imported by hand".
- **Integrations:** the existing columns (`last_sync_at`, `last_error`, run tables, certificate status, acknowledged privileges, live and
  IPS poll columns, exposure runs) plus three small additive columns that did not exist: `ldap_config.last_reconcile_*` (the directory
  check wrote nothing) and `ai_settings.last_probe_*` (probe rows are swept after an hour). Error texts keep going through the same
  translators as the settings pages.
- **Queues:** SQL over pg-boss's tables, using only `queue.name`, `job.name`, `job.state`, `job.start_after` and `job.completed_on`,
  which are in the schema of every pg-boss release we know (10 to 12; this release uses 12). pg-boss's own counters are updated by a maintenance pass and know neither the last 24 hours
  nor the wait of the oldest job. If a future pg-boss changes those tables the query fails and the page says "not available" instead of
  guessing; a test runs it against a real pg-boss schema, so the upgrade that breaks it also breaks the build.
- **Nightly scan:** the last run (`scan_schedule_run`) with the outcome of the scans it queued, and the next one computed by the database
  in the organisation's zone (ADR 0005). On the two days a year when the local time is skipped or read twice the answer can be an hour
  off the real run; the page shows the time to the minute and the docs say so.

### 4. The local build (vunnel and grype-db)

Today GarnetOps uses Anchore's published database. The ROADMAP plans a build with vunnel and grype-db. The page has a row for it that
says **"Not set up (planned)"** and links to the roadmap. The report the builder will write is part of this ADR, so it can arrive without
a breaking change:

```json
{
  "v": 1,
  "enabled": true,
  "lastBuildAt": "2026-10-23T03:10:00Z",
  "providers": [
    { "name": "nvd", "lastRunAt": "2026-10-23T03:02:00Z", "result": "ok", "records": 250000, "durationMs": 420000, "reason": null },
    { "name": "debian", "lastRunAt": "2026-10-23T03:05:00Z", "result": "failed", "records": null, "durationMs": 900, "reason": "network" }
  ]
}
```

stored as `system_report` with key `vulndb_build`. `v` is the version of the shape; **readers ignore fields they do not know and new
fields are only ever added**. `result` is `ok`, `failed` or `skipped`; `reason` is a short code, never the feed's output, a URL or a
token. The page shows nothing else about the builder, so a feed's text can never reach it.

### 5. The page

- Owners and admins only, in the **Admin** group of the navigation, and in the command search ("Go to System status").
- One column of reading width (72 rem) at the base step (content below 1450 px), **two columns from wide** (1450 px) and **three from
  xwide** (1900 px), measured on the content area with container queries (rule 5). A card is never split between columns. Layout checks
  at 1100, 1280, 1536, 1920 and 2560 px, in English and German.
- It asks again every 60 seconds while it is visible (TanStack Query pauses the interval in a hidden tab) and has a button that asks now.
- Every row has a word and an icon; times are relative with the exact time on hover (ADR 0005: shown in the user's zone).
- The text of every reason comes from a list in the user's language: stored codes and the existing translators, never a remote text. A
  value this version does not know is shown as it is, which is a code or an already user-safe sentence of the worker.

### 6. What is not built

Alerting on these states (a notification when the worker stops) is the next step and will use the notification catalogue of ADR 0019;
it needs a decision about noise and is not part of this page. History and graphs, a button that repairs something, and any write action
are out of scope. So is a check of anything outside the installation (is Anchore reachable?): the page reports what the installation
did, not what the internet does.

## Threat model

**Assets:** the integrations' and the installation's internal facts: what is connected, what is blocked, which versions run. These help
an attacker who already has an admin's session little, and a viewer's session not at all.

| Threat | Control |
| --- | --- |
| A member or viewer reads the installation's inner state | `requireRole(admin)` on the endpoint, the route redirects, the navigation hides the entry. API tests for all four roles. |
| The page leaks a secret, an address or a fingerprint | The view is built from numbers, states and codes. Connection names are the admin's own labels. A test seeds an address, a fingerprint, a token ID and a mailbox and asserts none of them is in the answer; an e2e test does the same for the rendered page. |
| A tool's output or a remote text reaches the page (stored XSS, log injection) | The worker stores codes and versions, never output. The versions are matched against a strict pattern, update failures become one of six codes, the providers' names are cut and shown as text. Remote error texts are the ones the settings pages already show (fixed English sentences chosen from a list by the worker). React escapes everything. |
| A hostile database file or a hostile integration makes the status page expensive | The API only reads small rows; the queue query is an aggregate over live jobs only. The worker counts records on a read-only handle, once per database, and a failure only means "no counts". |
| A damaged report breaks the page | Reports are validated on every read; a bad one means "not reported". |
| The worker's report is forged | Only the worker's database role writes it, as for every other worker-owned table. Nothing on the page triggers an action, so a forged report can mislead but not act. |
| Polling hammers the server | 60 seconds per open page, `no-store`, no fan-out to integrations (everything is already in the database). |
| The page hides trouble | A missing report is "not reported yet" and counts as needing a look; a worker without heartbeat is red; an unreadable queue table is amber. The overall verdict counts every row that needs a look or has failed. |

## Consequences

- Migration 0023 is additive (two tables, seven columns); nothing is renamed or removed (rule 2). The endpoint is new; fields may be
  added later and are never changed in meaning.
- The worker does a little more at start (two version calls) and every 15 minutes (one `grype db status`), and writes a heartbeat row
  every 30 seconds.
- The pinned scanner versions now live in two places that a test keeps equal.
- The page is the natural home for the later alerting and for the builder's report.

## Alternatives considered

- **The API runs `grype version` itself.** Rejected: the API image would need the binaries and the permission to run them, for a
  convenience; and it would report what the API's container has, not what the worker runs.
- **pg-boss's `getQueues()` and `getQueueStats()`.** They work, but their numbers are written by a maintenance pass (stale by
  minutes), and they have no "failed in 24 hours" or "oldest waiting job". Used where possible would have meant two ways to read the
  same thing.
- **Blocking scans with an outdated database.** Rejected (see above): a behaviour change for a gate nobody asked to tighten.
- **A health page for the public (no sign-in).** Rejected: the versions and the list of integrations are information an attacker would
  like (the same reasoning as the version on `/api/healthz`, ADR 0007).
