# System status

**Admin → System status** answers one question: is everything current and running? It is read-only, for owners and admins, and
refreshes every minute while it is open (the button "Refresh now" asks at once). The design and its threat model are in
[ADR 0024](adr/0024-system-status-page.md).

Nothing on this page changes anything. It reports what the worker and the integrations have written into the database; the API never
runs a scanner and never contacts an integration to answer it.

## How to read a row

Every row has an icon and a word, so colour is never the only signal.

| Icon | Meaning |
| --- | --- |
| Grey check | As expected. This is deliberately not green: GarnetOps reserves green for proof (a gate that passed). A worker that runs or a database that is current proves nothing about your code. |
| Amber triangle | Needs a look: stale, blocked, waiting for a first result, a version that differs. |
| Vermilion octagon | Failed. |
| Dashed circle | Not active: not configured, paused or planned. These rows do not count in the summary. |

The summary at the top counts the rows that need a look and the rows that failed.

## Scanners

The versions of **grype** and **syft** as the worker reports them. The worker runs `grype version` and `syft version` when it starts and
refreshes the entry from the output of every successful scan. Each row shows whether the version is the one this release pins
(`scripts/fetch-scanners.mjs` downloads exactly that version and checks its SHA-256). A different version still scans, but this release
was not tested with it. Without syft, scans list only vulnerable packages, not the full package inventory.

The row **Isolation** says where syft and grype run ([ADR 0028](adr/0028-scanner-isolation.md)):

| State | Meaning |
| --- | --- |
| Isolated | They run in the scanner service: no network, no vault key, no database, the clones read-only. |
| In the worker | The installation still uses a `docker-compose.yml` older than 0.0.9, so they run inside the worker, next to the vault key. Scans work; download the Compose file and `updater.yaml` of your release to isolate them ([Updating](updating.md#scanner-service-from-009)). Needs a look. |
| Other release | The scanner service runs another release than the worker: it was left out of an update, usually because `updater.yaml` is older than 0.0.9. Needs a look. |
| Not answering | The scanner service does not answer its health check, so every scan fails. Check it with `docker compose ps` and `docker compose logs scanner`. Failed. |

The worker checks this when it starts, every 15 minutes and whenever a scan cannot reach the service.

## Vulnerability database

| Field | Meaning |
| --- | --- |
| Built | When the database was built, and how old it is. |
| Schema version | The database's own schema version. |
| Source | *Anchore's published database* (automatic updates are on), *imported by hand* (they are off), later *built by GarnetOps*. |
| Last read | When the worker last read the database's metadata (at start, after every update and every 15 minutes). |
| Last update | The result of the worker's last `grype db update`: *worked* or *failed* with a short reason (the download did not work, took too long, failed its integrity check, could not be stored, grype could not be started). The tool's own output is never kept. |
| Next update | One day after the last attempt. With `GARNETOPS_GRYPE_DB_UPDATE=off` the page says that automatic updates are off. |
| Providers | The feeds in the database (NVD, GitHub, a distribution, ...), the date of their data, and the number of advisories per provider. |

**Limits** (constants in `packages/core/src/system-status.ts`):

| Age | State |
| --- | --- |
| up to 3 days | current |
| more than 3 days | **stale** (amber) |
| more than 7 days | **outdated** (vermilion) |

Anchore publishes a database every day. **Scanning with a stale or outdated database stays allowed**; the page says that scans cannot
find advisories published after the build. If the update keeps failing, check that the worker can reach the internet (or your proxy:
`HTTPS_PROXY` and `NO_PROXY` apply), or import a database by hand as the [installation guide](installation.md) describes. A missing or
invalid database fails the row: no scan can run.

**Advisory counts.** grype has no command that prints record counts. The worker counts the advisories per provider with one read-only
`select` over the database file, once per database. If that does not work with a future database layout, the providers are listed
without counts and the page says so; nothing else depends on it.

## Local database build (vunnel and grype-db)

Shows **Not set up (planned)** with a link to the roadmap. GarnetOps does not build its own vulnerability database yet. When the builder
exists it reports, per provider, the last run, the result, the number of records and the duration, and this row turns into that table.
The report's shape is fixed now so that the builder can arrive without a breaking change (see below).

## Integrations

One row for each of the directory sign-in, the AI endpoint and the notification channels:
whether it is configured, when it last worked, the last attempt and its result, and what blocks it. A link leads to its settings
(the directory settings are for owners).

| State | Meaning |
| --- | --- |
| Not configured | Nothing is set up. |
| Paused | An admin switched it off (or paused it). Not counted. |
| Blocked | Nothing happens until an admin acts: a certificate of a directory server waits for confirmation or changed, the directory refused the service account, an external AI endpoint was not acknowledged. |
| Failed | The last attempt failed. The reason is shown in your language. |
| Stale | The last success is older than three of its own intervals (15 minutes for the directory check). |
| Waiting for a first result | Set up, but no attempt has finished yet. |
| Current | The last attempt worked and is recent. |

Parts: the directory has the *account check* (every 15 minutes, with the number of accounts checked); the AI endpoint the last *connection
test* and where the endpoint is (inside or outside your network); the notification channels their last *delivery*. For several channels
the worst state stands for the row and up to five that need a look are named.

The rows of Wazuh (XDR), Proxmox VE, UniFi, external exposure and the GeoIP data existed up to version 0.0.3 and were removed in 0.0.4
([ADR 0025](adr/0025-focus-on-the-developer-pipeline.md)).

## Worker and jobs

- **Worker:** running, late (no heartbeat for 90 seconds) or not running. It writes its heartbeat, with its version and start time, every
  30 seconds, and removes it when it stops cleanly. If it is late or not running, scans and checks wait. Check `docker compose
  logs worker`.
- **Nightly scan:** the schedule, the last run (how many repositories were queued and how those scans ended) and the next run. On the two
  days a year when the local time is skipped or read twice (daylight saving time, [ADR 0005](adr/0005-time-and-time-zones.md)) the next
  run shown can be an hour off.
- **Database:** its size and whether every migration this build ships is applied.
- **Queues:** per queue the waiting jobs, the running jobs, the jobs that failed in the last 24 hours and how long the oldest waiting job
  has waited (over 15 minutes needs a look). The numbers are read with SQL from pg-boss's tables; if they cannot be read the page says so.

## Application

The running version (for example "0.0.13 Alpha") and, if the [update service](updating.md) is set up, its phase (nothing scheduled, an
update scheduled, running, the last one worked or failed) and the newest release it knows. Without the service the page says that
updates are done by hand.

## API

`GET /api/v1/system/status` (owners and admins; 403 for everyone else; `Cache-Control: no-store`). The answer has the keys `generatedAt`,
`refreshSeconds`, `overall`, `app`, `scanners`, `vulnDb`, `localBuild`, `integrations` and `worker`. It contains numbers,
states and short codes only: no secret, no address of an integration and no output of a tool. Fields are added over time and never
change their meaning (within `/api/v1`). The type is `SystemStatus` in `packages/core/src/system-status-view.ts`.

## For the builder: the report shape

The local builder will write one JSON document into `system_report` under the key `vulndb_build`:

```json
{
  "v": 1,
  "enabled": true,
  "lastBuildAt": "2026-10-23T03:10:00Z",
  "providers": [
    { "name": "nvd", "lastRunAt": "2026-10-23T03:02:00Z", "result": "ok", "records": 250000, "durationMs": 420000, "reason": null }
  ]
}
```

`result` is `ok`, `failed` or `skipped`; `reason` is a short code (at most 60 characters), never output of a feed, a URL or a token.
Readers ignore fields they do not know, and `v` counts versions of the shape, so new fields can be added without breaking the page.
