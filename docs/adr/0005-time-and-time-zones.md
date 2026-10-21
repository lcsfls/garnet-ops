# ADR 0005: Time and time zones

- Status: accepted
- Date: 2026-10-21
- Decided by: maintainer
- Prompted by: daylight-saving bugs reported in other AI-assisted projects
  (jobs stuck after the clock goes back, mails sent twice, hash chains broken
  by a timestamp earlier than its predecessor)

## Context

Customers run GarnetOps in many zones, mostly Europe/Berlin and its
neighbours. Twice a year a local hour is skipped (spring) or repeated
(autumn). Code that stores local times, adds days as 24 hours, or compares
clocks of different machines fails on exactly those nights, which is when
nightly scans and digests run.

## Decision

1. **Instants are UTC.** Every point in time is stored as `timestamptz` and
   handled as a UTC instant (JavaScript `Date`, ISO 8601 with `Z` in the API).
   Local wall-clock times are never stored.
2. **Database sessions run in UTC** (`TimeZone=UTC` on every connection), so
   SQL like `::date` or `current_date` never depends on the server's zone.
   SQL `date` values reach JavaScript as `"YYYY-MM-DD"` strings.
3. **A user's calendar days are computed explicitly** with an IANA zone name
   (`AT TIME ZONE 'Europe/Berlin'` in SQL, the browser's zone in the web app).
   Days are added on the calendar, never as multiples of 24 hours. A day the
   user picks ("accepted until 19 January") means the whole of that local
   day and is sent to the API as the exact end instant.
4. **One clock decides.** Deadlines, leases and "stuck job" checks compare
   times taken from the same clock, the database's `now()`, never a worker's
   clock against a stored database time. Elapsed time inside a process uses
   a monotonic clock (`performance.now()`), not the wall clock.
5. **Order is not time.** Anything that must be strictly ordered (the audit
   log, a future hash chain over it) is ordered by a sequence number. The
   timestamp is metadata and may repeat or go backwards.
6. **Schedules carry a zone and a de-duplication key.** Recurring jobs
   (nightly scans, weekly digests) are scheduled either in UTC or with an
   explicit IANA zone, and each run has a key derived from its intended local
   date, so a repeated autumn hour cannot send a mail or start a scan twice
   and a skipped spring hour cannot drop it.
7. **Tests use fixed instants around real transitions** (Europe/Berlin
   2026-03-29 and 2026-10-25, plus a zone whose midnight is skipped such as
   America/Santiago), pin the zone per test (`process.env.TZ` in Node,
   `AT TIME ZONE` in SQL), and never depend on the machine's own zone.

## Consequences

- Implemented now: points 1 to 4 and 7 (`packages/db` session and date
  parsing, `openFindingsTrend`, `apps/web/src/lib/dates.ts`, the worker's
  stale-scan check), with tests in `packages/db/src/time.test.ts` and
  `apps/web/src/lib/dates.test.ts`.
- Points 5 and 6 apply when the audit hash chain, scan scheduling and mail
  digests are built; their roadmap items reference this ADR.
- The native date input shows dates in the browser's format and zone, which
  matches point 3.
