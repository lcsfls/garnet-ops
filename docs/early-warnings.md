# Early warnings

**Daily → Early warnings** answers one question between two scans: does a new advisory affect a package a repository
already uses? ([ADR 0029](adr/0029-early-warnings.md))

## How it works

After every update of the local vulnerability database (automatic, or imported by hand on an air-gapped host), GarnetOps
matches the stored package lists of all repositories against the new database. It does not clone anything and does not
contact anything outside your network; it uses the package inventory of each repository's last scan.

A match is listed as an early warning when the repository has no finding for it yet and the advisory was published or
changed after the database of the repository's last scan. The check runs once per database build, about a quarter of an hour
after the new database arrived.

## What an early warning is, and is not

An early warning is not a finding. It does not change findings, grades, statistics or quality gates, so a pipeline that
passed yesterday is not affected by it. It tells you to look: scan the repository (**Scan to confirm**, members and above),
and the scan closes every open early warning of that repository:

| Outcome | Meaning |
| --- | --- |
| Confirmed by a scan | The scan found the same advisory in the same package; it is now a finding. |
| Not found by the scan | The full scan, which also knows where each package comes from, did not match it; nothing to do. |

**Show → Closed (30 days)** lists what scans closed in the last 30 days.

## Notifications

A notification channel (Settings → Notifications) can subscribe to **Early warnings: new advisories for stored packages**.
It gets one message per repository with the number of new early warnings per severity, from the channel's minimum severity
on and only for the channel's repositories ([notifications](notifications.md#filters-per-channel)).

## Limits

- Only repositories scanned with syft (the default in the images) have a package list; without one there are no early
  warnings.
- At most 100,000 distinct packages are checked per database build.
- With the scanner service (0.0.9 and later), the check runs there, like a scan.

## API

`GET /api/v1/early-warnings?state=open|closed&repositoryId=<id>` returns the early warnings of the signed-in organisation:
open ones worst first, closed ones of the last 30 days newest first, at most 500 (`truncated` says when there are more).
