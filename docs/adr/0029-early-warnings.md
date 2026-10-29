# ADR 0029: Early warnings from the local vulnerability database

- Status: accepted (2026-10-29), implemented in 0.0.10
- Date: 2026-10-29
- Decided by: maintainer (match the stored inventories against each new local database; no new outbound service)
- Builds on: ADR 0002 (scanning with grype and syft), ADR 0010 (notifications), ADR 0024 (system status), ADR 0028 (scanner
  isolation), AGENTS.md rules 1 (security first, air-gap capable) and 2 (gate behaviour never changes silently)

## Context

A repository is scanned nightly or on demand. Between two scans, the daily update of the vulnerability database can bring an
advisory for a package the repository already uses. Today nobody hears of it until the next scan, and a repository that is
scanned rarely can carry a known vulnerability for days.

Every successful scan with syft stores the repository's full package inventory (`repository_package`), including each package
URL (purl). grype can match a list of package URLs directly (`grype purl:<file>`), without a clone.

## Decision

1. **When.** The worker checks after every probe of the vulnerability database (every 15 minutes, ADR 0024), but only once per
   database build: a new build, whether from the automatic update or a manual import on an air-gapped host, starts one check.
   The build the last check used is kept in `system_report` (`early_warning`).
2. **How.** The distinct package URLs of all stored inventories (at most 100,000) go to grype as one list. With the scanner
   service (ADR 0028) grype runs there (`POST /v1/match-purls`, the list validated line by line: `pkg:` and printable ASCII
   only); without it, in the worker. No clone, no network, no credential is involved.
3. **What counts as new.** A match becomes an early warning only when both hold:
   - the repository has no finding for that advisory and package, in any state, and
   - the advisory was published or changed after the build of the database its last scan used.
   The second rule keeps out matches a package URL finds and a full SBOM does not (or the other way round) for advisories the
   last scan already had: only what the new database brought is reported.
4. **Not a finding.** Early warnings live in their own table (`early_warning`). They never change findings, grades, statistics or
   quality gates (rule 2). The next successful scan of the repository's branch closes each open one as *confirmed* (the scan
   found it, it is now a finding) or *cleared* (it did not). Closed ones stay visible for 30 days.
5. **Where it shows.** **Daily → Early warnings** lists the open ones worst first (and the closed ones of the last 30 days) for
   every member; members and above can start the confirming scan from there. `GET /api/v1/early-warnings` returns the same.
   Notification channels can subscribe to the event `advisory.new` (one message per repository, counts per severity), which
   follows the channel's minimum severity and repositories (ADR 0010 amendment).

## Threat model

| Threat | Mitigation |
| --- | --- |
| A stored package URL (from a scanned, hostile repository) is crafted to inject options or another input into grype | Every line must start with `pkg:`, consist of printable ASCII without spaces and be at most 1,000 characters; the list is written to a file grype reads as `purl:<file>`, never passed as arguments. |
| A compromised scanner answers with crafted matches | Same as for scans: the answer is size-capped and parsed with schemas; a forged answer can at worst add or hide early warnings, which a scan then confirms or clears. |
| Early warnings change what a pipeline sees | They are not findings: gates, grades and statistics read findings only. |
| A flood of notifications | One message per repository per database build, and only for warnings that are new; channels choose the minimum severity and repositories. |
| Data leaves the network | Nothing new goes out: the database is the local one, and messages carry counts and a link only. |

## Consequences

- New table `early_warning` (additive migration 0026) and the report key `early_warning`.
- New scanner service endpoint `POST /v1/match-purls`; a scanner service of 0.0.9 does not have it, so the check then fails and is
  logged until the scanner service runs the same release as the worker (the update sidecar updates both).
- Repositories scanned without syft have no package URLs and get no early warnings.
