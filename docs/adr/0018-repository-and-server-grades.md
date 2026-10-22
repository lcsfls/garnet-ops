# ADR 0018: Repository and server grades

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (the rules A to F below; a grade is display only)
- Implements: a grade per repository and per server on the lists and detail pages
- Builds on: ADR 0008 (quality gates: gate behaviour never changes silently), ADR 0011 (servers)

## Context

The repositories and servers lists show open findings per severity. A busy sysadmin with forty repositories wants
one answer first: which ones do I look at today? A count of findings does not give it (one critical with a fix
matters more than fifty lows), and a score such as "73 out of 100" suggests a precision the data does not have
(AGENTS.md rule 6: no fake precision). The maintainer decided on a letter from A to F with fixed, explainable
rules.

## Decision

### The rules

Only **open** findings count. The worst matching rule wins. "With a fix" means the finding has at least one fixed
version.

| Grade | A repository or server gets it when it has at least one open finding that is... |
| --- | --- |
| F | a known exploited vulnerability (CISA KEV) with a fix |
| E | a critical with a fix |
| D | a high with a fix, or a critical without a fix |
| C | a medium with a fix, or a high without a fix |
| B | anything else: only low findings, or only findings without a fix that are not covered above |
| A | no open findings |

Notes that follow from the table:

- A KEV vulnerability **without** a fix is graded by its severity only (critical: D, high: C, medium and lower: B).
- Severity is the finding's own severity (the same as in the lists and in ADR 0008's "critical"), not a CVSS
  threshold. Negligible and unknown severities fall under B.
- With two rules at the same grade the one **with a fix** is named as the reason (`high-with-fix` before
  `critical-without-fix`, `medium-with-fix` before `high-without-fix`), because that is what a person can act on.

### What "open" means

- **Repositories:** `state = open`, plus **accepted risks whose acceptance has run out** (`accepted_until` in the
  past). The nightly scan reopens those only at its next run; the grade does not wait for it, it is computed at
  query time. An acceptance without an end date does not expire, as in the gate evaluation. Accepted risks with a
  valid acceptance and resolved findings never count.
- **Servers:** `state = open` (server findings have no accepted state).

### No grade, and a failed run

- A repository that was **never scanned successfully** (`last_scan_id` is empty), and a server that was **never
  inventoried successfully**, has **no grade** (`grade: null`), shown as "not scanned" / "not read yet". It is not
  an A: nothing is known.
- If the **latest scan or inventory failed** but an earlier one succeeded, the findings of that earlier run are
  still what GarnetOps knows, so the grade of the last successful run is shown with a **stale** hint
  (`gradeStale: true`: a clock next to the letter and a sentence in the note). The failure itself is shown as before
  (Failed badge, error text). Checks of other refs (pull requests) never make a repository stale, as they are not
  the repository's own state.

### Display only

**A grade never changes anything.** It is not an input to gate rules, notifications, alerts, scan schedules, AI
triage, fix proposals or exports. Gate results come from ADR 0008 alone. The UI and the documentation say so, in
the grade note and in the help ("How grades work").

### API (additive only, AGENTS.md rule 2)

`GET /api/v1/repositories`, `GET /api/v1/repositories/{id}`, `GET /api/v1/hosts` and `GET /api/v1/hosts/{id}` gain
three fields; nothing else changes meaning:

- `grade`: `"A"` to `"F"`, or `null` (not scanned).
- `gradeReason`: `{ rule, count, example }` or `null`. `rule` is one of `known-exploited-with-fix`,
  `critical-with-fix`, `high-with-fix`, `critical-without-fix`, `medium-with-fix`, `high-without-fix`, `other-open`,
  `none`; `count` is the number of open findings of that rule (for `other-open`: all open findings, which are then
  all of the mild kind); `example` is one package of that rule (highest CVSS score, then name) or `null`.
- `gradeStale`: the latest scan or inventory failed.

The lists accept `sort=grade` (worst first by default; not scanned last) and `grade=F,E,none` (letters and `none`;
an unknown value is refused with 422 instead of showing everything). `GET /repositories/grades` and
`GET /hosts/grades` return the number of repositories or servers per grade (and `none`), for the filter.
`GET /hosts/{id}/findings` accepts `fixable=1` and `kev=1`, like the findings list, so that a grade can link to
the findings that decided it. No table or column is added; there is no migration.

The rules are one pure function (`gradeOf` in `packages/core/src/grades.ts`) with tests for every boundary. The API
computes its inputs in SQL (counts by severity and fix, KEV with fix) and uses a SQL expression of the same rules
for sorting and filtering; a test compares both on every combination of severity, fix and KEV.

### Interface

- A **Grade** column on the repositories and servers lists, right after the name: the letter in a badge. The
  letter is always visible, so colour is never the only signal. Colours come from the fixed severity scale: F and E
  vermilion, D orange, C amber, B grey, A neutral. **A is not green** (see below).
- Hover or keyboard focus shows a note with the reason in plain words ("D: 2 high vulnerabilities with a fix
  (lodash)") and a link to the findings behind it: the findings list for a repository (filters repository,
  severity, fix, known exploited), the server page for a server (its findings list takes the same filters). Escape
  closes the note. A grade without findings behind it (A) and "not scanned" show the note on focus or tap, without a
  link.
- The detail pages show the grade and its reason under the title.
- Sortable (F first) and filterable by grade.
- A short help ("How grades work") above both tables lists the rules and says that the grade is display only.
- The overview shows no distribution: its grid has no room for another card without moving the existing ones. The
  counts per grade exist in the API (`/grades`) for a later addition.

## Why letters, not a percentage

A percentage or a 0 to 100 score needs weights (how many highs are one critical?) that nobody can defend, moves
by small amounts when a scan finds a low, and invites arguing about 82 against 85. Six letters with rules a person can
read in ten seconds are honest about what is known: the worst thing that is open, and whether it can be fixed.
The reason is always given with the letter, so the grade can be questioned and checked against the findings.

## Why A is not green

AGENTS.md rule 6: green means proof (a gate that passed, a fix whose tests passed). A repository without open
findings is only free of the vulnerabilities the local database knows today; it proves nothing, and tomorrow's
database update can change it. A is neutral grey, with the same letter badge as the others.

## Threat model

- **Hostile package names and versions** (scanned content) appear in the `example` field and in the note. They are
  shown as text by the framework (escaped by default), cut to 200 characters on the server and passed to the
  translation as a parameter, never as part of the format string. Package names are never put into a URL or
  markup by the grade code.
- **A wrong grade** could hide a problem: an A for a repository with a critical. Mitigations: the rules are one
  tested function plus one SQL expression that are compared on every combination; a repository that was never
  scanned has no grade instead of an A; a failed run is marked stale instead of hiding the grade; the reason and
  the link to the matching findings are always there. A grade is not a security control and is never described as
  one.
- **A grade steering behaviour** (a pipeline that passes or fails by grade, an alert that fires): excluded by
  decision, the grade is computed for display, nothing reads it back. There is no setting for it.
- **Cross-organisation reads:** every query filters by the caller's organisation; the lists and `/grades` count only
  the caller's repositories and servers; a test covers it.
- **Cost:** sorting and filtering evaluate one correlated subquery per row, backed by the existing indexes on
  `finding(repository_id, state)` and `host_finding(host_id, state, ...)`. Organisations with thousands of
  repositories should be watched; a stored grade is possible later without changing the API.

## Consequences

- No migration. Existing API fields are unchanged; clients that ignore the new fields keep working.
- Two small, known differences between the grade and other counts, both only between the end of an acceptance and
  the next nightly scan: the severity columns and the findings list count `state = open` only, while the grade
  already counts an expired acceptance as open. The reopened finding appears in both after the scan.
- Open: a distribution of grades on the overview; a grade history (the trend lines show open findings, not grades);
  optional thresholds per organisation are deliberately not planned, the rules are the same for everyone.
