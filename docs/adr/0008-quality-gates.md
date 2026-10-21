# ADR 0008: Quality gates and the gate API for CI

- Status: accepted (2026-10-21)
- Date: 2026-10-21
- Decided by: maintainer (all rules report-only by default; pull request ref and sha are scanned)
- Implements: ROADMAP Phase 1 "Quality gate API for CI (token per repository), rules in
  report-only mode by default, status check on the pull request"; mockup page "Quality gates"

## Context

Teams want a pipeline to stop when a change brings in a dependency with a known, fixable
critical vulnerability, and to see why. AGENTS.md rule 2 requires that gate behaviour never
changes silently: a pipeline that passed yesterday must not fail tomorrow because of an
update to GarnetOps. Rule 1 requires least privilege: repository credentials stay
read-only, and nothing a CI job can reach may leak code or findings.

## Decision

### Rules and modes

1. A gate is a set of **rules**, each in one of three **modes**: `off`, `report` (counted
   and shown, never fails a pipeline) or `block` (fails the pipeline).
2. Rules in the first version, all evaluated on the open findings of the scan (accepted
   risks never count):

   | Rule | Matches | Default |
   | --- | --- | --- |
   | `critical-fixable` | critical, or CVSS 9.0 or more, with a fixed version | report |
   | `known-exploited` | listed in CISA KEV | report |
   | `high-fixable` | high with a fixed version | report |
   | `license-denied` | a package whose licence is on the organisation's deny list (SPDX ids) | off, empty list |

   Later rules (secrets, "reachable per AI", "development dependencies only") arrive the
   same way: **every new rule ships `off` or `report`**, never `block`.
3. Modes are set per organisation by owners and admins (audited). Per-repository
   overrides follow later, as an addition.
4. **Nothing switches to `block` by itself.** Defaults never change in an update; a
   stored choice is never rewritten by a migration.

### Runs

5. Every successful scan is evaluated once and stored as a **gate run**: result `passed`
   (no rule matched), `notes` (only `report` rules matched) or `blocked` (a `block` rule
   matched), the matches per rule (counts only), the scan, the trigger and the rule modes
   in force at that moment. Runs are never re-evaluated: changing a rule affects the next
   run only.
6. Only `passed` is shown in green (AGENTS.md rule 6: green means proof).

### The gate API for CI

7. **Gate tokens are per repository**, created by owners and admins, shown once,
   stored as a SHA-256 hash, revocable, and audited (created, used, revoked). A token can
   do exactly two things for its repository: request a gate check, and read the result of
   that check. It cannot read findings, packages, code or other repositories.
8. `POST /api/v1/gate/checks` (Bearer gate token, optional `ref` and `sha`) queues a scan
   of the repository at that ref (default: its configured branch) and returns a check id.
   With `sha`, the scan refuses to run unless the fetched commit is exactly that one.
   `GET /api/v1/gate/checks/{id}` returns `queued`, `running`, or the result.
9. **The answer holds no details**: result, rule names, counts, and a link to the
   repository in GarnetOps. Pipeline logs of public projects are public; a vulnerability
   list there would tell an attacker where to look.
10. The status check on the pull request is the **pipeline step itself** (its exit code),
    so GarnetOps needs no write access to the forge. A ready-to-copy step (curl and a few
    lines of shell) is shown on the Quality gates page; no published action is needed.
11. Rate limit per token (one running check per repository, at most 30 requests a minute),
    surviving restarts like the sign-in limits.

## Threat model

- **A leaked gate token** (CI secret, log): the holder can queue scans of one repository
  and learn its pass/fail state and counts. It cannot read findings or code, other
  repositories, or change anything. Mitigations: per-repository scope, minimal answers,
  rate limit, revocation, audit entry per use with the client address, hash-only storage.
- **A malicious ref or sha**: refs are validated like branch names (no leading `-`, no
  `..`), passed after `--`; the clone stays shallow, read-only and sandboxed as today.
- **A gate that silently tightens**: excluded by decision 4; covered by a test that a
  database without stored modes evaluates every rule as its documented default.
- **Spoofed results**: results come only from GarnetOps over HTTPS; the step fails closed
  (non-zero exit) when GarnetOps cannot be reached, unless the team chooses otherwise in
  the step.

## Consequences

- New tables (additive migration): `gate_rule` (organisation, rule, mode, config),
  `gate_token` (repository, hash, prefix, created by, last used, revoked) and `gate_run`.
- Scans gain an optional ref and expected sha (worker: fetch that ref, verify the sha).
- New page "Quality gates" (rules, recent runs, pipeline step), a gate column on the
  repositories list and a "Recent gate runs" card on the overview, as in the mockup.
