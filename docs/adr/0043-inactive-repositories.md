# ADR 0043: Inactive repositories

- Status: accepted (2026-10-31)
- Date: 2026-10-31
- Decided by: maintainer (repositories that are not used or maintained at the moment can be set aside)
- Builds on: ADR 0005 (nightly scans), ADR 0029 (early warnings), ADR 0030 (private repositories), ADR 0032 (pull requests),
  AGENTS.md rule 2 (no silent gate changes)

## Context

Organisations keep repositories they no longer work on: archived projects, a site that was replaced, an experiment. Their old
findings fill the overview, the findings list and the statistics, they are scanned every night and they get early warnings,
although nobody will fix them. Removing them loses the history; keeping them hides what matters.

## Decision

1. **Set aside, not removed.** A repository gets an inactive state (`inactive_at`, who, and an optional short reason). Owners
   and admins set any repository they see aside; a member sets aside their own private repository, as with removing it. It is
   taken back into use the same way. Both directions are in the audit log.
2. **What stops:** the nightly scan, reading its pull requests, early warnings, **Scan all**, and the fix proposals list of the
   organisation.
3. **What leaves it out:** every view over the whole organisation: overview figures and the open-findings trend, findings,
   packages, statistics, early warnings, pull requests and the search for findings and packages. The repository list shows active
   repositories; **Inactive** lists the ones set aside, with a badge.
4. **What stays:** the repository, its findings, scans, history and credentials; its own page with everything on it (with a
   notice what being inactive means); a scan by hand; its quality gate, so a pipeline that still calls it gets the same answer as
   before (rule 2).
5. **API:** `PUT /api/v1/repositories/{id}/activity` (`{ active, reason? }`), `inactive` on every repository, `activity` on
   `GET /api/v1/repositories` (`active` by default, `inactive`, `all`) and `inactive` in `GET /api/v1/repositories/counts`. Lists
   over the whole organisation leave inactive repositories out; asking for one repository (`repositoryId`) still shows them. As
   nothing is inactive after an upgrade, every answer stays the same until someone sets a repository aside.

## Consequences

- Migration 0040 adds three columns to `repository` (expand only).
- Statistics count active repositories: setting one aside also takes its history out of the charts; taking it back puts it back.
- Not in this version: setting aside automatically after a time without commits.
