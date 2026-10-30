# ADR 0041: Early warnings for hosts, containers and websites

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (early warnings also for what runs on hosts and for websites)
- Builds on: ADR 0029 (early warnings for repositories), ADR 0034 and 0037 (hosts and containers), ADR 0038 (website software
  versions), AGENTS.md rules 1 (air-gap capable) and 2 (no silent gate changes)

## Context

Early warnings answered one question for repositories: does a new advisory affect a package before the next scan looks? Hosts,
containers and websites had no such view. Running images and host packages are matched again with every new database, so a new
advisory became a finding without anyone seeing that it was new. Release lines and distributions that are about to lose their
security updates were only reported once they had ended.

## Decision

1. **New advisories for what runs.** When an image, a host's running kernel or a host's own packages are matched again with a
   newer vulnerability database, a finding that was not there before and whose advisory was published or changed after the
   database of the previous match is recorded as an early warning (`runtime_early_warning`). Unlike a repository, running
   software needs no scan to confirm it: it is a finding of the image or host at once. The warning stays open while the finding
   exists and is cleared when a later match no longer has it (the image or package changed). A first match, a new kernel and a
   changed package list never make warnings: what is new there is the software, not the advisory.
2. **Distributions near or past their end.** Hosts (the distribution of their packages or kernel) and images (the distribution
   syft names) are judged against the end-of-life data of endoflife.date that ships with GarnetOps, now with Debian, Ubuntu,
   Alpine Linux, Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Amazon Linux, Fedora and CentOS Stream. A release whose regular
   security support ended, or ends within 90 days, is listed. Computed when the page is read; nothing is stored.
3. **Website software that ends soon.** A release line that still gets fixes but ends within 90 days is listed per website, from
   its last look (ADR 0038). Once the line has ended it is a finding of the website, as before.
4. **One page, three sources.** **Early warnings** gets a switch for Repositories, Hosts and containers (when that module is on)
   and Websites (when that module is on). New advisories for what runs notify members in the app and by mail if they want
   (**A new advisory concerns a running container or host**), once per image or host and match.
5. **Nothing else changes.** Findings, grades, statistics and quality gates behave as before; the warnings only say what is new or
   what ends soon.

## Threat model

| Threat | Control |
| --- | --- |
| A hostile host or image reports a crafted distribution name | only letters, digits, spaces, dots, dashes and underscores are kept, at most 80 characters; it is only matched against a fixed list, never rendered as markup |
| Warnings leak between organisations | every query is bound to the signed-in organisation; tests check another organisation's rows stay out |
| Stale end-of-life data | the snapshot date is in the file; it is refreshed before every release; it works offline |
| Floods of notifications after a large database update | one notification per image or host and match, with the count |

## Consequences

- New: table `runtime_early_warning` (migration 0037), `GET /api/v1/early-warnings/hosts` and `GET /api/v1/early-warnings/websites`,
  `judgeDistribution` and `endsSoon` in `@garnetops/core/software`, the personal notification event `hosts.new_advisory` (group
  Hosts and containers), and nine distributions in `eol-data.ts`.
- `GET /api/v1/early-warnings` is unchanged.
- Not in this version: language packages inside images outside the distribution's package manager are matched as before but their
  runtimes (Node.js, Python) are not judged for end of life; channel notifications for hosts.
