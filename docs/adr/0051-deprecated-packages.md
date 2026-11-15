# ADR 0051: Deprecated and yanked packages, as a module

- Status: accepted (2026-11-15)
- Date: 2026-11-15
- Decided by: maintainer (an `npm ci` that warns about deprecated packages GarnetOps did not show; chosen: the registry as the
  source, opt-in with own registries and excluded names; npm, PyPI and crates.io; a view and a card of their own, not findings)
- Builds on: ADR 0033 (modules), ADR 0005 (scans and inventory), AGENTS.md rules 1, 2 and 6

## Context

grype reports packages with known vulnerabilities. A package can also be **deprecated** by its maintainers (npm: "no longer
supported", "use X instead") or a version **yanked** (PyPI, crates.io: withdrawn, often for a serious bug). None of this is in a
vulnerability database or a lockfile; only the registry knows it. Asking the registry means sending package names out of the
customer's network, which AGENTS.md rule 1 allows only as a visible opt-in.

## Decision

1. **A module, off by default** (`deprecated`, Settings → Modules), switched by owners and admins and audited like the others
   (ADR 0033). While it is off nothing is asked, nothing is shown, and the gate rule has nothing to count.
2. **The registries asked**, one per ecosystem, each an `https://` address an admin may replace with their own (Verdaccio, Nexus,
   Artifactory, devpi, a crates.io sparse index mirror); private addresses are allowed for an own registry, loopback, link-local and
   metadata addresses never:
   - **npm** (`https://registry.npmjs.org`): the abbreviated package document (`application/vnd.npm.install-v1+json`), whose
     versions carry `deprecated` with the maintainers' message.
   - **PyPI** (`https://pypi.org`): `/pypi/{name}/{version}/json`, yanked when every file of the version is (`yanked_reason`).
   - **crates.io** (`https://index.crates.io`, the sparse index): the crate's index file, one JSON line per version with `yanked`.
3. **What is sent**: the package name (and for PyPI the version), and a fixed `User-Agent` without anything of the installation.
   Nothing about repositories, organisations or people. **Excluded names never leave**: an admin lists npm scopes (`@acme`) and name
   patterns (`acme-*`) that stay inside (internal packages); they are not asked and show as "not checked".
4. **When**: after a scan, for the packages it found that are not known or older than 24 hours, and once a day for all; at most
   2,000 names per run, four at a time, with timeouts and size limits. Answers are kept per registry (the public registries' answers
   are shared by the installation, an organisation's own registry's answers by that organisation only) and replaced after 24 hours.
5. **Where it shows**: the **Packages** page gets a filter "Deprecated or yanked" with the registry's message; a repository gets a
   card listing its deprecated and yanked packages; nothing becomes a finding, nothing has a severity, the grade does not change.
6. **Gate rule `deprecated-package`**, **off by default** (rule 2): set to report or block, it counts the packages of the checked
   commit known to be deprecated or yanked.

## Threat model

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Internal package names reach a public registry | Disclosure of internal project names | Module off by default; excluded scopes and patterns are never asked; an own registry instead of the public one |
| An admin points a registry at an internal service | Server-side request forgery | `https` only, address checked on every connection (loopback, link-local, metadata refused), no redirects, GET only, no credentials, fixed paths built from validated names |
| A hostile registry answers | Memory, time, rendering | 16 MB per answer, timeouts, JSON parsed defensively; messages cleaned (control and bidirectional characters removed), cut to 300 characters, shown as text, links not followed |
| A registry is down | Wrong "fine" | An error is kept as "not checked", never as "fine"; the gate counts only known deprecated or yanked packages |
| Names leak between organisations | Disclosure | Answers of an organisation's own registry are kept for that organisation only |

## Consequences

- Teams see `npm ci` warnings (and their PyPI and Rust equivalents) in GarnetOps, with the maintainers' message, without a scan
  changing anything about findings or grades.
- Air-gapped installations use it only with an own registry, or not at all.
- Go (retracted versions) and Composer (abandoned packages) may follow; their sources are different enough for a decision of their own.
