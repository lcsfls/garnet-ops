# ADR 0006: AGPL-3.0 with a commercial license (dual licensing)

- Status: accepted (2026-10-21); legal review still due before the first release
- Date: 2026-10-21
- Decided by: maintainer
- Would amend: ADR 0001 (license), `LICENSE`, `AGENTS.md` (license, editions)

## Context

ADR 0001 made GarnetOps proprietary with unpublished source. This ADR
publishes the source, with GitHub as the host
(`https://github.com/lcsfls/garnet-ops`). Two licenses were discussed:

- **Apache-2.0** (like Restow): anyone may use, change, resell and host the
  product, including as a closed SaaS, without giving anything back. Paid
  editions would have little to stand on.
- **AGPL-3.0-only**: anyone may use, change and host it, but whoever offers
  a modified version to users, including over a network, must publish those
  changes under the AGPL. A closed SaaS fork is not possible.

The copyright holder is IT Systeme Flores UG (haftungsbeschränkt), and so far
all code was written by it or copied from Restow, its own
Apache-2.0 code. Apache-2.0 code may be included in an AGPL-3.0 work.

## Proposal

1. Publish GarnetOps under **AGPL-3.0-only**.
2. Offer a **commercial license** in addition (dual licensing) for customers
   who cannot or will not use AGPL software, or who want terms the AGPL does
   not give (no source obligation for their changes, warranty, indemnity).
3. Editions: the Community edition is the AGPL code. Paid editions offer the
   commercial license and support. Security fixes stay free for every
   supported version line (AGENTS.md, EU Cyber Resilience Act).
4. **Contributor License Agreement** before the first outside contribution,
   granting the UG the right to relicense contributions. Without it, dual
   licensing ends with the first merged outside patch.
5. Third-party rule unchanged: **no AGPL or GPL components inside our code**.
   As copyright holder we are not bound by our own AGPL; we would be bound by
   someone else's, which would block the commercial license.
6. Trademark: the AGPL covers code, not the name. "GarnetOps", the logo and
   the wordmark stay reserved (trademark policy in the repository; DPMA and
   EUIPO registration is already on the roadmap).

## Consequences

- Positive: customers and auditors can read the code, which supports the
  "your code never leaves your network" promise and security reviews. Forks
  that host GarnetOps must share their changes.
- Negative: many companies do not allow AGPL software; for them the
  commercial license exists.
- Publishing is not reversible for released versions. Before the first public
  push: run gitleaks over the whole history, check that no customer data,
  test fixtures with real paths or credentials are in it, and add
  `SECURITY.md`, `CONTRIBUTING.md` with the CLA, and a trademark policy.
- Files to change once accepted: `LICENSE` (AGPL-3.0 text plus a note on the
  commercial license), ADR 0001 (license section superseded), `AGENTS.md`
  (rule 3 stays, "What we are building" license and editions paragraphs,
  "our own code is never published" sentence), `README.md`, SPDX headers
  (`AGPL-3.0-only`) or a `REUSE.toml`, `package.json` `license` fields
  (`UNLICENSED` to `AGPL-3.0-only`).
- Legal review before the first public release: AGPL section 13 obligations
  for the hosted offering, the CLA text, the commercial
  license terms, and the interaction with the Cyber Resilience Act.

## Alternatives

- Stay proprietary (ADR 0001 as is); the GitHub repository stays private.
- Apache-2.0: simplest for adoption, but allows closed hosted forks.
- Source-available licenses (BSL, Elastic License, FSL): ruled out for our
  own dependencies by AGENTS.md rule 3; for our own code they are possible
  but are not open source, and the community trust is lower.
