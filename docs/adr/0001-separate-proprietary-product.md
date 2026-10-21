# ADR 0001: Separate, proprietary product next to Restow

- Status: accepted; license section superseded by ADR 0006 (AGPL-3.0 plus commercial license)
- Date: 2026-10-19
- Decided by: maintainer

## Context

Restow is a self-hosted backup suite (Apache-2.0 core with commercial
editions) by the same copyright holder. The new security platform targets a similar
audience (IT service providers, SMBs, regulated sectors in the EU) and could
reuse a lot of Restow's foundation. Three options were considered:

1. One installation with backup and security as modules.
2. Two products under one brand with a shared login.
3. Two fully separate products that share engineering practices only.

## Decision

Option 3.

- Own product name (pending), own visual identity, logo and colours.
- Own login and user database: local accounts, LDAP/Active Directory and
  OIDC/OAuth, second factor mandatory. Nothing is shared with Restow at runtime:
  no database, no credentials, no process, no agent.
- Own repository, release cycle and versioning.
- **Proprietary license**, pricing on request. (Superseded by ADR 0006: the
  source is published under AGPL-3.0-only with a commercial license.)
- English is the primary language of the product and all materials; German is
  the first translation; further EU languages follow.
- Foundations may be copied from Restow (auth setup, editions, alerts, audit
  log, updater, Compose layout, UI kit). Restow's Apache-2.0 code belongs
  to the same copyright holder; copies keep a note of their origin in the commit message.
  Contributions to Restow by third parties under its CLA are only copied if
  the CLA permits relicensing.

## Consequences

- Security: a compromised scanner sandbox cannot reach backup keys, because the
  products never share a host process or database.
- Restow users are never affected by changes in this product (never break user
  space).
- Some code is duplicated. Shared packages may be extracted later, once both
  products are stable, without forcing changes on Restow users.
- Integrations between the two products, if any, happen over public APIs like
  with any third-party system.
