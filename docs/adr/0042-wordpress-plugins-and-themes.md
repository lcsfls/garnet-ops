# ADR 0042: WordPress plugins and themes of websites

- Status: accepted for part 1 (2026-10-30); parts 2 to 4 are planned
- Date: 2026-10-30
- Decided by: maintainer (detect from the outside and with an own plugin; versions from wordpress.org and advisories from the
  Wordfence feed only with the customer's opt-in and key)
- Builds on: ADR 0023 and 0033 (website monitoring), ADR 0038 (software versions), AGENTS.md rules 1 and 3

## Context

Most WordPress sites are attacked through plugins and themes, not WordPress itself. Website monitoring knew the WordPress version
(ADR 0038) but not what runs on it.

## Decision

1. **Part 1, from the outside (this version).** The home page that stage 1 reads once a day is searched for asset addresses under
   `/wp-content/plugins/<slug>/` and `/wp-content/themes/<slug>/`. A slug is kept only in the shape wordpress.org uses (lowercase
   letters, digits, dashes and underscores, at most 64 characters); a version only from the address's `ver` parameter in the shape
   of a version number, and not when it equals the WordPress version (WordPress puts its own there for assets without one). At
   most 60 plugins and 5 themes. No other page or path is requested: plugins that load nothing on the home page are not seen. To
   see assets that load at the end of larger pages, stage 1 now reads up to 256 KiB of the home page (was 64 KiB); the page is
   still never stored. The list is shown on the HTTP tab; it is information, not a finding.
2. **Part 2 (planned): latest versions from wordpress.org**, opt-in per organisation, because it sends the slugs to wordpress.org.
   A plugin behind its latest version then becomes a finding.
3. **Part 3 (planned): advisories from the Wordfence Intelligence feed** with the customer's own key; the data's terms do not
   allow bundling, so nothing is shipped or fetched without a key.
4. **Part 4 (planned): a GarnetOps WordPress plugin** (GPL-2.0-or-later, as WordPress requires, our own code, published
   separately) that reports the exact list of plugins and themes with signed reports, like the host agent.

## Threat model (part 1)

| Threat | Control |
| --- | --- |
| A hostile page injects markup or long text through asset addresses | only slugs and version numbers of a fixed shape are kept; rendered as text |
| A page with thousands of asset addresses | at most 256 KiB are read and searched, at most 60 plugins and 5 themes kept |
| A wrong version from an address | shown as "as the asset address says", never judged in part 1 |

## Consequences

- New: `@garnetops/core/wordpress`, `wordpress` in the HTTP snapshot (absent when none were seen, and in older snapshots).
- `MAX_HTTP_BODY_BYTES` is 256 KiB.
