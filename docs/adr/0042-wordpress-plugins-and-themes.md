# ADR 0042: WordPress plugins and themes of websites

- Status: accepted for parts 1 and 2 (2026-10-30); parts 3 and 4 are planned
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
2. **Part 2: latest versions from wordpress.org**, opt-in per organisation (Settings → Modules, owners and admins, with a recent
   sign-in and an acknowledgement, audited both ways). The worker asks `api.wordpress.org` for the slugs that opted-in
   organisations' home pages name, one request per slug with every field but the version switched off, at most once a day each
   and one request a second, at most 200 an hour. Nothing else is sent: no website name, version or organisation. The answers are
   public data, kept once for the installation (`wordpress_component`). The daily look then judges each plugin and theme with a
   version: behind wordpress.org's latest is a finding `wordpressOutdated` (low, because the version comes from an asset
   address). A slug wordpress.org does not list (premium or custom) is not judged. Switching the lookup off resolves these
   findings at the next look.
3. **Part 3 (planned): advisories from the Wordfence Intelligence feed** with the customer's own key; the data's terms do not
   allow bundling, so nothing is shipped or fetched without a key.
4. **Part 4 (planned): a GarnetOps WordPress plugin** (GPL-2.0-or-later, as WordPress requires, our own code, published
   separately) that reports the exact list of plugins and themes with signed reports, like the host agent.

## Threat model

| Threat | Control |
| --- | --- |
| A hostile page injects markup or long text through asset addresses | only slugs and version numbers of a fixed shape are kept; rendered as text |
| A page with thousands of asset addresses | at most 256 KiB are read and searched, at most 60 plugins and 5 themes kept |
| A wrong version from an address | shown as "as the asset address says"; judged only as low |
| Slugs leave the network | off by default; opt-in with step-up and acknowledgement; only slugs, only to api.wordpress.org, over HTTPS with the outbound address policy |
| A hostile or broken directory answer | at most 256 KiB read; only a `version` of a fixed shape is kept; a failed request keeps the previous answer |

## Consequences

- New: `@garnetops/core/wordpress`, `wordpress` in the HTTP snapshot (absent when none were seen, and in older snapshots).
- `MAX_HTTP_BODY_BYTES` is 256 KiB.
- Part 2: `wordpress_org_*` columns on `exposure_settings` and the table `wordpress_component` (migration 0038), the worker queue
  `websites.wordpress-org` (hourly), `wordpressOrg` in `GET`/`PUT /api/v1/exposure/settings` (`ct` is now optional there) and in
  `GET /api/v1/exposure/{id}`, the rule `wordpressOutdated`.
