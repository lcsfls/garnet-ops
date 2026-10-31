# ADR 0042: WordPress plugins and themes of websites

- Status: accepted (parts 1 to 3 on 2026-10-31, part 4 on 2026-10-31)
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
3. **Part 3: advisories from the Wordfence Intelligence feed** with the organisation's own API key. An owner or admin sets the
   key under Settings → External services, with a recent sign-in and an acknowledgement of the feed's terms; it is sealed in the
   vault at once (purpose `wordfence-api-key`), never shown again, and opened only by the worker. Once a day, and right after a
   key is set, the worker downloads the production feed (`/api/intelligence/v3/vulnerabilities/production`, `Authorization:
   Bearer <key>`, at most 400 MiB) and keeps only the advisories for the plugins, themes and WordPress versions that
   organisation's websites show, for that organisation alone; they are replaced with every download and deleted with the key.
   The daily look then reports each shown version that lies in an advisory's affected range as `wordpressVulnerable`, with the
   advisory's CVSS rating as its severity, the CVE, the fixed versions and Wordfence Intelligence named as the source. The data's
   terms do not allow bundling, so nothing is shipped or fetched without a key. The record format was implemented from Wordfence's
   description of the v3 feed; the build environment could not reach the service, so it is tested with recorded-shape fixtures
   only. Every field is checked for its shape and cut; records that do not fit are skipped.
4. **Part 4: the GarnetOps WordPress plugin** (`integrations/wordpress/garnetops/`, GPL-2.0-or-later as WordPress requires, our
   own code, a separate program; the installation serves it as a zip at `GET /api/v1/exposure/wordpress-plugin.zip`). It is
   **read by GarnetOps**, not sending: GarnetOps usually runs inside the customer's network and websites run outside, so a pull
   needs no inbound access to GarnetOps. The plugin adds one REST endpoint (`/?rest_route=/garnetops/v1/inventory`, which
   works with and without pretty permalinks) that answers only over HTTPS and only with the token GarnetOps generated for that
   website; it stores only the token's SHA-256 and compares in constant time. Wrong tokens are slowed down (429 after 20 in ten
   minutes), the right one never is, so nobody can lock GarnetOps out. It answers with versions only: WordPress, PHP, and every
   installed plugin and theme with its version and whether it is active; no users, content, settings or paths. The token also
   goes in `X-GarnetOps-Token`, because some Apache and CGI setups drop `Authorization`.

   An owner or admin connects a website whose control is proved, with a recent sign-in; the token is shown once, sealed in the
   vault (purpose `wordpress-plugin-token`) and opened only by the worker. At the daily look the worker reads the endpoint over
   verified HTTPS at the same checked address as the home page, without redirects, at most 512 KiB, and only while the website
   is verified. The plugin's exact list then replaces the guess from asset addresses (`source: "plugin"`), WordPress and PHP
   are judged from the reported versions, and a plugin or theme behind its latest version is medium while active (exact) and
   low otherwise. How the read went (`unauthorized`, `notInstalled`, `notVerified`, ...) is shown on the website.

## Threat model

| Threat | Control |
| --- | --- |
| A hostile page injects markup or long text through asset addresses | only slugs and version numbers of a fixed shape are kept; rendered as text |
| A page with thousands of asset addresses | at most 256 KiB are read and searched, at most 60 plugins and 5 themes kept |
| A wrong version from an address | shown as "as the asset address says"; judged only as low |
| Slugs leave the network | off by default; opt-in with step-up and acknowledgement; only slugs, only to api.wordpress.org, over HTTPS with the outbound address policy |
| The Wordfence key leaks | sealed at once, never returned by the API, never logged, never in audit data; sent only to www.wordfence.com over HTTPS |
| A hostile or broken feed | at most 400 MiB read; every id, slug, version, CVE and title checked for its shape and cut; unknown records skipped; titles rendered as text |
| False positives from asset versions | the version is the one the asset address names, and the finding says so; WordPress's own version comes from its generator tag |
| The plugin token reaches the wrong site | sent only to a name whose control is proved, over HTTPS with the certificate verified, to the checked public address, without redirects; never stored in snapshots, logs or audit data |
| The plugin endpoint is guessed or abused | 256-bit token, only its SHA-256 stored on the site, constant-time comparison, HTTPS only; wrong tokens slowed down, the right one never locked out |
| The plugin leaks what it should not | it answers with versions only; no users, content, settings or paths; it never sends anything by itself |
| A hostile site answers the plugin's address | the answer must have the plugin's format and version; slugs and versions are checked for their shape, at most 500 plugins and 50 themes |
| A hostile or broken directory answer | at most 256 KiB read; only a `version` of a fixed shape is kept; a failed request keeps the previous answer |

## Consequences

- New: `@garnetops/core/wordpress`, `wordpress` in the HTTP snapshot (absent when none were seen, and in older snapshots).
- `MAX_HTTP_BODY_BYTES` is 256 KiB.
- Part 2: `wordpress_org_*` columns on `exposure_settings` and the table `wordpress_component` (migration 0038), the worker queue
  `websites.wordpress-org` (hourly), `wordpressOrg` in `GET`/`PUT /api/v1/exposure/settings` (`ct` is now optional there) and in
  `GET /api/v1/exposure/{id}`, the rule `wordpressOutdated`.
- Part 3: `wordfence_*` columns on `exposure_settings` and the table `wordpress_advisory` (migration 0039), the worker queue
  `websites.wordfence` (hourly for due organisations, and on demand), `PUT` and `DELETE /api/v1/exposure/settings/wordfence`,
  `wordfence` in `GET /api/v1/exposure/settings`, the rule `wordpressVulnerable`.
- Part 4: `wordpress_token_*` columns on `exposure_asset` (migration 0041), `POST` and `DELETE /api/v1/exposure/{id}/wordpress-plugin`,
  `GET /api/v1/exposure/wordpress-plugin.zip`, `wordpressPlugin` on a website and in its snapshot, `reported` versions in the HTTP
  snapshot, the plugin under `integrations/wordpress/` with PHP tests in CI, and the plugin files in the image
  (`/opt/garnetops/wordpress-plugin`, `WORDPRESS_PLUGIN_DIR`).
- Settings: every connection that can leave the network is now listed and switched in one section, **External services** (public
  DNS, Certificate Transparency, wordpress.org, Wordfence, registry checks); **Modules** keeps the module switches.
