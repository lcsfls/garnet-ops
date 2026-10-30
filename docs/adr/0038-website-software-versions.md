# ADR 0038: Software versions of websites, judged against end-of-life data

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (detect from what a site already says about itself, without a plugin; judge against openly licensed
  end-of-life data that ships with GarnetOps)
- Builds on: ADR 0023 and 0033 (website monitoring), AGENTS.md rules 1 (air-gap capable), 2 (no silent gate changes) and 3 (licences)

## Context

Teams want to know when a site runs software that no longer gets security fixes: an old PHP line, a WordPress that missed several
security releases, a Drupal past its end of life. The checks already read the home page and its headers once a day; until now a
version in a header was only reported as "names a version".

## Decision

1. **Detect only what the site says**, from the request stage 1 makes anyway: the `Server` header (nginx, Apache), `X-Powered-By`
   (PHP) and the `<meta name="generator">` tag of the home page (WordPress, Drupal, Joomla, TYPO3, MediaWiki, Astro). The page body
   is still dropped; at most three generator values of 120 characters are kept in the snapshot. No extra request, no probing of
   paths like `readme.html` or `/wp-json`, no plugin.
2. **Judge against the release line**, with a snapshot of endoflife.date (MIT License) committed as `packages/core/src/eol-data.ts`
   and refreshed before a release with `scripts/update-eol-data.mjs`. A version belongs to the longest release cycle it starts with.
   The line has ended: `softwareEndOfLife`. A newer version of the same line exists: `softwareOutdated`. No data or no line: not
   judged. It works offline; nothing is fetched at run time.
3. **Severity by how reliable the number is.** A CMS names its own version exactly: end of life is high, outdated medium. A server
   header can come from a build that was patched without a new number: one step lower (medium, low). A header that names a
   distribution (`Apache/2.4.57 (Debian)`, `PHP/8.1.2-1ubuntu2.14`) is shown but **not judged**: Debian, Ubuntu, Red Hat and others
   backport security fixes and keep the old number, so the number says nothing about the fixes.
4. **Findings only**, like every website rule: they do not change repository grades or quality gates. Rules that need the home
   page are left unjudged when it did not answer.

## Threat model

| Threat | Control |
| --- | --- |
| A hostile page uses the generator tag to inject markup or very long text | only the `content` of generator meta tags, cut to 120 characters, control and format characters removed, rendered as text |
| False alarms on patched distribution builds | distribution-named builds are not judged; header versions count one step lower |
| A site hides or fakes its version | the result is information about what the site says, worded as such; a missing version is not judged |
| Stale end-of-life data | the snapshot date is in the file; it is refreshed before every release, and a security release can refresh it |

## Consequences

- New: `@garnetops/core/software` (detection and judgement), `eol-data.ts` (generated), `generators` in the HTTP snapshot,
  `software` in `GET /api/v1/exposure/{id}`, rules `softwareEndOfLife` and `softwareOutdated`.
- `docs/COMPONENTS.md` lists endoflife.date as a data source with its attribution.
- Not in this version: WordPress plugins and themes, versions from asset URLs (`?ver=`), vulnerability matching of website
  software (CVE data for CMS plugins is under licences that do not allow resale).
