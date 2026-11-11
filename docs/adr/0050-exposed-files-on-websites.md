# ADR 0050: Checking verified websites for files that must not be public

- Status: accepted
- Date: 2026-11-11
- Decided by: maintainer (report sensitive files a website serves publicly, such as `/.env`, `/.git/config`, backups, dumps and
  `phpinfo`; only for names whose control is proved by DNS TXT)
- Builds on: ADR 0023 and 0033 (website monitoring, verification, stage 1 and 2), ADR 0038 (software versions), ADR 0040
  (availability), ADR 0042 (WordPress), ADR 0049 (secrets in repositories)

## Context

A `.env`, a `.git` folder, a database dump or a `wp-config.php.bak` left in a web root hands the same secrets to anyone that a
committed key does, often more directly. Scanners on the internet look for these paths all day. GarnetOps looks at a website from
outside, but so far reads only `/`: ADR 0023 ruled out crawling, and ADR 0038 and 0042 promised that no other path is requested.

Asking for a fixed handful of well-known paths is not crawling, but it is a new kind of request, can show up in a web
application firewall or an intrusion detection system as a probe, and is only acceptable on infrastructure the person is allowed
to test. So the promise of the earlier ADRs stays the default, and this check is something an admin switches on per website.

## Decision

### 1. Opt-in per website, only for proved names

- `exposure_asset.exposed_files_at/by`: switched on by an **admin** with a **recent sign-in**, only for a name whose control is
  proved (its own TXT record or file, or a verified parent with subdomains included; ADR 0023), never for an address. Audited
  (`exposure.exposed_files_enabled`, `_disabled`). Switching it off resolves the open findings of this check at once.
- The worker checks the proof again on every run. A lost proof stops the check; findings stay as they are until it is proved again
  or switched off ("could not look" is not "fixed").
- Existing installations change nothing until someone switches it on; the documentation's "what is never done" now names this
  one exception.

### 2. What is asked, and how

- Once a day with the website's stage 1 run, **a fixed list of at most 24 paths**, fixed in code (`packages/core/src/exposed-files.ts`):
  environment files (`/.env`, `/.env.production`, `/.env.local`), Git (`/.git/HEAD`, `/.git/config`), credentials
  (`/.aws/credentials`, `/.npmrc`, `/.htpasswd`, `/.claude/settings.local.json`), configuration backups
  (`/wp-config.php.bak`, `/wp-config.php~`, `/wp-config.php.save`, `/wp-config.old`, `/config.php.bak`), dumps and archives
  (`/backup.sql`, `/dump.sql`, `/database.sql`, `/db.sql`, `/backup.zip`, `/backup.tar.gz`), diagnostics (`/phpinfo.php`,
  `/info.php`, `/server-status`) and `/.DS_Store`.
- `GET https://<name><path>` to the address the run already checked, with the name as Host and SNI, verified TLS, the user agent
  `GarnetOps-Exposure-Check/1`, **no redirects followed**, at most 8 KiB of the body read, 8 seconds each, one after another with a
  quarter of a second between them. No cookies, no credentials, no query strings, no other method.
- **A file counts only when its content proves it**: status 200 and a signature of that kind of file in the first bytes
  (`KEY=value` lines for `.env`, `ref: refs/` for `.git/HEAD`, `[core]` for `.git/config`, `DB_PASSWORD` for WordPress
  configuration, `CREATE TABLE`/`INSERT INTO`/dump headers for SQL, the ZIP or gzip magic for archives, the phpinfo title, the
  Apache status title, the `Bud1` magic of `.DS_Store`). A site that answers 200 with its own page for every path ("soft 404") does
  not count, and an HTML body never matches a non-HTML signature.
- **Nothing of the body is stored**: the finding keeps the path and the kind. The bytes are dropped as soon as they are checked.

### 3. Findings

One rule, `exposedFile`, with the path as subject and fixed severities by kind: **critical** for environment files, cloud and
registry credentials and configuration backups with a database password; **high** for an exposed Git repository, SQL dumps,
archives, `.htpasswd` and AI agent settings; **medium** for phpinfo and the server status; **low** for `.DS_Store`. They appear in
the website's findings and report (area **Files**), in the websites at a glance and the organisation report like every website
finding, count in the menu's attention like every critical or high one, and a new critical or high one tells admins once
(`exposure.exposed_file`, in the app by default). The text says what to do: remove the file, block the path in the web server,
and rotate what it contained, because it may have been read already.

## Threat model

| Threat | Impact | Control |
| --- | --- | --- |
| GarnetOps probes someone else's server | Unauthorised scanning, complaints, legal risk | Only names whose control is proved, re-checked on every run; opt-in by an admin with a recent sign-in; audited |
| The check is used to read secrets from a site | Secrets in GarnetOps | Only 8 KiB read, only a match/no-match kept, nothing of the body stored, logged or notified |
| A redirect or DNS answer leads the request elsewhere | Probing a third party, SSRF | The address checked by the run (public addresses only, anti-rebinding), no redirects followed |
| False positives from soft 404 pages | Alarm fatigue | Content signatures per kind; HTML never matches a non-HTML kind |
| Load on the website, WAF bans | Outage of the check, blocked addresses | At most 24 small requests a day, sequential, paced, 8 KiB each, honest user agent |
| A timeout reads as "fixed" | A real exposure closed silently | A run with failed requests leaves open findings of this rule as they are |

## Consequences

- People learn of a forgotten `.env` or `.git` on their site from GarnetOps rather than from an attacker.
- The promise "only `/` is requested" now has one exception that an admin chooses per website, documented as such.
- New findings and a new notification; nothing changes for websites where it is not switched on.
