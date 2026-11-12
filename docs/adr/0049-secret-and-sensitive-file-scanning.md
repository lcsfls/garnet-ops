# ADR 0049: Secret and sensitive-file scanning

- Status: accepted
- Date: 2026-11-09
- Decided by: maintainer (check repositories for API secrets and other sensitive data that does not belong there; the current
  state on every scan and the Git history as an opt-in per repository; files that never belong in a repository count too;
  before the code viewer, as 0.1.3)
- Builds on: ADR 0004 (vault), ADR 0006 and AGENTS.md rule 3 (licences), ADR 0008 and 0012 (quality gates), ADR 0010 and 0019
  (notifications), ADR 0013 (AI triage), ADR 0028 (scanner isolation), ADR 0030 (private repositories), ADR 0043 (inactive
  repositories), ADR 0046 (backup)

## Context

A token, a key or a password in a repository is readable by everyone who can read the repository, today and in every clone and
fork made since, and it stays in the Git history after the file is fixed. Next to vulnerable dependencies, it is the most common way
code hands an attacker a way in. GarnetOps already clones every linked repository for its dependency scan; it does not look for
secrets yet (ROADMAP Phase 5).

The engine must be resale-safe (rule 3). gitleaks is MIT, its default rules are part of the same repository, it runs as a single
static binary without network access, and we already run it on our own repository in CI. TruffleHog is AGPL-3.0 and out.

The finding itself is sensitive: storing the secret, the matched line or the commit author would turn GarnetOps into a second place
where the secret leaks.

## Decision

### 1. Engine and rules

- **gitleaks** 8.30.1 (MIT), pinned by SHA-256 per platform in `scripts/fetch-scanners.mjs` like grype and syft, shipped in the app
  image at `/opt/scanners/gitleaks` with its licence, listed in `docs/COMPONENTS.md`.
- GarnetOps always passes **its own configuration** (`packages/core/src/secrets.ts`): gitleaks' default rules (`useDefault`) plus
  rules of ours for **files that never belong in a repository**: `.env` files with values (not `.env.example` and other
  templates), SSH and PuTTY private key files, key stores, `.git-credentials` and `.netrc`, `.npmrc` and `.pypirc` with
  credentials, registry credentials, kubeconfig with credentials, Terraform state, database dumps and SQLite files, `.htpasswd`,
  `wp-config.php` with a database password, and personal AI agent settings (`.claude/settings.local.json`).
- A repository's own `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments are **never honoured**: anyone who can
  commit could otherwise hide a secret from the check (tested: a repository's own configuration turns five findings into none).
  False positives are closed in GarnetOps, by a person, with a reason (4).
- **Fixed severities per rule**, plain and never moved by anything else: critical for access to infrastructure, code or the
  supply chain (private keys, cloud providers, forges, package registries, secret managers, Kubernetes, CI); high for every other
  service credential and for most sensitive files; medium for rules that guess by shape or entropy (`generic-api-key`, JWTs) and
  for database files; low for identifiers that are public by design (client ids, publishable keys). A rule from a newer gitleaks
  that GarnetOps does not know is high.

### 2. When and where it runs

- **Every scan of a repository's branch** checks the scanned commit's files (`gitleaks dir`) in the same clone as the dependency
  scan, inside the isolated scanner (ADR 0028: no network, read-only clone, its own scratch directory, limits), or in the worker
  where no scanner service is configured. Files above 5 MB are skipped.
- **The Git history** (`gitleaks git`, every commit of every branch the clone has) is checked when the repository has history
  scanning switched on, or once when someone presses **Check history now**. That scan clones the full history instead of one commit,
  within `GARNETOPS_MAX_REPO_MB` and the scan's time limit; a repository too large for it says so.
- **Pull request checks** (scans of a ref for the CI gate) check the files of that commit too, so the gate rule (6) can stop a pull
  request that adds a secret. They never change findings (as today).
- An older scanner service that does not know the secret scan, a missing binary, or a failure of gitleaks alone does not fail the
  scan: the dependency results stand and the scan records that secrets were not checked (`secretScan: "skipped" | "failed"`).

### 3. What is stored, and what never is

- **The value never leaves the scanner as text.** The scanner rewrites gitleaks' report before handing it over: the secret
  becomes its SHA-256, and the matched text, the commit author, e-mail and message are removed. The worker turns the SHA-256 into
  a **keyed fingerprint**: HMAC-SHA-256 with the organisation's own random 256-bit fingerprint key, cut to 128 bits. The key is
  created on first use and kept sealed in the vault (purpose `secret-fingerprint-key`, ADR 0004), so a fingerprint cannot be
  checked against a guessed password without it, and it survives a backup and restore (ADR 0046). The report file is deleted
  with the scan's directories.
- Stored per finding (`secret_finding`): repository, rule, severity, fingerprint, state, where it is (path and line in the current
  files; path, line, commit and commit date from a history scan; at most 50 of each, the rest counted), whether it is still in
  the current files, first and last seen. **Never**: the value, a part of it, the matched line, the commit author or e-mail.
- One finding per secret per repository: the same token in three files is one finding with three places, because it is rotated
  once. A rule about a whole file is one finding per file.

### 4. States: a secret is closed by a person, never by a scan

- `open`, `revoked` (the secret was rotated or withdrawn, so its value no longer works) and `dismissed` (not a secret: a test
  value, an example, a public key), each change with a reason of at least 10 characters, by members and above on repositories
  they can see, audited (`secret.revoked`, `secret.dismissed`, `secret.reopened`).
- **Removing the file does not close the finding**: the value is still in the history and in every clone. A finding no longer in the
  current files stays open with "Only in the history now: rotate it"; the card says how to remove it from the history afterwards.
- A closed finding stays closed when the same fingerprint turns up again (a rotated value committed again is harmless; a dismissed
  example is still an example). A new secret is a new fingerprint and a new finding.

### 5. Where people see it

- **Secrets** (`/secrets`, beside Findings in the menu): a table of its own (rule, severity, repository, where, state, first seen), filters
  by state, severity and repository, a detail with the places and the actions, and the plain steps: rotate first, then remove it
  from the files, then, if needed, from the history. The menu counts open critical and high secrets.
- The repository page gets a **Secrets** card: open secrets by severity, the history setting, **Check history now**, and when the
  history was last checked.
- Visibility follows the repository (ADR 0030): a private repository's secrets are visible to its owner only.
- Secret findings are **never** sent to the AI (no "Ask AI"), never part of the dependency counts, grades, early warnings or the
  existing exports, and not shown on the overview's key figures in this version.

### 6. Gate rule and notifications: opt-in

- A new gate rule **`secret-found`** (open critical or high secrets in the checked commit, not closed in GarnetOps) with the default
  **`off`**. `report` would already turn a passing gate run into one with notes, so it ships off: a pipeline that passed yesterday
  passes tomorrow (rule 2). Admins switch it to report or block.
- A new notification event **`secret.new`** (new open secrets in a scan; counts only, never a path) for channels and the personal
  matrix. Existing channels do not get it until someone ticks it; personal defaults follow the matrix (in the app, not by mail).

### 7. History setting

- `repository.secret_history_at/by`: switched on by admins, or by a member for their own private repository (as the inactive flag,
  ADR 0043), audited (`repository.secret_history_enabled/_disabled`). **Check history now** is for members and above, at most
  once an hour per repository.

## Threat model

| Threat | Impact | Control |
| --- | --- | --- |
| GarnetOps becomes a second place where the secret leaks (database, backup, logs, mail) | The secret is read from GarnetOps | The value leaves the scanner only as SHA-256 and is stored only as a keyed HMAC; no matched text, author or e-mail is kept; notifications carry counts only; the report file is deleted with the scan directory |
| Someone guesses a weak secret and checks it against a stored fingerprint | A password is confirmed | HMAC with a random per-organisation key sealed in the vault; 128 bits |
| A repository hides a secret from the check | A leak goes unseen | GarnetOps' own configuration always; the repository's `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` are ignored |
| A hostile repository attacks the scanner (huge files, deep encodings, symlinks, archives) | Worker or scanner exhausted, files outside read | Isolated scanner without network, read-only clone, symlinks not followed (hardened clone), files above 5 MB skipped, decoding depth 2, no archive traversal, the scanner's time and memory limits |
| A person sees secrets of a repository they may not see | Disclosure | Visibility of ADR 0030 on every route; members and above for changes; audited |
| A finding is closed by deleting the file | The leaked value stays valid | Only a person closes a finding; "only in the history now: rotate it" |
| A false positive flood | Alert fatigue | Fixed, plain severities; public identifiers low; dismiss with a reason; nothing in gates or notifications until switched on |
| The AI reads secret findings | Secrets to a model | Secret findings are never offered to the AI |
| History scans load the system | Scans delayed | Opt-in per repository, at most once an hour on demand, size and time limits |

## Consequences

- Repositories are checked for secrets and sensitive files on every scan with no setting to change; the history on request.
- Gate results and notifications do not change for anyone until they opt in.
- The scanner image grows by the gitleaks binary (about 20 MB).
- ADR 0028 gains a third scanner endpoint (`POST /v1/secrets`).
- Not in this version: secrets in container images, personal data and internal addresses, export of secret findings, a
  section in the reports of ADR 0047, the overview's key figures. The code viewer (ADR 0048) will show secret findings with the
  value masked.

## Addendum (2026-11): ignore rules

Closing false positives one by one does not scale where a repository has test fixtures or examples. Admins can now make
**ignore rules** in GarnetOps: a path glob (`test/fixtures/**`, `**/*.example.env`), a rule id, or both, for one repository or
all, with a reason of at least 10 characters, a recent sign-in, and an audit entry (`secret.ignore_rule_created`,
`secret.ignore_rule_deleted`).

- A rule is never read from a repository: the decision of 4 above (the repository's own suppressions are ignored) stands.
- A finding is set aside (`secret_finding.ignored_by`) only when **every** place it is known at matches a rule; the same value
  anywhere else keeps it open. With more than the 50 stored places of a kind, nothing is set aside.
- Set aside means: not in the open count, the menu, the gate rule `secret-found` or the `secret.new` notification. It stays listed
  under **Ignored** with the rule that set it aside, and each rule shows how many it sets aside.
- Patterns are relative globs (`*`, `**`, `?`) of at most 200 characters, without `..`, brackets or braces; a pattern that would
  match every path (`**`) is refused, so a rule cannot switch the check off.
- Rules apply at once when made or removed (the API recomputes the organisation's findings) and after every scan.

| Threat | Impact | Control |
| --- | --- | --- |
| An admin hides real secrets with a wide rule | A leak goes unseen | Recent sign-in, reason, audit entry, rules visible to everyone with their count, set-aside findings still listed, a match-everything pattern refused, the same value elsewhere still counts |

## Addendum (2026-11-12): the repository's `.gitleaksignore` in the scanned directory

gitleaks reads a `.gitleaksignore` from the scanned directory as well as from `--gitleaks-ignore-path`, so passing an empty
directory there did not keep the repository's file out. In history mode its entries (`commit:path:rule:line`) match, so a
committer could hide a secret in the history from the check (0.1.3 and 0.1.4); in file mode an entry has to name the clone's
random absolute path, which nobody can know. The worker now removes the file from its clone before any scanner sees it, and
`runGitleaks` removes it again and refuses to run while it is still there. Tested with gitleaks 8.30.1 in both modes. Decision 4
stands unchanged.

## Addendum (2026-11-12): the repository's own gitleaks configuration, as an opt-in that hides nothing

- Decided by: maintainer (teams keep their exceptions in `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments and
  want GarnetOps to respect them; chosen: "set aside visibly", over "extra rules only" and over "as gitleaks does").
- **Off by default**, switched on per repository by an admin with a recent sign-in, audited (`secret.repo_config_changed`).
  Decision 4 stays the default: without the switch nothing of the repository's configuration is read.
- With the switch, every scan runs gitleaks **twice**: first with GarnetOps' own configuration exactly as before (the strict
  run), then with GarnetOps' configuration extended by the repository's `.gitleaks.toml` (or `gitleaks.toml`), its
  `.gitleaksignore` and its `gitleaks:allow` comments (the repository run). The repository's file is read from the clone
  (regular file, at most 64 KiB, text) and cleaned: its `[extend]` table is replaced by `useDefault = true` (its
  `disabledRules` kept), so it cannot pull in another file or URL; rule ids starting with `garnetops-` are refused.
- **What the repository run finds that the strict run did not** (its own rules) is added as ordinary findings.
- **What the strict run finds that the repository run does not** (at the same path, line, commit and value) is **set aside
  by the repository**: kept, listed under **Ignored** with that reason, and, like a secret set aside by an ignore rule, not
  counted, not in the gate and not notified. A finding is set aside only when every place it is known at is.
- Anything that goes wrong in the repository run (no file, an invalid file, a refused file, a timeout) **sets nothing aside**:
  the strict result stands, and the repository's Secrets card says why.

| Threat | Mitigation |
| --- | --- |
| A committer hides a secret with the repository's exceptions | Off unless an admin switches it on for that repository; what it hides stays listed under Ignored with the reason; the strict run is unchanged |
| The repository's configuration reads other files (`[extend] path`) | `[extend]` replaced before use; inline or dotted `extend` keys refuse the file |
| The configuration slows the scan down | gitleaks' regular expressions run in linear time (RE2); 64 KiB limit; the scanner's time limit |
| A repository rule poses as one of GarnetOps' own | `garnetops-` rule ids refuse the file; GarnetOps' own rules take precedence over the repository's in the extension chain |

