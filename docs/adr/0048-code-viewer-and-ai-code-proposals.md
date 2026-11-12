# ADR 0048: Code viewer for findings, and AI code proposals as pull requests

- Status: accepted (2026-11-12); delivered in two steps: the viewer (0.1.5), then AI excerpts, proposals and pull requests (0.1.6)
- Date: 2026-11-05
- Decided by: maintainer (a code viewer that shows the affected code of a finding, an AI fix proposal shown before and after in
  tabs, handed on as a pull request; code fetched on demand, nothing stored; code excerpts for the AI only as an opt-in per
  organisation; highlight.js; the affected code of a dependency finding is where the package is declared and where it is used;
  files read through the forge API, else through a short-lived clone)
- Builds on: ADR 0004 (vault), ADR 0013 (AI triage), ADR 0014 (fix pull requests), ADR 0027 (web app and CSP), ADR 0028 (scanner
  isolation), ADR 0030 (personal forge connections, private repositories), ADR 0039 (fix pull requests through connected accounts)

## Context

A finding today says which package in which version is vulnerable, and a fix proposal bumps one version string in one manifest.
What people miss is the code: where the package is declared, where the project uses it, and what has to change besides the
version, for example an import that moved in the new major version or an override for a package that only arrives transitively.
They want to see that code next to the finding, ask the AI for a change, compare before and after, and hand the change on as a pull
request that a human reviews.

GarnetOps only has dependency findings (grype on an SBOM). There are no line numbers in our own data: `finding.locations` names
SBOM paths (a lockfile, a manifest), `repository_manifest` holds the manifests of the scanned commit with their blob ids, and
`scan.commit_sha` names the commit. GarnetOps keeps no clones (ADR 0028), the API cannot open forge credentials (ADR 0004, 0014),
and ADR 0013 deferred code excerpts for the model to "a later decision" with the settings column `ai_settings.context_policy`
fixed at `metadata`.

Code is the most sensitive thing GarnetOps can touch after credentials: it leaves the customer's network if it reaches an external
model, it is hostile input (comments and strings can carry prompt injection), and a change made from it can reach a repository.

## Decision

### 1. What the viewer shows

For a finding on a repository, on its detail, a **Code** section with two parts, both read at the commit of the scan that last saw
the finding (`finding.last_seen_scan_id` → `scan.commit_sha`), and both labelled with that commit:

- **Where it is declared**: the manifests in `repository_manifest` that declare the package, and the lockfile among the finding's
  locations, each with the lines that name the package highlighted. The lines are found by the pure manifest scanners of
  `packages/core/src/manifests.ts` (extended to report line ranges), for lockfiles by a bounded search for the package name and
  version.
- **Where it is used**: the source files that import the package, found by name with fixed patterns per ecosystem (npm:
  `import … from "x"`, `import("x")`, `require("x")`, also `x/…`; PyPI: `import x`, `from x import`; Go: the module path in import
  blocks; Cargo: `use x::`, `extern crate x`; Composer: the package's PSR-4 namespaces from its `composer.json` entry where present).
  Each hit shows the line with three lines around it. It says plainly that it is a search by name and can miss dynamic imports or
  include a namesake. At most 200 hits in 50 files; more are counted, not shown.

Other ecosystems (Maven, NuGet, OS packages in images) show the declaration only, or a sentence that the package is not declared in
a file GarnetOps reads. Host and container findings have no code.

### 2. How the code is read: the worker, on demand, nothing kept

Only the worker reads code, with the repository's **read** credential (the one scans use; never the write token of ADR 0014, and
a connection's token only as ADR 0030 allows for scanning). The API asks and waits, as for directory lookups (`askDirectory`):

- The API checks the person (member or above, see 5) and that the repository is visible to them (`visibleRepository`), inserts a
  `code_request` row (organisation, requester, finding, repository, commit, kind `declaration` or `usages`, state, result), sends a
  `code.fetch` job with the id only (no retries, expires in 2 minutes) and polls the row. A declaration answers within 28 seconds or
  the request ends with "try again"; a search of usages may need a clone, so the browser polls (`202` and an id) for up to 2
  minutes.
- The worker checks the row again (organisation, repository, commit, the requester's visibility), reads, writes the result, and the
  API **deletes the row when it hands the result over**. A sweep deletes rows older than 10 minutes in any state. The response is
  sent with `Cache-Control: no-store`; the browser keeps it in memory for the open page only.
- **Reading a file**: GitHub, Gitea and Forgejo repositories whose forge and API address are known (a connection, a write access
  row, or the address recognised) go through the contents API at the commit (`readFile`: 1 MB per file, 2 MB per response, the
  address policy and timeouts it already has). Everything else, and every search of usages, uses a **shallow clone of that one
  commit** with the hardened git of the scans (no configuration, hooks, symlinks, submodules or LFS, `GARNETOPS_MAX_REPO_MB`, a
  2-minute limit) into a fresh directory under `GARNETOPS_SCANNER_WORK_DIR` that is removed in `finally`. Nothing in the repository
  is executed.
- The search reads regular files only, UTF-8 text up to 1 MB each, skips `node_modules`, `vendor`, `.git`, build output and
  binary files, and stops after 20,000 files or 30 seconds. Paths are the repository's relative paths, normalised and checked
  (no `..`, no absolute paths, no control characters).
- Every value is cleaned like scanned text for the model (control, invisible and bidirectional characters removed) before it is
  stored in the row. A line longer than 2,000 characters is cut and says so.
- Rate limits: 30 requests a minute per person, 200 an hour per organisation (`rate_limit`); one clone at a time per organisation,
  two in total, so code views never starve scans.

Viewing code is audited as `code.viewed` (finding, repository, commit, kind; never the content), because it shows the content of a
repository to a person who may not have the forge account for it.

### 3. Rendering

- **highlight.js** (BSD-3-Clause), the core with a fixed set of languages (JavaScript, TypeScript, JSON, Python, Go, Rust, PHP,
  TOML, YAML, INI, XML, Dockerfile, shell, plain text), bundled and self-hosted, pinned, listed in `docs/COMPONENTS.md`. It is
  chosen by the file name, never guessed from content (no auto-detection: slow and itself a surface).
- The HTML that highlight.js returns is **not inserted as it is**. It is parsed and rebuilt from text nodes and `span` elements with
  `hljs-*` classes only; any other element or attribute is dropped and its text kept. highlight.js escapes its input, so this is
  defence in depth against a bug in a grammar. Files above 256 KB or 5,000 lines are shown without highlighting.
- Colours are semantic tokens of their own (`--code-keyword`, `--code-string`, `--code-comment`, `--code-number`, `--code-title`,
  `--code-meta`, `--code-added-bg`, `--code-removed-bg`, …) in light and dark, contrast-tested in CI like the others. They avoid
  red and the severity colours (AGENTS.md rule 6): removed lines are marked by a sign and a muted surface, not by red. No inline
  styles, so the Content Security Policy stays as it is.
- Line numbers, the highlighted lines and the commit are part of the view; long lines wrap; the view scrolls inside its own area at
  1080p and gains the AI pane beside it at the wide steps (rule 5).

### 4. Code for the AI: an opt-in per organisation

- `ai_settings.context_policy` becomes the switch: `metadata` (default, as today) or `excerpt`. A migration sets every existing row
  to `metadata` and changes the column default from `excerpt` (never used) to `metadata`, before anything reads it.
- Only **admins** switch it on, with a recent sign-in and an acknowledgement that names what leaves: "excerpts of your source code
  go to the model at `<host>`". When the endpoint is outside the private network (ADR 0013, `endpoint_scope` external), the
  acknowledgement names the external host again. Switching on or off is audited (`ai.context_policy_changed`), and Settings →
  External services lists it.
- With `excerpt`, the worker adds to the facts of ADR 0013: the declaring lines of the manifest with five lines around them, and up to
  12 usage hits with five lines around each, at most 6,000 characters in all, read by the worker itself at the scan's commit (the
  browser never sends code to the API). They pass through the same cleaning and secret redaction and go into the untrusted-data
  block. "What the model saw" shows them.
- With `metadata`, the viewer still works for people; the model gets the facts of today and a proposal (6) can change the manifest
  only.

### 5. Who may do what

- Viewing code: **members and above** who can see the repository. Viewers keep seeing findings without code: a viewer role is for
  people who read results, and code is more than a result.
- Asking for an AI code proposal: members and above, AI ready (ADR 0013), the rate limits of ADR 0013.
- Creating the pull request: as ADR 0014 and 0039 (members and above, recent sign-in, write access or the person's connection with
  pull requests switched on).
- Switching code excerpts for the AI on: admins, recent sign-in.

### 6. AI code proposals

A new message kind `proposal` in the finding's thread. The worker asks the model for a JSON answer: a short explanation and a list
of **edits**, each `{ path, find, replace, reason }`. The answer is untrusted and is checked by a pure function in
`packages/core` before anything shows it:

- `path` must be one of the files the model was shown (the manifests, the lockfile is never edited, the files of the usage hits),
  at most 8 files and 40 edits;
- `find` must occur **exactly once** in that file at the commit; `replace` is at most 4,000 characters; the result must be valid
  UTF-8 text without control characters other than tab and newline;
- **refused**: new files, deleted or renamed files, binary files, lockfiles, CI and forge configuration (`.github/`, `.gitea/`,
  `.forgejo/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`), build and install scripts (`Makefile`, `scripts` in
  `package.json`, `setup.py`, `build.rs`, `Dockerfile`), and any change to a manifest other than the version of the finding's
  package or an override or resolution entry for it;
- **the version comes from our data**: the manifest edit is always the deterministic bump of ADR 0014 to a version in `fixed_in`;
  an override the model proposes must name the same package and a version in `fixed_in`. A different version is refused, never
  corrected;
- the proposal records the blob id of every file it was made against.

What survives is stored as the message's `structured` value: the edits and blob ids, **not the files**. The viewer shows it in
tabs, **Before**, **After** and **Changes** (a unified diff computed in the browser from the file read again at the commit and the
edits), labelled "AI suggestion, review every line". A refused edit is shown as refused with the reason; it never reaches a pull
request. Without the opt-in (4) the model only sees facts, so it can only propose the manifest change; the viewer says why.

### 7. From proposal to pull request

"Create pull request" opens the confirmation of ADR 0014 with the full diff, the files, the branch and the credential that will be
used. `POST /api/v1/fixes/prs` takes `{ repositoryId, messageId }` for a proposal (the existing `{ repositoryId, key }` stays as it
is). The API checks the message (its finding is on that repository, its edits are valid again) and queues the job; the worker:

1. reads every file at the head of the tracked branch and refuses with `file-changed` if a blob id differs from the proposal's;
2. applies the edits with the same pure function, re-checked;
3. creates `garnetops/ai-fix-<package>-<version>-<short id>`, writes the files to it with their old blob ids as preconditions (one
   commit per file through the contents API on Gitea and Forgejo; the Git data API on GitHub for one commit), and opens the pull
   request with a fixed template that says **"AI-generated change: review every line before merging"**, names the model, the person
   who asked, the files and the vulnerability ids, and never includes the model's explanation as markup (it goes into a code block
   that cannot be closed from inside);
4. deletes its branch if anything after creating it fails.

It never merges, approves, enables auto-merge, force-pushes or writes to an existing branch (ADR 0014). Audited as
`fix_pr.created` with `kind: "ai"` and the message id. Repositories without a forge API (plain Git) cannot get a pull request; the
viewer offers the change as a patch file to download instead (`git apply`-compatible), audited as `code.patch_downloaded`.

## Threat model

| Threat | Impact | Control |
| --- | --- | --- |
| Source code reaches an external model | Code leaves the customer's network | Off by default; admins only, recent sign-in, acknowledgement naming the host; the address policy of ADR 0013 still applies; excerpts bounded (6,000 characters), secret redaction, audited, "what the model saw" |
| Prompt injection in code or comments | The model proposes a harmful change (exfiltration in CI, a backdoor, a different package) | Excerpts sit in the untrusted-data block; the answer is a list of edits validated by code: only files shown, `find` exactly once, no CI, forge, build or install files, no new files, versions only from `fixed_in`; a human reviews the full diff in GarnetOps and again on the forge; never merged automatically |
| Hostile repository content attacks the viewer (XSS) | Session takeover | highlight.js escapes, its output is rebuilt from text and `hljs-*` spans only, no raw HTML elsewhere, strict CSP without inline script or style |
| A person sees code they may not see | Disclosure of a private repository | Members and above, the repository's visibility checked in the API and again in the worker, audited `code.viewed` |
| Code is kept | Disclosure later, larger backups | Request rows deleted on hand-over and swept after 10 minutes, clone directories removed in `finally`, `no-store`; a proposal stores edits, not files; nothing is in a backup beyond the edits of proposals |
| Path traversal, symlinks, huge files, zip bombs | Reading outside the repository, exhausting the worker | Hardened clone (no symlinks, submodules, LFS), regular blobs only, normalised relative paths, size, file count and time limits, nothing executed |
| Credentials | Token disclosure, writing with a read token | Worker only; the read credential for reading, the write credential only for the pull request (ADR 0014); ids only in jobs; never in a result, a log or an error |
| A stale proposal applied to changed code | A broken or wrong change | Blob ids recorded and required as preconditions; `file-changed` instead of a guess |
| Load from code views | Scans delayed, forge rate limits | Rate limits per person and organisation, one clone per organisation, two in total, timeouts |
| A grammar bug in highlight.js | Slow page, wrong colours | Fixed languages, no auto-detection, no highlighting beyond 256 KB or 5,000 lines, pinned version, listed in COMPONENTS.md |

## Consequences

- People see where a vulnerable package is declared and used without leaving GarnetOps, and can turn an AI proposal into a pull
  request that still needs a human on both sides.
- Organisations that keep `metadata` lose nothing of today: the viewer works, the AI behaves as before.
- The usage search is a search by name, not a call graph; reachability stays the AI's and the person's judgement.
- The API gains no credential: everything that touches a repository stays in the worker.
- Lockfiles are still never edited: the pull request says to regenerate them, as today.
- New dependency: highlight.js (BSD-3-Clause), in the web bundle only.
- Code-level findings (SAST, secrets) are not part of this decision; when they come (Phase 5), the viewer shows their lines the same
  way.
