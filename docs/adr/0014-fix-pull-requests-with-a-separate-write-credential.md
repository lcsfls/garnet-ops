# ADR 0014: Fix pull requests with a separate write credential

- Status: proposed (2026-10-21), for review by the maintainer
- Date: 2026-10-21
- Implements: ROADMAP Phase 2 "Fix pull requests: separate write credential, human review
  always" and "Version-bump PRs (own implementation; Renovate is AGPL-3.0)"; mockup page
  "Fix proposals"
- Builds on: ADR 0004 (vault: the API seals, only the worker opens), ADR 0008 (gates are not
  changed by this), ADR 0010 (outbound address rules), ADR 0013 (AI triage; section 8, "the
  seam for fix pull requests")

## Context

For a vulnerable dependency with a fixed version, the cheapest useful help is a pull request
that raises the version. AGENTS.md sets the frame:

- repository credentials are read-only by default; write access for fix pull requests is a
  **separate, explicit opt-in per repository** (rule 1);
- scanned content is hostile and nothing from a scanned repository is ever executed (rule 1);
- LLM output is never merged automatically and never decides anything (rule 1): the model's
  `upgradeTo` is a hint for a human, so the version must come from the vulnerability data
  (ADR 0013, section 8);
- Renovate is AGPL-3.0 and is not bundled (rule 3); we write our own, small version bump;
- a human always reviews; nothing is merged, approved or pushed to the default branch.

## Decision

### 1. A write token of its own, per repository, opened only by the worker

Turning fix pull requests on for a repository means storing a **second** credential next to
the read credential: the **write token**. It is sealed in the vault (new purpose
`forge-write-token`, ADR 0004), bound to its organisation, record and purpose; the API seals
it, **only the worker opens it**, and it is shown nowhere afterwards. The read credential (the
`forge-token` or deploy key used for cloning) is never used to write, and the write token is
never used to clone or scan. Turning the feature off deletes the sealed token. Deleting the
repository deletes it too. The API cannot read it, so the API never calls a forge.

Scopes, explained next to the input field (`docs/fix-prs.md`):

| Forge | Token |
| --- | --- |
| GitHub, GitHub Enterprise Server | fine-grained personal access token for **this repository only**, permissions Contents: Read and write, Pull requests: Read and write, nothing else |
| Gitea, Forgejo | access token with scope `write:repository`, owned by a (bot) user who has write access to this repository only |
| Plain Git (SSH or HTTPS without a forge API) | not supported: there is no pull request to open |

Gitea and Forgejo cannot limit a token to one repository themselves, GitHub classic tokens
with `repo` reach everything their owner reaches. The worker's check (section 5) reads the
`X-OAuth-Scopes` header GitHub sends for classic tokens and stores a **broad-token warning**,
shown on the repository page. It is a warning, not a refusal: GitHub Enterprise Server
installations that offer classic tokens only must still be usable.

Who: **owners and admins** turn it on, replace the token or turn it off, each with a **recent
sign-in (step-up, ADR 0009)** and each in the audit log (`fix_pr.write_access_enabled`,
`fix_pr.write_token_replaced`, `fix_pr.write_access_disabled`). The token, its prefix and its
length are never logged or audited. Replacing a token deletes the old secret.

### 2. Forge, API address and the address policy

The forge kind (`github`, `gitea`, `forgejo`) is chosen by the admin; the repository host
suggests it (`github.com` is GitHub, `codeberg.org` and host names containing `forgejo` or
`gitea` are guessed, anything else must be chosen). Owner and repository come from the
repository address (https, `ssh://` and `git@host:owner/repo` forms are understood). The API
address, the only place the token is ever sent to, is derived (`https://api.github.com`,
`https://<host>/api/v3` for GitHub Enterprise Server, `https://<host>/api/v1` for Gitea and
Forgejo) or typed by the admin for a forge under a sub-path, and must be `https`, free of
credentials, query and fragment, and end with the forge's API path.

The worker applies the rules of ADR 0010/0013 on **every connection**: resolve the host, check
every answer with the shared classifier (loopback, link-local and cloud metadata, unspecified,
multicast and reserved addresses are refused in every notation, mixed answers count as the
strictest), connect **to the address that was checked** (the name travels only as SNI and
`Host`), **no redirects** (a redirect would carry the token to another host), **TLS
verification always on** (a private CA is trusted by adding it to the worker container, not by a
switch), a 15 s time to the first byte and 30 s per request, 2 MB per answer, 3 MB per request,
and **error bodies are never read**: a failure is a short code. Private addresses are allowed:
a self-hosted forge in the customer's network is the normal case.

### 3. Proposals are computed from our own data

The Fix proposals page (`/fixes`, group "Code") lists, per repository and manifest, one
proposal per package that has open findings with a fixed version. The inputs are the findings
(`fixed_in`, locations from the SBOM, package type) and the manifests of the last scan
(section 4). Nothing from the AI is an input.

- **Target version**: for each vulnerability the lowest fixed version in the **same major
  release** as the installed version; only when it has none, the lowest fixed version above it.
  The target is the highest of those, so that one bump fixes all of the package's open
  vulnerabilities. A target in a later major release than the installed version is **marked
  "major upgrade"** and says so in the proposal, the confirmation and the pull request.
  Pre-releases are never proposed (unless the installed version is one). A fixed version is an
  assumption until the next scan confirms it; the pull request says so.
- **Comparison without a dependency**: three small comparators in `packages/core/src/versions.ts`:
  semver-like (npm, Cargo, Composer, Go; up to six numeric parts, pre-releases, build metadata
  ignored), PEP 440 (epoch, pre, post and dev releases, local versions ignored) and a numeric one
  for everything else. A version that does not parse is "unknown", never guessed.
- **Direct or transitive**: a package the manifest next to its lockfile declares is **direct**;
  any other is **transitive** and gets **no automatic edit** (the page says to update the parent
  or add an override). Go's `// indirect` requirements count as transitive. Maven, Gradle, Poetry,
  Pipfile, pnpm workspaces' child manifests and every other ecosystem: "no automatic fix" with the
  reason shown (`unsupported-ecosystem`, `no-manifest`).
- The page shows severity, the number of vulnerabilities fixed, ecosystem, manifest path,
  direct/transitive, a **labelled, read-only AI suggestion** if a triage exists (text only; if
  its `upgradeTo` differs from the target, the page says which one GarnetOps proposes and why),
  and the pull request status. It is sortable, filterable, searchable, with extra columns at the
  `wide` and `xwide` layout steps and a detail pane (a drawer below `wide`).

### 4. Manifests are read at scan time, as data

To know what a repository declares, and which file a pull request may touch, the worker records
the **dependency manifests** of the scanned commit in `repository_manifest`: `package.json`,
`composer.json`, `go.mod`, `Cargo.toml`, `requirements*.txt`. They are read from the clone that
the scan already made, **as text**, by the pure scanners in `packages/core/src/manifests.ts`:
nothing is executed, no package manager or build tool is started, symlinks, submodules and files
that are not regular blobs are ignored, `node_modules`, `vendor` and similar directories are
skipped, at most 300 files of at most 1 MB each, UTF-8 only. Each row holds the git **blob id**
from the commit's tree (what the forge calls the file's `sha`) and the declared dependencies
with their requirement. Only scans of the repository's configured branch replace the rows;
checks of other refs (gate checks) do not. Git commands run with the hardened environment of the
clone (no user or system configuration, no prompts, literal pathspecs).

### 5. Creating the pull request (worker only)

`POST /api/v1/fixes/prs { repositoryId, key }`: **members and above**, never viewers, only on a
repository with write access on whose token did not fail, **recent sign-in required**, rate
limited (10 per minute per person, 100 per hour per organisation, in the `rate_limit` table),
audited as **`fix_pr.created`**. The client names the proposal only; the API computes the
proposals again and takes version, file and expected blob id from them. A partial unique index
allows one live (`queued`, `running`, `open`) request per repository and proposal. The API
queues one job without retries: a retry could open a second pull request.

The worker, with the token open only for the duration of the job:

1. checks that the token may push (`permissions.push`, not archived);
2. reads the head of the **tracked branch** (the repository's configured branch, else the forge's
   default branch);
3. reads the manifest through the contents API at that branch and **refuses with a clear message
   if its blob id differs from the one recorded at the scan** (`manifest-changed`) or if it is
   gone (`manifest-missing`);
4. edits the text with the pure function (below); a refusal is stored as `edit-<code>`;
5. creates the branch **`garnetops/fix-<package>-<version>`** (never reusing a branch that
   exists: `branch-exists`), writes the one changed file to it with the old blob id as
   precondition (the forge refuses the write if the file moved on), and opens a pull request into
   the tracked branch with a **fixed template**;
6. if anything after the branch creation fails, **deletes the branch it made**;
7. builds the pull request link itself from the repository address and the number (the forge's
   `html_url` is ignored) and records `open`.

It **never** merges, approves, comments, enables auto-merge, force-pushes, or writes to the
default branch. The edit endpoints use `PUT contents` on the new branch only.

**The edit** is a text replacement of exactly one version string (a JSON string, a TOML string,
a requirement specifier, a `go.mod` version), found by a strict scanner, so formatting, comments,
line endings (CRLF), a byte order mark and key order stay as they were. Supported: npm
(`dependencies`, `devDependencies`, `optionalDependencies`; the operator `^`, `~`, `=`, `>=` or
none stays), Python `requirements*.txt` (pinned `==` lines), Composer, Go `go.mod` (`require`
lines, same major only), Cargo (`name = "x"`, `{ version = "x", … }`, `[dependencies.name]`).
Refused instead of guessed: invalid syntax, duplicate keys, a dependency declared twice in a
place, ranges that are not one version with an operator, git/path/workspace/URL sources,
hash-pinned requirements, `replace` directives, Go major upgrades (new import path), indirect Go
requirements, a requirement that already allows the target ("only the lockfile needs updating").
Maven's `pom.xml` is **not supported** (XML with properties, parents and profiles is not trivial).
Dockerfile `FROM` bumps are out of scope. **Lockfiles are never edited**; the pull request says
that the project's CI or a developer must regenerate them. The functions are fuzz-tested against
mutated manifests (truncation, odd characters, duplicates, huge files, CRLF, BOM).

**The text** contains the package, old and new version, the manifest path, the vulnerability ids
with links built from our data (NVD for CVEs, the GitHub advisory page for GHSAs, else the first
`https` address in the data) and their severities, the lockfile note, a major-upgrade warning,
and "Created by GarnetOps at the request of `<display name>`. Review before merging". No
advisory text is included. Every value from scanned data or from a person is validated and
rendered **inside a code span that cannot be closed from the inside**, or from a fixed
vocabulary; control, invisible and bidirectional characters are removed. A mention (`@everyone`),
a heading, a link or an image in a package name or a person's name stays inert text. Package
names must match `[A-Za-z0-9@][A-Za-z0-9@/._+~-]*` before they reach a branch name, a commit
message or the forge.

### 6. Status

Each request is a `fix_pr` row: `queued`, `running`, `open`, `merged`, `closed`, `failed`, a
**safe reason code** (never a response body), the branch, the number and the link. The worker
refreshes open pull requests **every 15 minutes** (a light read of `GET pulls/<n>`) and on demand
(`POST /api/v1/fixes/refresh`, members and above, rate limited); if the token fails, the state
stays and the reason is noted. Requests whose worker disappeared end as `failed` (`interrupted`)
after 20 minutes. Webhooks from forges are out of scope. The Pull requests view lists the whole
history, including merged and closed ones whose proposals are gone. Worker-side events are
audited too (`fix_pr.opened`, `fix_pr.failed`, `fix_pr.merged`, `fix_pr.closed`).

### 7. Renovate configuration

For customers who run their own Renovate, the repository page shows a generated `renovate.json`
to copy: `vulnerabilityAlerts` on and one `packageRules` entry per vulnerable package with
`allowedVersions: ">=<proposed version>"`. GarnetOps never runs, bundles or calls Renovate.

## Threat model

| Threat | Mitigation |
| --- | --- |
| **Stolen write token** (database dump, log, backup) | Sealed with the hybrid post-quantum envelope, bound to organisation, record and purpose, so it opens nowhere else; never in the API's memory after sealing, never returned, never in logs, errors or the audit log (tested over every table and the log output). A stolen **plaintext** token is limited by what the admin gave it: one repository (GitHub fine-grained), contents and pull requests. In our code paths it can only create a branch, change one file and open a pull request |
| **Token sent to the wrong place** (redirect, DNS rebinding, a typed address aimed at the network) | The token goes only to the stored https API address; resolve, check and connect to the checked address; no redirects; TLS always verified; loopback, link-local, metadata, unspecified and multicast refused in every notation; admin-only configuration with step-up; the address must end with the forge's API path |
| **Malicious manifest content** (huge files, odd encodings, duplicate keys, comments, deep nesting, hostile names) | Pure text scanners with hard limits (1 MB, 64 nesting levels, 20,000 entries, 10,000 characters per line), strict JSON, refusals instead of guesses, fuzz tests; only the requirement's own text can change (asserted in tests); nothing is executed, no package manager is started; the file must be exactly the blob the scan recorded |
| **A manifest that changes between scan and pull request** | The blob id is checked against the forge before editing, and the forge checks it again as the write's precondition; a change ends in `manifest-changed`, never in an overwrite |
| **Pull request text injection** from package names, versions, CVE ids, display names | Validated identifiers, code spans that cannot be closed, fixed vocabularies, no advisory text, control and bidi characters removed, mentions inert; tested with hostile values |
| **A member abusing Create PR** (spam, mass edits) | Members only on repositories an admin opted in; step-up per action; 10/min per person, 100/h per organisation; one live request per change; audit entry per request with person, package and versions; branches under one prefix; nothing is merged, so every change passes a human review on the forge |
| **Auto-merge or privilege escalation** | No merge, approve, comment, auto-merge or branch-protection call exists in the client; the token should not have those scopes; never a push to the default branch (tested: only the new branch is written) |
| **The AI picks the version** | It does not: the target comes from `fixed_in`; the model's text is shown as labelled read-only plain text |
| **A hostile forge answer** (huge, endless, not JSON, wrong shape, malicious `html_url`) | Size and time limits, schema validation, errors as codes, the link is built by us |
| **Cross-tenant access** | Every query is scoped to the actor's organisation; the worker re-checks organisation and purpose when it opens the token; tested with a token sealed for another organisation |
| **A scanned repository persuading us to edit another file** | Manifest paths are validated repository-relative paths without `..`; the path comes from our own record of the scan, not from the client; locations from the SBOM only map to a sibling manifest |

## Consequences

- Migration 0013 (additive): tables `repository_manifest`, `repository_write_access`, `fix_pr`
  (a partial unique index allows one live request per repository and proposal); secret purpose
  `forge-write-token` (a text column; no schema change).
- New queues `fix-pr.create`, `fix-pr.check`, `fix-pr.refresh` and a schedule `fix-pr.tick`; new
  endpoints under `/api/v1/fixes` and `/api/v1/repositories/:id/write-access` and
  `/renovate-config`; `GET /api/v1/repositories/:id` gains `writeAccess`; new audit actions
  `fix_pr.*`.
- Repositories scanned before this version have no manifests until their next scan; their
  proposals say "scan again" (`no-manifest`).
- The worker needs a network path to the forge's API (the API does not).
- No new dependency.
- Follow-ups, not decided here: editing lockfiles (needs executing a package manager, which we
  do not do), pnpm/npm workspaces (child manifests), Maven/Gradle/Poetry/Pipfile/Bundler/NuGet,
  Dockerfile base images, per-user forge connections with OAuth or a GitHub App instead of a
  token (ROADMAP Phase 1), GitHub-App style installation tokens that expire, webhooks for
  pull request status, opening the pull request as a draft, a stored list of pull request
  reviewers.
