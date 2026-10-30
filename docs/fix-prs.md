# Fix proposals and fix pull requests

For an open finding that has a fixed version, GarnetOps can open a **pull request that raises the
version** of the vulnerable dependency. You review it; GarnetOps never merges, approves or
pushes to your default branch. Design and threat model: ADR 0014.

This is optional and **off for every repository** until an owner or admin turns it on for it.
Scans, quality gates and notifications never depend on it.

## Fix proposals

**Code → Fix proposals** lists one proposal per package and manifest (for example `lodash` in
`web/package.json`) for all open findings that have a fixed version:

- **Package**, installed version and the proposed version. The proposal is the **lowest version
  that fixes all open vulnerabilities of the package**, in the installed major release if that is
  possible. If only a later major release fixes it, the row says **Major upgrade**. The version
  always comes from the vulnerability data, never from the AI.
- **Fixes**: the worst severity and how many vulnerabilities the new version fixes.
- **Repository**, **file** (the manifest) and **dependency** (direct or transitive) on wide screens.
- **AI suggestion** on very wide screens and in the detail pane: if you asked the AI about one of
  the findings, its summary is shown as read-only text with a label. It does not influence the
  proposal.
- **Status**: the pull request if there is one (waiting, open, with its number as a link to the
  forge), the **Create PR** button (or **Create PR as *your account***, below), or the reason why
  GarnetOps leaves the change to you.

Sort by package, fixes, repository, ecosystem or status; filter by "can be opened" or "by hand",
severity, repository, ecosystem and pull request state; search for a package, a CVE or a file.
The filters live in the address. A click on a row opens the details (a pane on wide screens, a
drawer below).

The **Pull requests** view lists every pull request GarnetOps opened, with its status, including
merged and closed ones whose proposals are gone.

### What GarnetOps changes, and what it leaves to you

GarnetOps edits **one version string in a manifest**, as text. It changes nothing else: comments,
formatting, line endings and the order of keys stay as they are.

| Ecosystem | File | What is edited |
| --- | --- | --- |
| npm | `package.json` | `dependencies`, `devDependencies`, `optionalDependencies`; the operator (`^`, `~`, `>=`, none) stays |
| Python | `requirements*.txt` | pinned `==` lines |
| Composer | `composer.json` | `require`, `require-dev`; the operator stays |
| Go | `go.mod` | `require` lines; same major version only |
| Cargo | `Cargo.toml` | `name = "1.2.3"`, `{ version = "1.2.3", … }`, `[dependencies.name]`, also `dev-` and `build-` dependencies |

**Lockfiles are never changed.** The pull request says so: your CI or a developer regenerates
the lockfile (`package-lock.json`, `yarn.lock`, `go.sum`, `Cargo.lock` …) and pushes it to the
branch. GarnetOps does not run a package manager and executes nothing from your repository.

These are shown as **by hand**, with the reason:

- **Transitive** dependencies (another package pulls them in): update the parent, or add an
  override or resolution. Go modules marked `// indirect` count as transitive.
- A requirement that is a range (`>=1 <3`, `1.x`, `||`, `*`), a git or path source, a workspace
  entry, an alias, a `replace` directive, a package declared twice, hash-pinned requirements, a
  new major release of a Go module (a new import path).
- The manifest already allows the fixed version: only the lockfile needs an update.
- Maven (`pom.xml`), Gradle, Poetry, Pipfile, Bundler, NuGet, containers and everything else.
- Repositories scanned before this feature existed: scan again.
- Packages that only a child manifest of a workspace declares: the child manifest is not
  looked at yet.

The manifests are read during the scan, from the commit that was scanned, as data. If the file on
the forge differs from the one the scan saw when you press **Create PR**, GarnetOps refuses
("The file changed after the last scan") and you scan again first.

## Turning it on for a repository (owners and admins)

Open the repository page, **Fix pull requests → Turn on …**. You need a sign-in from the last ten
minutes. Create a **token on the forge that can only write to this repository** and paste it:

| Forge | Token |
| --- | --- |
| **GitHub** and GitHub Enterprise Server | a *fine-grained personal access token* for **this repository only**, repository permissions **Contents: Read and write** and **Pull requests: Read and write**, and nothing else. A classic token with the `repo` scope reaches every repository of its owner; GarnetOps shows a warning if the forge says so |
| **Gitea** and **Forgejo** | an access token with the scope **`write:repository`**, owned by a user who has write access to this repository only (best a dedicated bot user). These forges cannot limit a token to one repository themselves |
| Plain Git over SSH or HTTPS | not supported: there is no pull request to open |

The forge is suggested from the repository address; the API address is filled in
(`https://api.github.com`, `https://<host>/api/v3` for GitHub Enterprise Server,
`https://<host>/api/v1` for Gitea and Forgejo). Change it only for a forge under a sub-path.
Only `https` addresses on your network or on the internet are accepted; loopback, link-local and
cloud metadata addresses never are. Certificates are always verified. For a forge with a
certificate from your own CA, add that CA to the worker container (`NODE_EXTRA_CA_CERTS`).

The token is stored encrypted, is **separate from the read token or deploy key** that scans use,
is opened only by the worker, and is shown nowhere afterwards. The worker checks it right away
(**Token works** / **Token does not work**, with the reason) and again whenever you press
**Check again**. **Replace token …** deletes the old one; **Turn off …** deletes it and switches
the feature off. Pull requests that are already open stay on the forge.

The repository page shows the state: **On / Off**, who turned it on and when, the forge, the API
address and the result of the last check.

## In your own name, with your connected account

Instead of a write token per repository, each person can let GarnetOps open fix pull requests
**in their own name** with their own connected account ([connected-accounts.md](connected-accounts.md),
[ADR 0039](adr/0039-fix-pull-requests-through-connected-accounts.md)). This is **off for every
connection** until its owner switches it on under **Settings → Connected accounts → Pull
requests** (recent sign-in, and a confirmation of what the token will be used for). Nobody else,
admins included, can switch it or use the account.

A proposal then offers **Create PR as *your account name*** when you have a connection with pull
requests on, on the **same forge (host)** as the repository. The pull request is created by your
account, so the forge shows it as yours and its own permissions apply: the worker asks the forge
before every pull request whether your token may push to the repository, and refuses otherwise
("The token cannot push to this repository"). The repository does not need a write token for
this; if it has one, **Create PR with the repository token** stays available next to it.

Everything else is the same: one branch, one changed manifest, the same text, nothing merged.
The audit log records the request with `via: "connection"`. If the connection is removed, given a
new token, or has pull requests switched off before the worker starts, the request fails ("The
connected account it was requested with is gone …"); it never falls back to the repository's
token.

## Creating a pull request

Members, admins and owners can press **Create PR** on a proposal of a repository that has fix
pull requests on, or **Create PR as *account*** with their own connected account (above). Viewers
cannot. You are asked to confirm what will happen and, if your sign-in
is older than ten minutes, to sign in again. GarnetOps then, in the background:

1. creates the branch `garnetops/fix-<package>-<version>` from the repository's tracked branch;
2. changes the one manifest on that branch;
3. opens a pull request into the tracked branch with a fixed text: the package, old and new
   version, the file, the vulnerabilities fixed (identifiers and links, severity), a note that
   lockfiles must be regenerated, a warning for major upgrades, and "Created by GarnetOps at the
   request of *your name*. Review before merging."

If a step fails, the branch it made is deleted and the proposal shows the reason ("The file
changed after the last scan", "A branch with this name already exists", "The forge rejected the
write token" …). A change can have one live pull request at a time. Up to 10 pull requests a
minute per person and 100 an hour per organisation. Every request and every result is in the
audit log (filter **Fix PRs**).

### Status

The status of an open pull request (open, merged, closed) is read from the forge **every 15
minutes** and when you press **Refresh status**. Webhooks are not used. A merged pull request
disappears from the proposals with the next scan that no longer finds the vulnerability.

## Renovate configuration

If you run your own Renovate, the repository page has a **Renovate config** button: a
`renovate.json` for the vulnerable packages of this repository (vulnerability alerts on, and
for each package a rule that keeps Renovate from choosing a version below the proposed one).
Copy it into the repository. GarnetOps never runs, calls or bundles Renovate (it is AGPL-3.0
licensed).

## Security notes

- The write token can only be used by the worker, and only to read the repository, create one
  branch, change one file and open or read one pull request. Nothing in the client merges,
  approves or comments.
- A connected account's token is used for pull requests only after its owner switched that on,
  only for that owner's own requests, and only on the connection's own forge
  ([ADR 0039](adr/0039-fix-pull-requests-through-connected-accounts.md)).
- The API address is fixed when you save the token and is the only place it is ever sent to; no
  redirects are followed.
- Text from packages and advisories is shown in the pull request as inert text (names in code
  spans, no advisory text, no mentions).
- Reasons for failures are short codes; a forge's error text is never stored or shown.
