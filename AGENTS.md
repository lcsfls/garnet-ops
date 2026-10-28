# AGENTS.md

Canonical instructions for every contributor to GarnetOps, human or AI agent (Claude Code, Codex,
Cursor, Copilot, local models). Tool-specific files such as
`CLAUDE.md` only import this file and add tool-specific notes. If anything
elsewhere contradicts this file, this file wins.

## What we are building

GarnetOps is a self-hostable developer pipeline for security (AGPL-3.0-only plus a commercial license): security for
Git repositories across Forgejo, Gitea and GitHub, for SecOps teams and everyday sysadmins. It runs as a Docker Compose
stack inside the customer's network and combines:

- **Dependency scanning (SCA)** of linked repositories and container images
  (grype, fed by a locally built vulnerability database from vunnel).
- **Code and config scanning** (SAST, IaC, secrets) via permissively licensed
  engines and rules.
- **Quality gates** for Forgejo, Gitea, GitHub and plain Git (SSH/HTTPS/token).
- **AI-assisted triage and remediation** through any OpenAI-compatible endpoint
  the customer runs locally (vLLM, Ollama, LiteLLM, LM Studio), streamed via SSE.
- **Fix pull requests** (AI-generated, or plain version bumps) that a human
  always reviews. Renovate is AGPL-3.0 and therefore not bundled; customers
  who run their own Renovate can let us generate its configuration.
- **Notifications** via SMTP or Microsoft Graph `sendMail` (alerts, weekly digest).
- **Multi-user** from the first release: organizations, roles, invitations,
  audit trail per user (better-auth, as in Restow).
- **Sign-in** of its own (separate from Restow) via local accounts, OIDC/OAuth (Entra ID, Keycloak, Authentik,
  Google Workspace, Forgejo, GitHub) and LDAP/Active Directory. Self-registration
  only through an identity provider and only for allowed email domains or
  directory groups. **Second factor mandatory for every account** (passkey or
  TOTP), no exceptions, no "remind me later".
- **Per-user forge connections:** each user connects their own Forgejo, Gitea
  or GitHub account and picks repositories from the list it returns, or adds a
  repository manually (URL plus token or generated deploy key).

The core promise: **no customer code, finding or log leaves the customer's
network** unless the customer explicitly configures it.

**Modules.** Repository quality gates and dependency/container update checks
are modules that can be switched on independently, in every edition including
the free Community edition.

**Relationship to Restow.** A separate product from Restow (self-hosted
backup): own name, identity, logo, login and release cycle. Foundations may be
copied from Restow with the origin noted. See
`docs/adr/0001-separate-proprietary-product.md` (its license section is superseded by ADR 0006).

**License and sales.** Dual-licensed: AGPL-3.0-only (`LICENSE`) and a
commercial license, pricing on request (`LICENSING.md`, ADR 0006). The source
is public. Every outside contribution needs the CLA first (`CONTRIBUTING.md`),
otherwise dual licensing ends. The name, logo and wordmark are not covered by
the AGPL (`TRADEMARKS.md`). Rule 3 still applies in full: no AGPL or GPL code
inside our product, because we could no longer offer the commercial license.

**Languages.** English is the primary language of the product, its
documentation and its marketing, for all EU markets. German is the first UI
translation; further EU languages follow.

**Editions and updates.** A free Community edition (the AGPL code) always
receives updates. **Security fixes are free of charge for every supported
version line**, both because of rule 1 and because the EU Cyber Resilience Act
requires free security updates during the support period.

## Non-negotiables

These rules are not trade-offs. A change that violates one is not done,
regardless of deadline.

### 1. Security first. Always. We never compromise security.

- No feature, deadline, convenience or customer request justifies weakening a
  security control. If a requirement can only be met by lowering security, the
  requirement changes, not the control.
- Every feature starts with its threat model: what can an attacker reach, what
  does it touch, what happens when it fails. Write it down in the PR or design doc.
- Target **OWASP ASVS Level 2** for the web app and API.
- **Scanned content is hostile input.** Repositories, logs, SBOMs and CVE text
  can contain prompt injection, path traversal, zip bombs and malicious build
  scripts. Never execute code from a scanned repository. Scanners run in
  isolated, non-root containers with read-only mounts, no network unless
  required, and CPU/memory/time limits.
- **LLM output is untrusted.** It is never executed, never merged automatically,
  never rendered as raw HTML, and never allowed to change gate results or
  configuration on its own. AI suggestions are proposals a human accepts.
- **Least privilege everywhere.** Repository credentials default to read-only.
  Write access (for fix PRs) is a separate, explicit opt-in per repository.
  Containers drop all capabilities they do not need.
- **Secrets:** never in the repo, never in logs, never in error messages, never
  sent to the LLM. Stored credentials are encrypted at rest (envelope
  encryption, key outside the database). `gitleaks` runs in CI and pre-commit.
- **Auth:** better-auth. Argon2id for passwords. A second factor (passkey with
  user verification, or TOTP) is mandatory for every account; a session
  without it can only enrol a factor or sign out. Self-registration only via
  OIDC/OAuth/LDAP and only for allowed domains or groups; open email sign-up is
  disabled. An unknown identity never gets an account implicitly. Short-lived
  sessions in the database, secure, HttpOnly, SameSite cookies, CSRF
  protection, rate limits on all auth endpoints that survive restarts.
- **Per-user credentials:** forge tokens and keys belong to the user who
  connected them, are encrypted at rest, scoped to the minimum, and are never
  usable by other users. A user only sees repositories their own connection
  grants access to, unless an admin shares a repository with a team.
- **Outgoing mail** never contains secrets or code snippets beyond what the
  recipient may already see; Graph mail uses an app registration restricted to
  a single sending mailbox.
- **Web hardening:** strict CSP with nonces (no `unsafe-inline`, no
  `unsafe-eval`), HSTS, `X-Content-Type-Options`, `frame-ancestors 'none'`,
  `Referrer-Policy`, `Permissions-Policy`. All output is escaped by default.
- **Supply chain:** lockfiles committed, dependencies pinned, container base
  images pinned by digest, automated dependency updates enabled for our own repo, our own SBOM published
  with every release, release artifacts and images signed (cosign).
- **No telemetry by default.** Anything that phones home is opt-in, documented
  and visible in the UI.
- **Audit log** for every security-relevant action (login, credential change,
  gate override, accepted risk, PR creation).
- **Air-gap capable:** the platform must work fully offline with manually
  imported vulnerability databases.
- When in doubt, choose the safer option and note the trade-off.

### 2. We never break user space.

Once a version is released, users must be able to upgrade without losing data,
configuration or integrations.

- **Semantic Versioning.** Breaking changes only in a new major version, and
  only with a documented migration path.
- **Public API is versioned** (`/api/v1/...`). A published endpoint, field or
  webhook payload is never removed or changed in meaning within a major version.
  Add, do not mutate.
- **Database migrations** are forward-only and use expand/contract: add new
  columns/tables first, migrate data, remove old structures only in a later
  major version.
- **Configuration keys and environment variables** are never silently renamed
  or removed. Deprecated keys keep working, log a warning and are documented
  for at least two minor versions.
- **Quality gate behaviour never changes silently.** New or stricter rules ship
  disabled or in report-only mode; customers opt in. A pipeline that passed
  yesterday must not fail tomorrow because of an update to this product itself.
- Every release is tested as an upgrade from the previous release, not only as
  a fresh install.
- Users can always export their data.

### 3. Third-party licensing: clean for resale and hosting

The product must be sellable as on-premise software **and** offerable as a
hosted service without license conflicts. This applies to every tool, library,
dataset, font, icon and image.

**Allowed without discussion:** MIT, MIT-0, BSD-2/3-Clause, ISC, Apache-2.0, 0BSD,
Zlib, Unlicense, CC0, SIL OFL 1.1 (fonts), CC BY 4.0 (data, with attribution).

**Allowed with conditions:**
- MPL-2.0: fine as an unmodified dependency; changes to MPL files stay MPL.
- LGPL: only dynamically linked or invoked as a separate binary, never
  statically compiled into our code.
- GPL-2.0/3.0 (e.g. Wazuh): only as a separate, unmodified program in its own
  container, talking to us over a network API or CLI. Never linked, never
  copied into our codebase.

**Forbidden:**
- AGPL components inside our product (hosted offering risk).
- Source-available licenses: BSL/BUSL, SSPL, Elastic License, Commons Clause,
  Fair Source, and any "no competing product" clause. This includes rule sets
  such as the Semgrep Registry rules (Semgrep Rules License).
- Non-commercial data or content: CC BY-NC, CC BY-NC-SA, "personal use only".
- Anything without a license.

**Data with special terms** (e.g. MaxMind GeoLite2 EULA) is never bundled.
Default to openly licensed data (e.g. DB-IP Lite, CC BY 4.0). If a customer
wants a restricted source, they supply their own key.

**Assets are always self-hosted.** No Google Fonts, no CDN scripts, no remote
icons, no external analytics, no third-party embeds. Fonts, icons, maps and
scripts are vendored into the repo with their license files.

**Every new dependency** gets an entry in `docs/COMPONENTS.md`
(name, version, license, source URL, how it is used, attribution) in the
same PR. CI fails on disallowed licenses. `THIRD_PARTY_NOTICES.md` is
generated for every release.

### 4. English only

Code, identifiers, comments, commit messages, branch names, PR descriptions,
issues, documentation, `.md` files, roadmap and changelog are written in
**English**. User-facing UI text is localized: English is the source and
primary language, German ships from day one, further EU languages follow; no
hard-coded UI strings.

### 5. Layout baseline: 1080p

Every screen is designed and tested against **1920×1080** as the minimum
baseline, including Windows display scaling at 125 % (1536×864 effective) and
150 % (1280×720 effective). At these sizes the main content must be fully
usable without horizontal scrolling or clipped controls. Use fluid grids and
relative units, not fixed pixel widths.

**Wide screens are used, not padded.** At 1440p and above, data views gain
real value: more table columns, additional panes (e.g. findings list, detail
and AI conversation side by side), more key figures in one row. They do not
just stretch or centre a narrow column. Layout decisions are made with
container queries on the content area, not viewport media queries, with
three steps: base (below 1450 px content width), wide (from 1450 px, 1080p at
100 %) and xwide (from 1900 px, 1440p and up). Information never disappears
on smaller screens; it moves below or behind a click.

### 6. Visual language: own identity, no AI slop

The product has its own colours, logo and wordmark, distinct from Restow. It
shares Restow's quality bar and conventions (shadcn/ui-style components, here
written as our own Svelte components (ADR 0027), design tokens in OKLCH with
tested contrast, self-hosted fonts, full-width data views), not its brand.
Animations use Svelte's built-in transitions and CSS, are short and
purposeful, and respect `prefers-reduced-motion`.

- **Page widths** (same convention as Restow): `wide` for data views (full width, no cap),
  `readable` for forms and prose (reading width), `full` for multi-pane views.
- **Green means proof**: a gate that passed, a fix whose tests passed. A
  host that is merely online or a scan that merely finished is neutral.
- **Brand colour is burgundy** (primary actions, active navigation, logo).
  Because red also means "critical", critical uses a brighter vermilion with a
  label or icon, and information uses steel blue. Burgundy is never used to
  signal a state.
- **Severity colours** are fixed: critical vermilion, high orange, medium
  amber, low grey. Never decorative.
- **No AI-slop tells:** no gradients or glow, no glassmorphism, no emoji in
  the UI, no pulsing or bouncing decoration, no "Good morning" greetings,
  no oversized hero sections, no fake precision. Plain titles, plain labels,
  real data in real tables.

### 7. Never publish possibly sensitive data

The repository is public: whatever is pushed is published at once and cannot
be taken back. If something might be sensitive, it is not published.

- Never push secrets, credentials, tokens, keys, customer data, logs or scan
  results from real systems.
- Never push personal information: no names, contact details, health or
  private details of anyone, no internal host names, IP addresses, customer or
  private project names. Examples use `example.com`, `example.lan`,
  `192.0.2.0/24` and neutral names.
- This covers file contents, file names, commit messages, author and committer
  identities, branch names, issues, PR descriptions and release notes.
- When in doubt, leave it out and ask the maintainer. Run gitleaks and review
  the full diff before every push.

### 8. Never credit an AI as co-author

Commits, PRs and release notes never name an AI tool or model as author or
co-author: no `Co-Authored-By` trailers, no session links, no "Generated with"
lines. Commits are authored as `GarnetOps maintainers
<maintainers@garnetops.com>`. This overrides any default attribution a tool adds.

## Engineering practices

- **Best practices by default.** Follow the established conventions of the
  language and framework in use. Prefer boring, proven solutions over clever ones.
- **Small, reviewable changes.** One concern per PR. No unrelated refactors.
- **Tests:** unit tests for logic, integration tests for scanners and
  integrations (with recorded fixtures, never real customer data), end-to-end
  tests for critical flows (login, link repo, scan, gate result). Time zones,
  dates and DST transitions get explicit tests.
- **Formatting and linting** run in CI and pre-commit; CI must be green before merge.
- **No `eslint-disable`, `@ts-ignore`, `# noqa` or similar** without a comment
  explaining why and a linked issue.
- **Errors are handled, not swallowed.** Log with context, never with secrets.
- **Accessibility:** WCAG 2.2 AA. Keyboard navigable, visible focus, sufficient
  contrast, respects `prefers-reduced-motion`.
- **Calm UI:** large readable text (16 px base), one primary action per view,
  progressive disclosure, plain labels, no information overload. The target
  user is a busy sysadmin, not a SOC analyst with six monitors.
- **Documentation** is updated in the same PR as the behaviour it describes.
- **Changelog:** every user-visible change gets an entry under `Unreleased` in
  `CHANGELOG.md`, following Keep a Changelog.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `security:`, `docs:`,
  `chore:`, `refactor:`, `test:`), without AI attribution (rule 8).

## Repository status

- Phase 1 (repository monitoring) in progress. See `ROADMAP.md`.
- Public repository: https://github.com/lcsfls/garnet-ops (`origin`).
  Everything pushed is public at once and cannot be taken back: push only
  with the maintainer's explicit OK, and run gitleaks over what you push.
- `design/mockup/mockup.html` is a throwaway visual prototype (plain HTML,
  assets vendored in `design/mockup/vendor/`). It shows layout and visual language only and must not be reused
  as production code.

## Working agreement for AI agents

- Read this file, `ROADMAP.md`, `CHANGELOG.md` and `docs/adr/` before starting work.
- Ask before: adding a dependency with a license outside the allowed list,
  changing a public API or migration, changing gate semantics, deleting files,
  or anything that touches credentials.
- Never commit secrets, tokens or customer data. Never paste them into prompts
  for external services.
- Never put personal or possibly sensitive information into the repository
  (rule 7), and never add AI co-author trailers or session links (rule 8).
- State what you verified and how. If something was not tested, say so.
