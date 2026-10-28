# Components and licensing register

Every library, tool, dataset, font, icon set and external service that
GarnetOps uses, bundles or integrates with is listed here, together with its
version, license, source and how we use it. This file is the license register
required by `AGENTS.md` (rule 3).

**Rules for this file**

- A new dependency is added here in the same PR that introduces it. CI will
  compare this file against the lockfiles once code exists.
- Versions are the exact version in use (or the version evaluated, for planned
  components). Update the row when the version changes.
- A license is only marked as verified after someone read the actual license
  file of that exact version. Until then the status says `to verify`.
- Removed components are not deleted; they move to [Rejected or removed](#rejected-or-removed)
  with the reason, so the history stays traceable.
- Last reviewed: 2026-10-28.

**Status values**

| Status | Meaning |
|---|---|
| `in use` | Shipped or used in the repository today |
| `planned` | Intended for the product, not added yet |
| `candidate` | One of several options, decision pending |
| `integration` | Not shipped by us; the customer runs it and we talk to it over an API |
| `rejected` | Evaluated and not allowed or not chosen (see reason) |

**License check legend:** `verified` = license file read for this version;
`to verify` = taken from the project page, must be confirmed before use.

## In use today (mockup)

These are vendored in `vendor/` for the throwaway mockup.

| Component | Version | License | Check | Source | Use | Attribution |
|---|---|---|---|---|---|---|
| Inter Tight | 5.x (Fontsource) | SIL OFL 1.1 | verified | https://github.com/rsms/inter | UI text font | License file shipped |
| IBM Plex Mono | 5.x (Fontsource) | SIL OFL 1.1 | verified | https://github.com/IBM/plex | Monospace font | License file shipped |
| Lucide | 0.469.0 | ISC (portions MIT, Feather) | verified | https://github.com/lucide-icons/lucide | Icons | License file shipped |
| d3 | 7.9.0 | ISC | verified | https://github.com/d3/d3 | Globe projection | License file shipped |
| topojson-client | 3.1.0 | ISC | verified | https://github.com/topojson/topojson-client | Map data decoding | License file shipped |
| world-atlas (countries-110m) | 2.0.2 | ISC; data Natural Earth (public domain) | verified | https://github.com/topojson/world-atlas | Globe map | License file shipped |

## In use today (application)

Exact versions from `pnpm-lock.yaml`. "verified" means the license file in the
installed package was read on 2026-10-21; Drizzle ships no license file in its
npm packages, so its upstream repository still has to be checked.

| Component | Version | License | Check | Source | Use | Notes |
|---|---|---|---|---|---|---|
| Node.js | 24 LTS (24.7 or newer) | MIT | to verify | https://github.com/nodejs/node | Runtime; `node:crypto` provides Argon2id and ML-KEM (OpenSSL 3.5) | Not bundled until the container images exist |
| @types/node | 24.19.2 | MIT | verified | https://github.com/DefinitelyTyped/DefinitelyTyped | Node.js type definitions (dev) | |
| TypeScript | 5.9.3 | Apache-2.0 | verified | https://github.com/microsoft/TypeScript | Language (dev) | |
| Hono | 4.13.13 | MIT | verified | https://github.com/honojs/hono | HTTP API | |
| @hono/node-server | 2.1.5 | MIT | verified | https://github.com/honojs/node-server | Node adapter for Hono | |
| zod | 3.25.76 | MIT | verified | https://github.com/colinhacks/zod | Validation (API, worker, web search params) | |
| better-auth | 1.7.10 | MIT | verified | https://github.com/better-auth/better-auth | Sessions, accounts, two-factor plugin (TOTP) | Telemetry disabled in `apps/api/src/auth.ts` |
| @better-auth/passkey | 1.7.10 | MIT | verified | https://github.com/better-auth/better-auth | WebAuthn passkeys: second factor and sign-in method (ADR 0017) | Separate package of better-auth 1.7. It verifies with `requireUserVerification: false`, so `apps/api/src/lib/passkey-policy.ts` checks the signed user-verified flag itself |
| @better-auth/utils | 0.5.0 | MIT | verified | https://github.com/better-auth/utils | TOTP (`createOTP`) for replacing the authenticator app (ADR 0017) | Already pulled in by better-auth; now a direct dependency of the API |
| @simplewebauthn/server | 13.3.3 | MIT | verified | https://github.com/MasterKale/SimpleWebAuthn | WebAuthn registration and sign-in verification, used by @better-auth/passkey | Pulls in @peculiar/x509, @peculiar/asn1-* (MIT), @peculiar/utils (MIT), @hexagon/base64 (MIT), @levischuck/tiny-cbor (MIT), asn1js (BSD-3-Clause), pvtsutils (MIT), pvutils (MIT), tslib (0BSD), tsyringe (MIT), reflect-metadata (Apache-2.0) |
| @simplewebauthn/browser | 13.3.0 | MIT | verified | https://github.com/MasterKale/SimpleWebAuthn | WebAuthn ceremonies in the browser (passkey registration and sign-in) | No dependencies; bundled into the web app, no CDN |
| drizzle-orm | 0.45.4 | Apache-2.0 | to verify | https://github.com/drizzle-team/drizzle-orm | ORM and migrations | License from package metadata only |
| drizzle-kit | 0.31.11 | MIT | to verify | https://github.com/drizzle-team/drizzle-orm | Migration generator (dev) | License from package metadata only. Its deprecated `@esbuild-kit/core-utils` dependency is forced to esbuild 0.25.12 (MIT) by a pnpm override in `pnpm-workspace.yaml` (GHSA-67mh-4wv8-2f99); `pnpm db:generate` reports no schema changes |
| pg (node-postgres) | 8.23.1 | MIT | verified | https://github.com/brianc/node-postgres | PostgreSQL driver | |
| pg-boss | 12.38.0 | MIT | verified | https://github.com/timgit/pg-boss | Job queue in Postgres | |
| PostgreSQL | 17 (embedded, dev only) | PostgreSQL License | to verify | https://www.postgresql.org | Database | Production version pinned with the Compose stack |
| embedded-postgres | 17.10.0-beta.17 | MIT | verified | https://github.com/leinelissen/embedded-postgres | Local development database without Docker (dev only) | Ships PostgreSQL binaries; never part of a release |
| tsx | 4.23.15 | MIT | verified | https://github.com/privatenumber/tsx | Runs TypeScript in development | |
| Biome | 2.5.15 | MIT OR Apache-2.0 | verified | https://github.com/biomejs/biome | Lint and format (dev) | |
| Vitest | 4.1.12 | MIT | verified | https://github.com/vitest-dev/vitest | Tests (dev) | 4.1.12 fixes GHSA-qxg6-89mg-rqv8 and GHSA-xp26-3454-mjgp in @vitest/mocker; 4.x no longer depends on tinypool. New transitive packages (obug, std-env 4, tinyrainbow 3, es-module-lexer 2, why-is-node-running, expect-type) are MIT or Apache-2.0 |
| nodemailer | 10.1.7 | MIT-0 | verified | https://github.com/nodemailer/nodemailer | Mail via SMTP from the worker (ADR 0010) | No dependencies; MIT-0 needs no attribution |
| @types/nodemailer | 8.0.2 | MIT | verified | https://github.com/DefinitelyTyped/DefinitelyTyped | nodemailer type definitions (dev) | |
| ssh2 | 1.17.0 | MIT | verified | https://github.com/mscdex/ssh2 | Local SSH test server for the SSH clone tests (dev only) | Pulls in asn1 (MIT), bcrypt-pbkdf (BSD-3-Clause), tweetnacl (Unlicense), safer-buffer (MIT); optional native add-ons (cpu-features, nan, buildcheck; MIT) are not built (`allowBuilds: false`) |
| @types/ssh2 | 1.15.6 | MIT | verified | https://github.com/DefinitelyTyped/DefinitelyTyped | ssh2 type definitions (dev) | |
| ldapts | 9.2.0 | MIT | verified (LICENSE of 9.2.0) | https://github.com/ldapts/ldapts | LDAP client in the worker for the directory sign-in (ADR 0020): bind, search and the message and filter classes. The worker hands it a socket whose TLS trust it decided itself; its own TLS defaults are not relied on. The fake LDAP server of the tests (`apps/worker/test/fake-ldap.ts`) is built on its message classes (dev) | One dependency: strict-event-emitter-types. Needs Node 22 or newer. Pinned exactly; released 2026-09-15 |
| strict-event-emitter-types | 2.0.0 | ISC | verified (package.json) | https://github.com/bterlson/typed-event-emitter | Type-only helper of ldapts: nothing of it is imported at run time (ldapts' `dist` has no reference to it) | `package.json` declares ISC, but the npm package ships no license file: read the upstream repository's license file before the first release |
| OpenSSH client | system | BSD-style (OpenSSH licence) | n/a | https://www.openssh.com | SSH transport for git clones with deploy keys | Invoked as a separate binary by git, never linked |
| grype | 0.120.1 | Apache-2.0 | verified | https://github.com/anchore/grype | Dependency scanning (SCA), separate binary run by the worker | Downloaded by `scripts/fetch-scanners.mjs` with pinned SHA-256 checksums. The pinned version is repeated in `packages/core/src/system-status.ts` for the System status page; a test keeps both equal |
| syft | 1.55.0 | Apache-2.0 | verified | https://github.com/anchore/syft | SBOM / package inventory of every scan, separate binary run by the worker | Downloaded by `scripts/fetch-scanners.mjs` with pinned SHA-256 checksums from the release checksums file (its sigstore bundle not verified yet: no cosign on the dev machine); network lookups disabled |
| git | system | GPL-2.0 | n/a | https://git-scm.com | Shallow clone of linked repositories | Invoked as a separate binary, never linked |
| Svelte | 5.57.3 | MIT | verified | https://github.com/sveltejs/svelte | Web UI (ADR 0027), compiled to plain JavaScript | |
| @sveltejs/kit | 3.1.0 | MIT | verified | https://github.com/sveltejs/kit | Routing, build and the hashed Content Security Policy of the web app (ADR 0027) | Single-page app, no server at run time |
| @sveltejs/adapter-static | 4.0.0 | MIT | verified | https://github.com/sveltejs/kit | Builds the web app as static files for Caddy (dev) | |
| @sveltejs/vite-plugin-svelte | 7.3.1 | MIT | verified | https://github.com/sveltejs/vite-plugin-svelte | Svelte support for Vite (dev) | |
| @tanstack/svelte-query | 6.3.6 | MIT | verified | https://github.com/TanStack/query | Server state in the Svelte app | |
| @lucide/svelte | 1.62.0 | ISC | verified | https://github.com/lucide-icons/lucide | Icons in the Svelte app (the same icon set as lucide-react) | |
| svelte-check | 4.7.7 | MIT | verified | https://github.com/sveltejs/language-tools | Type and template checks (dev) | |
| TypeScript (web app) | 6.0.3 | Apache-2.0 | verified | https://github.com/microsoft/TypeScript | Type checking of the Svelte app (dev); SvelteKit 3 requires it | The other packages stay on 5.9 |
| React, react-dom | 19.3.1 | MIT | verified | https://github.com/facebook/react | Web UI | |
| @tanstack/react-router | 1.170.45 | MIT | verified | https://github.com/TanStack/router | Routing with route guards | |
| @tanstack/router-plugin | 1.168.47 | MIT | verified | https://github.com/TanStack/router | File-based route generation (dev) | pnpm offers "agent skills" from this package; not approved, not used |
| @tanstack/react-query | 5.104.5 | MIT | verified | https://github.com/TanStack/query | Server state | |
| Vite | 8.3.4 | MIT | verified | https://github.com/vitejs/vite | Build and dev server (dev) | |
| @vitejs/plugin-react | 6.1.2 | MIT | verified | https://github.com/vitejs/vite-plugin-react | React support for Vite (dev) | |
| Tailwind CSS, @tailwindcss/vite | 4.3.3 | MIT | verified | https://github.com/tailwindlabs/tailwindcss | Styling (dev, compiled to CSS) | |
| clsx | 2.1.1 | MIT | verified | https://github.com/lukeed/clsx | Class names | |
| tailwind-merge | 3.7.0 | MIT | verified | https://github.com/dcastil/tailwind-merge | Class merging (shadcn/ui convention) | |
| lucide-react | 1.60.0 | ISC | verified | https://github.com/lucide-icons/lucide | Icons | |
| i18next | 26.5.3 | MIT | verified | https://github.com/i18next/i18next | Localisation | |
| react-i18next | 17.1.0 | MIT | verified | https://github.com/i18next/react-i18next | Localisation for React | |
| i18next-icu | 2.6.1 | MIT | verified | https://github.com/i18next/i18next-icu | ICU message format | |
| intl-messageformat | 12.1.4 | BSD-3-Clause | verified | https://github.com/formatjs/formatjs | ICU message parser (used by i18next-icu) | Notice in THIRD_PARTY_NOTICES |
| uqr | 0.1.3 | MIT | verified | https://github.com/unjs/uqr | QR code for TOTP enrolment, rendered locally | Based on Project Nayuki's QR generator (MIT) |
| @fontsource/inter-tight | 5.3.0 | SIL OFL 1.1 | verified | https://github.com/fontsource/font-files | UI font, bundled by Vite | Font license shipped with the build |
| @fontsource/ibm-plex-mono | 5.3.0 | SIL OFL 1.1 | verified | https://github.com/fontsource/font-files | Monospace font, bundled by Vite | Font license shipped with the build |
| @playwright/test | 1.64.1 | Apache-2.0 | verified | https://github.com/microsoft/playwright | End-to-end and 1080p layout tests (dev) | Downloads Chromium for tests; never shipped |
| @types/react, @types/react-dom | 19.3.0 | MIT | verified | https://github.com/DefinitelyTyped/DefinitelyTyped | Type definitions (dev) | |
| @restow-backup/cicd-updater (SDK) | 1.0.0 (commit b2dd4ef) | Apache-2.0 | verified | https://github.com/restow-backup/cicd-updater | Client of the optional update sidecar: API calls, journal sync, maintenance banner, en/de message catalogs (ADR 0007) | Vendored tarball built from the reviewed commit, SHA-256 in `vendor/cicd-updater/README.md`; NOTICE file shipped in the package |
| zod (v4) | 4.6.7 | MIT | verified | https://github.com/colinhacks/zod | Runtime dependency of the cicd-updater SDK and better-call | Installed next to zod 3 used by our own code |

## In use today (container images and CI)

Pinned by digest in `Dockerfile` and `docker-compose.yml` (ADR 0007). Images bundle the
software of their base system under its own licenses; nothing of it is linked into our code.

| Component | Version | License | Check | Source | Use | Notes |
|---|---|---|---|---|---|---|
| node (official image, Alpine) | 24.22.1-alpine3.24 | MIT (Node.js); Alpine packages under their own licenses | to verify | https://hub.docker.com/_/node | Base of the app image (API, worker) | Digest `sha256:6a1c190e…`; npm and corepack removed from the runtime image |
| Caddy (official image, Alpine) | 2.11.7-alpine | Apache-2.0 | to verify | https://github.com/caddyserver/caddy | Web edge: TLS, static web app, reverse proxy, maintenance page during updates | Digest `sha256:d8542f48…`; runs as uid 1000 without file capabilities |
| PostgreSQL (official image, Alpine) | 17.11-alpine3.24 | PostgreSQL License | to verify | https://hub.docker.com/_/postgres | Database of the Compose stack | Digest `sha256:b0f9560a…` |
| Alpine packages git, openssh-client | from Alpine 3.24 | GPL-2.0 (git), BSD-style (OpenSSH) | to verify | https://pkgs.alpinelinux.org | Clones in the worker | Separate programs, never linked (rule 3) |
| GarnetOps updater image (cicd-updater, maintained in `updater/`) | sidecar 1.0.0; image tag = release version | Apache-2.0 | to verify | https://github.com/lcsfls/garnet-ops/tree/main/updater (origin: https://github.com/restow-backup/cicd-updater, commit b2dd4ef) | Optional update service (profile `updater`), ghcr.io/lcsfls/garnetops-updater | Built, smoke-tested, signed (keyless) and listed in `release.json` by our release workflow (ADR 0026); the operator pins a verified digest in `CICD_UPDATER_IMAGE`. Its components are in [the update sidecar](#in-use-today-update-sidecar-updater) |
| GitHub Actions in `updater/actions` (build, smoke, publish, release-json) | commit b2dd4ef | Apache-2.0 | verified | https://github.com/restow-backup/cicd-updater/tree/main/actions | Release workflow: build, smoke, sign (keyless), release.json | In this repository, no longer referenced externally; CI only. They use docker/setup-buildx-action v4.4.1, docker/setup-qemu-action v4.4.0, docker/login-action v4.6.0, docker/build-push-action v7.4.0 (Apache-2.0), sigstore/cosign-installer v4.1.2 (Apache-2.0), anchore/sbom-action/download-syft v0.24.2 (Apache-2.0), all pinned by commit SHA |
| actions/checkout, actions/setup-node, actions/upload-artifact, actions/download-artifact | v7.0.1, v6.5.0, v7.0.1, v8.0.1 | MIT | to verify | https://github.com/actions | CI and release workflows | Pinned by commit SHA |
| gitleaks (image) | 8.30.1 | MIT | to verify | https://github.com/gitleaks/gitleaks | Secret scan of every change in CI | Digest `sha256:c00b6bd0…`; CI only |

## In use today (update sidecar, `updater/`)

The optional update sidecar is maintained in this repository (ADR 0026, `updater/VENDORED.md`),
an isolated pnpm workspace with its own lockfile. It is Apache-2.0 code; the lists below are what
its image runs and what builds it. The full licence texts of the shipped packages are in
`updater/THIRD_PARTY_NOTICES` (generated from the lockfile; CI fails when it drifts, and the
generator fails on a licence outside MIT, ISC, Apache-2.0, BSD-2-Clause, BSD-3-Clause and 0BSD).

**Runtime of the image** (bundled into one file; no `node_modules` in the image):

| Component | Version | License | Check | Source | Use | Notes |
|---|---|---|---|---|---|---|
| Hono | 4.13.12 | MIT | verified | https://github.com/honojs/hono | HTTP API of the sidecar | Text in `updater/THIRD_PARTY_NOTICES` |
| @hono/node-server | 2.1.3 | MIT | verified | https://github.com/honojs/node-server | Node adapter for Hono | |
| yaml | 2.9.1 | ISC | verified | https://github.com/eemeli/yaml | `updater.yaml` and Compose files | |
| zod | 4.6.5 | MIT | verified | https://github.com/colinhacks/zod | Validation of protocol, configuration and release documents | A second copy next to the application's zod (the SDK uses 4.6.7) |
| Node.js (official image, Alpine) | 24.22.1-alpine3.24 | MIT; Alpine packages under their own licenses | to verify | https://hub.docker.com/_/node | Base of the updater image | Same digest as the application image (`NODE_IMAGE`); npm and corepack removed from the runtime stage |
| BusyBox (Alpine base system) | from Alpine 3.24 | GPL-2.0-only | to verify | https://busybox.net | `tar` for volume backups | Unmodified, run as a separate program, never linked (rule 3). The base system of every Alpine image we ship |
| Docker CLI, Buildx, Compose | from `docker:29.8.2-cli` | Apache-2.0 | to verify | https://github.com/docker/cli, https://github.com/docker/buildx, https://github.com/docker/compose | The sidecar drives the host's Docker engine | Copied from the official image, pinned by digest; separate programs |
| cosign | v3.1.3 | Apache-2.0 | to verify | https://github.com/sigstore/cosign | Verifies the signatures of `release.json` and images before an update | Copied from the official image, pinned by digest |
| age | Alpine 3.24 package | BSD-3-Clause | to verify | https://github.com/FiloSottile/age | Optional encryption of database backups | Separate program |
| tini | Alpine 3.24 package | MIT | to verify | https://github.com/krallin/tini | Init process of the container | |
| ca-certificates | Alpine 3.24 package | MPL-2.0 (certificate data), MIT | to verify | https://pkgs.alpinelinux.org/package/v3.24/main/x86_64/ca-certificates | TLS trust store | Unmodified data |

**Build and test tooling** (`updater/package.json`, dev only, never shipped): @biomejs/biome 2.5.15
(MIT OR Apache-2.0), tsup 8.5.1, tsx 4.23.15, vitest 5.0.3, @vitest/coverage-v8 5.0.3, ajv 8.20.0,
ajv-formats 3.0.1, fast-check 4.10.2, @types/node 22.20.4 (all MIT), typescript 6.0.3 (Apache-2.0).
All 101 packages of the lockfile that install on Linux x64 were checked with `pnpm licenses list`:
MIT, Apache-2.0, BSD-3-Clause, ISC, MIT OR Apache-2.0, and MPL-2.0 for lightningcss (a transitive
dev dependency of vite, unmodified, not shipped; the application's lockfile has it too). Nothing
is outside the allowed list.

## Planned: scanning and vulnerability data

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| vunnel | latest stable at start | Apache-2.0 | to verify | https://github.com/anchore/vunnel | planned | Fetches and normalizes vulnerability feeds | Runs on schedule; offline import for air-gap. The System status page shows it as "not set up (planned)" until a builder reports (ADR 0024) |
| grype-db | latest stable at start | Apache-2.0 | to verify | https://github.com/anchore/grype-db | planned | Builds the local grype database from vunnel output | We build our own DB instead of downloading Anchore's |
| syft | latest stable at start | Apache-2.0 | to verify | https://github.com/anchore/syft | planned | SBOM generation for customer repos and our releases | |
| Trivy | latest stable at start | Apache-2.0 | to verify | https://github.com/aquasecurity/trivy | candidate | IaC misconfiguration and secret scanning | Check licenses of bundled policy/check repositories separately |
| gitleaks | 8.30.1 in CI | MIT | to verify | https://github.com/gitleaks/gitleaks | candidate | Secret scanning in the product | In use in our own CI (see container images and CI) |
| Opengrep | latest stable at start | LGPL-2.1 | to verify | https://github.com/opengrep/opengrep | candidate | SAST engine | Invoke as separate binary only. Needs a rule set with a resale-compatible license |
| CVEfixes | latest release | Code and data licenses differ | to verify | https://github.com/secureIT-project/CVEfixes | candidate | Historical fix examples for AI remediation | Read both licenses before use; attribution in About screen |
| NVD data | API 2.0 | US government work; NVD terms of use | to verify | https://nvd.nist.gov/developers | planned | Vulnerability data via vunnel | Terms require a notice that the product is not endorsed by NVD |
| GitHub Advisory Database | n/a | CC BY 4.0 | to verify | https://github.com/github/advisory-database | planned | Vulnerability data via vunnel | Attribution required |
| OSV data | n/a | Varies per source | to verify | https://osv.dev | planned | Vulnerability data via vunnel | Check each ecosystem source |
| CISA KEV | n/a | US government work | to verify | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | planned | Known exploited flag for gate rules | |
| Distribution feeds (Debian, Alpine, Ubuntu, RHEL …) | n/a | Varies per distribution | to verify | via vunnel providers | planned | OS package vulnerability data | One row per provider once enabled |

## Planned: container image update checks

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| diun | latest | MIT | to verify | https://github.com/crazy-max/diun | candidate | Container image update checks | Or an own implementation against registry APIs |

## Planned: local AI

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| OpenAI-compatible API (protocol) | n/a | n/a | n/a | https://platform.openai.com/docs/api-reference | planned | Interface to the customer's model server | We implement the client; no OpenAI SDK required |
| vLLM | customer's choice | Apache-2.0 | to verify | https://github.com/vllm-project/vllm | integration | Model server run by the customer | Not shipped by us |
| Ollama | customer's choice | MIT | to verify | https://github.com/ollama/ollama | integration | Model server run by the customer | Not shipped by us |
| LiteLLM | customer's choice | MIT (core); `enterprise/` directory has a separate license | to verify | https://github.com/BerriAI/litellm | integration | Optional gateway run by the customer | Never bundle the enterprise parts |
| Model weights | customer's choice | Per model | n/a | n/a | integration | Inference | Customer's responsibility; document that some model licenses restrict commercial use |

## Planned: application stack

Decided in ADR 0003; components move to "In use today (application)" when they are added.

| Component | Version | License | Check | Source | Status | Use |
|---|---|---|---|---|---|---|
| TanStack Table | latest | MIT | to verify | https://github.com/TanStack/table | planned | Data tables |
| shadcn/ui | new-york-v4 registry | MIT | to verify | https://github.com/shadcn-ui/ui | candidate | Component source (copied into repo) |
| Radix UI | latest | MIT | to verify | https://github.com/radix-ui/primitives | candidate | Accessible primitives |
| Astryx | 0.x (beta) | to verify | to verify | https://astryx.atmeta.com | candidate | Alternative design system. Not recommended for now: beta (breaking changes expected), StyleX instead of Tailwind, no reuse of Restow's kit |
| AI Elements | latest | to verify | to verify | https://github.com/vercel/ai-elements | candidate | shadcn-based chat components (conversation, message, code block, reasoning). Project says it moves into shadcn/ui; check whether it needs the Vercel AI SDK or works with our own SSE stream |
| assistant-ui | latest | to verify | to verify | https://github.com/assistant-ui/assistant-ui | candidate | Alternative chat UI for React with shadcn styling and custom backends |
| Recharts | 3.x | MIT | to verify | https://github.com/recharts/recharts | candidate | Charts |
| Motion (formerly Framer Motion), `motion/react` | 12.x | MIT (core library only) | to verify | https://github.com/motiondivision/motion | planned | UI animations | Maintainer's choice. Only the MIT core; Motion+ (paid examples, premium APIs, AI Kit) is a separate commercial license and is not used. Wrap the app in `MotionConfig reducedMotion="user"`; motion stays subtle (rule 6) |

## Planned: authentication and users

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| better-auth SSO / generic OAuth plugins | with core | MIT | to verify | https://www.better-auth.com/docs/plugins/sso | planned | OIDC/OAuth sign-in (Entra ID, Keycloak, Authentik, Google Workspace, Forgejo, GitHub) | Allowed-domain enforcement on our side |
| ldapts | 9.2.0 | MIT | verified | https://github.com/ldapts/ldapts | in use | LDAP / Active Directory bind and group lookup | See "In use" above; better-auth has no first-party LDAP provider, so the sign-in is our own plugin (ADR 0020) |

## Planned: forge integrations (repository linking)

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| Forgejo / Gitea REST API | v1 | n/a (API) | n/a | https://forgejo.org/docs/latest/user/api-usage/ | planned | List a user's repos, webhooks, status checks, PRs | Per-user OAuth or token |
| GitHub REST API / GitHub App | 2022-11-28 | n/a (API) | n/a | https://docs.github.com/en/rest | planned | Same as above | GitHub App preferred over personal tokens (fine-grained, short-lived) |
| GitLab REST API | v4 | n/a (API) | n/a | https://docs.gitlab.com/ee/api/rest/ | candidate | Same as above | Later phase |
| Plain Git over SSH/HTTPS | n/a | n/a | n/a | n/a | planned | Manually added repositories | Deploy key generated per repo |
| isomorphic-git or system git | latest | MIT / GPL-2.0 | to verify | https://github.com/isomorphic-git/isomorphic-git | candidate | Clone/fetch in workers | System `git` is GPL-2.0: fine as a separate binary, never linked |

## Planned: notifications

| Component | Version | License | Check | Source | Status | Use | Notes |
|---|---|---|---|---|---|---|---|
| Nodemailer | 6.x | MIT-0 | to verify | https://github.com/nodemailer/nodemailer | candidate | SMTP delivery | |
| Microsoft Graph `sendMail` | v1.0 | n/a (API) | n/a | https://learn.microsoft.com/graph/api/user-sendmail | planned | Mail delivery for Microsoft 365 tenants | App registration with `Mail.Send` limited by an application access policy to one mailbox |
| @azure/msal-node | 2.x | MIT | to verify | https://github.com/AzureAD/microsoft-authentication-library-for-js | candidate | Client-credentials token for Graph | Or a minimal token request without the SDK |

## Planned: build, release and supply chain

| Component | Version | License | Check | Source | Status | Use |
|---|---|---|---|---|---|---|
| Docker / Compose spec | n/a | Apache-2.0 | to verify | https://github.com/compose-spec/compose-spec | in use | Deployment (`docker-compose.yml`) |
| cosign | 3.x | Apache-2.0 | to verify | https://github.com/sigstore/cosign | in use | Keyless signing of images and release.json, run by the actions in `updater/actions` in the release workflow; also inside the updater image (v3.1.3) |
| Dependabot | n/a (GitHub service) | n/a | n/a | https://docs.github.com/code-security/dependabot | candidate | Dependency updates for our own repo, if hosted on GitHub |

## Rejected or removed

| Component | License | Reason | Date |
|---|---|---|---|
| Renovate (bundled in the product) | AGPL-3.0 (to verify) | Rule 3 forbids AGPL components inside the product (hosted offering). Customers may run their own Renovate; we can generate `renovate.json` for them. Our own version-bump PRs need a separate implementation | 2026-10-19 |
| Semgrep Registry rules | Semgrep Rules License | Forbids use in a competing product or service | 2026-10-19 |
| Google Fonts (CDN) | OFL fonts, but remote delivery | Rule 3: all assets self-hosted; also leaks visitor IPs to a third party | 2026-10-19 |
| Inter, JetBrains Mono (mockup v1) | SIL OFL 1.1 | Replaced by Inter Tight and IBM Plex Mono to match Restow | 2026-10-19 |
| unpkg / jsDelivr at runtime | n/a | Rule 3: no runtime CDNs | 2026-10-19 |
| ldapjs (also as a test server) | MIT | Archived and deprecated by its maintainers, and its server half is not needed: the LDAP test server is built on the message classes ldapts already exports (ADR 0020) | 2026-10-22 |
| d3-geo 3.1.1 (with d3-array 3.2.4, internmap 2.0.3, @types/d3-geo 3.1.0, @types/geojson 7946.0.16) | ISC (types: MIT) | Removed with the attack overview globe (ADR 0025). The mockup under `design/mockup/vendor/` still vendors d3 and topojson-client as a throwaway prototype | 2026-10-28 |
| Natural Earth admin-0 countries 1:110m (via world-atlas 2.0.2) | public domain (data); ISC (packaging) | The world map and globe shapes were removed with the attack overview (ADR 0025); the generator script and the vendored shapes are gone | 2026-10-28 |
| DB-IP IP to Country Lite and IP to ASN Lite | CC BY 4.0 | GeoIP data of the attack overview and external exposure, never bundled; removed with those modules (ADR 0025) | 2026-10-28 |
| MaxMind GeoLite2, GreyNoise Community API, AbuseIPDB API | MaxMind EULA; service terms | Optional GeoIP and reputation sources of the attack overview; removed with it (ADR 0025) | 2026-10-28 |
| crt.sh (Certificate Transparency search) | service terms | Optional subdomain suggestions of external exposure; removed with it (ADR 0025) | 2026-10-28 |
| Wazuh 4.x and 5.0.0-rc1 (customer-run integration) | GPL-2.0 | The XDR integration was removed (ADR 0025); nothing of Wazuh was ever bundled or linked | 2026-10-28 |
| Proxmox VE 8.x and 9.x (customer-run integration) | AGPL-3.0 | The Proxmox VE integration was removed (ADR 0025); nothing of Proxmox was ever bundled or linked | 2026-10-28 |
| UniFi Network (Ubiquiti, customer-run integration) | Proprietary, external product | The UniFi integration was removed (ADR 0025); no code or library of it was ever used | 2026-10-28 |
