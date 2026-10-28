# ADR 0027: Web app on SvelteKit

- Status: accepted (2026-10-28), implemented: the whole end-to-end suite (311 tests) passes against the SvelteKit app
- Date: 2026-10-28
- Decided by: maintainer
- Supersedes in part: ADR 0003 (the "Web" row: React 19, TanStack Router, shadcn/ui, Radix, lucide-react)
- Builds on: AGENTS.md rules 1 (security first), 2 (we never break user space), 3 (clean third-party licensing), 5 (layout baseline)
  and 6 (visual language)

## Context

The web app is a React 19 single-page app (about 16,000 lines of TSX, 2,600 lines of framework-free TypeScript). Since ADR 0025
GarnetOps is a developer pipeline only, and a relaunch was planned: the web app on Svelte first, the API in Go later (a separate
ADR). The maintainer's reasons: fewer runtime dependencies in the browser bundle, less framework code to review, and a smaller
supply-chain surface (rule 1).

The browser contract does not change: the same API (`/api/v1`), the same cookies and session handling, the same pages, texts, colours,
icons and layout steps. The end-to-end suite (Playwright, about 300 tests) only drives the browser and does not know React; it is the
acceptance test of the rewrite.

## Decision

1. **SvelteKit with Svelte 5 (runes)**, the framework the Svelte project recommends for applications, built with
   `@sveltejs/adapter-static` as a single-page app: `ssr = false`, one fallback `index.html`, no Node.js server in the web image. Caddy
   serves the files as before (ADR 0007). File-based routes in `src/routes` replace TanStack Router; URL search parameters keep their
   zod schemas (`src/lib/search.ts`), so every filter stays in the URL.
2. **Same look.** Tailwind CSS v4 with the same OKLCH tokens and container queries (base, wide, xwide), the same self-hosted fonts.
   Icons from `@lucide/svelte`, the Svelte package of the same Lucide icon set. The UI components (`button`, `badge`, `dialog`,
   `drawer`, `select`, `field`, action menu, ...) are ported by hand from our own React components; no component library is added.
3. **Data and texts.** `@tanstack/svelte-query` keeps the caching, polling and invalidation behaviour of the React app.
   `packages/i18n` (English source, German) stays unchanged and is read through i18next with ICU messages, wrapped in a small
   reactive store. The better-auth client comes from `better-auth/svelte`.
4. **Strict CSP without `'unsafe-inline'`.** SvelteKit starts the app with one small inline script. SvelteKit's own CSP support in hash
   mode (`csp.mode = "hash"`) computes its SHA-256 at build time; `scripts/csp.mjs` writes the complete policy (our directives plus
   that hash) to `build/csp.txt` and, as a Caddyfile line, to `build/csp.caddy`, which the web image copies to
   `/etc/caddy/csp.caddy` and the Caddyfile imports. The preview server of the end-to-end suite (`scripts/serve.mjs`) sends the same
   header. A changed or injected inline script does not match the hash and does not run. Hashes are the static counterpart of nonces
   for a page that is the same for everyone; there is no server that could mint a nonce per response. SvelteKit's visually hidden
   route announcer has one fixed `style` attribute; `style-src-attr 'unsafe-hashes'` with the SHA-256 of exactly that value allows it
   and nothing else (computed from SvelteKit's own source at build time, checked by `scripts/csp.mjs`). Our own components set no
   style attributes; dynamic values go through `style:` directives, which use the CSSOM.
5. **Framework-free code moves as is**: API client, search schemas, formatting, time zones, markdown parser, notification and toast
   queues, types. Their unit tests keep running.
6. **One switch, no mixed app.** The rewrite is built on a branch and replaces `apps/web` in one release once the whole end-to-end
   suite passes against it. There is no period in which some pages are React and others Svelte.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Script injection through hostile scanned content (CVE text, package names, AI answers) | Svelte escapes every `{expression}`; `{@html}` is not used. Markdown from the model is parsed into tokens and rendered as elements, as before. The CSP blocks any inline script that is not the one hashed at build time. |
| A compromised dependency in the browser bundle | Fewer runtime dependencies than the React app; lockfile, `minimumReleaseAge` and the licence check in CI as before; every new package in `docs/COMPONENTS.md`. |
| The build's inline script changes without the header following | The header is generated from the same build output; the end-to-end suite runs the built app under that header (`vite preview`), so a mismatch fails every test. |
| Session and CSRF handling regress | The API is unchanged; the client keeps sending the same requests (same origin, cookies, the same-origin check in the API). The sign-in, step-up and session-end tests cover it. |

## Consequences

- Users see the same app; nothing in the API, the database or the configuration changes (rule 2). The release that switches is a
  minor one.
- `apps/web` gets new dependencies (`svelte`, `@sveltejs/kit`, `@sveltejs/adapter-static`, `@sveltejs/vite-plugin-svelte`,
  `@lucide/svelte`, `@tanstack/svelte-query`, `svelte-check`; MIT or ISC) and drops React, TanStack Router and lucide-react
  (`docs/COMPONENTS.md`).
- Caddy reads the CSP header from a file the web build writes, instead of a fixed string in the Caddyfile.
- SvelteKit 3 needs TypeScript 6 for the web app; the other packages stay on TypeScript 5.9 for now.
- Biome lints the scripts of `.svelte` files; unused names there are found by `svelte-check`, which sees the templates too.
- Two defects of the React app were fixed on the way: the repository list showed three columns under the wrong headers from the xwide
  step on, and switching the nightly scan off sent the disabled time field as "null" and was refused.
- The Go API is not part of this decision.
