# ADR 0003: Technology stack

- Status: accepted
- Date: 2026-10-19
- Decided by: maintainer, following the recommendation below

## Context

Restow, by the same copyright holder, already
runs on a TypeScript stack with better-auth and shadcn/ui; reusing that
knowledge and code reduces risk. Every dependency must pass rule 3 of
`AGENTS.md` (resale and hosting without license conflicts).

## Decision

| Area | Choice | License |
|---|---|---|
| Language, runtime | TypeScript (strict), Node.js 24 LTS (24.7 or newer) | Apache-2.0, MIT |
| Monorepo | pnpm workspaces (via corepack) | MIT |
| API | Hono on `@hono/node-server`, zod validation, errors as RFC 9457 problem details | MIT |
| Database | PostgreSQL 16+, Drizzle ORM and drizzle-kit migrations | PostgreSQL, Apache-2.0, MIT |
| Development database | `embedded-postgres` (no Docker needed on a dev machine) | MIT |
| Jobs | pg-boss (queue in Postgres, no Redis) | MIT |
| Auth | better-auth with two-factor (TOTP), passkey, SSO/generic OAuth; LDAP via ldapts | MIT |
| Web | React 19, Vite, TanStack Router, Query and Table, Tailwind CSS v4, shadcn/ui (copied), Radix, lucide-react, Motion (core) | MIT, ISC |
| Localisation | i18next with ICU, English source, German first translation | MIT |
| SSH | ssh2 | MIT |
| Crypto | Node.js `crypto` only (AES-256-GCM, X25519, ML-KEM-1024, Ed25519, HKDF, Argon2id); no third-party crypto | MIT |
| Scanners | syft and grype as separate binaries, run by the worker in a sandbox | Apache-2.0 |
| Lint, format | Biome | MIT, Apache-2.0 |
| Tests | Vitest, Playwright | MIT, Apache-2.0 |

Astryx was not chosen: it is in beta, uses StyleX instead of Tailwind and would
not let us reuse Restow's kit.

### Repository layout

```
apps/api       HTTP API, auth, SSE streams
apps/web       React single-page app
apps/worker    pg-boss consumer: clone, SBOM, scan, SSH inventory
packages/db    Drizzle schema, migrations, query helpers
packages/core  shared types, crypto (envelope encryption, SSH keys), pagination, problem details
packages/i18n  translations (en, de)
```

### Process model

The API and the worker are separate processes with separate privileges. Only
the worker runs scanners and opens SSH connections; only the worker can decrypt
SSH private keys and forge credentials. The API can encrypt but not decrypt
those secrets (see ADR 0004).

## Amendment 2026-10-21: Node.js 24

Raised the minimum runtime from Node.js 22 to **Node.js 24.7** (decided by the
maintainer). Node.js 24 is the active LTS line and its `node:crypto` provides
two things we need without third-party native code:

- **Argon2id** (`crypto.argon2`), which `AGENTS.md` requires for passwords;
  better-auth's default (scrypt) is replaced by `@garnetops/core/password`.
- **ML-KEM** (`crypto.encapsulate` / `decapsulate`, via OpenSSL 3.5) for the
  hybrid post-quantum vault (ADR 0004, amendment of the same date).

The alternative, staying on Node.js 22 and adding `@node-rs/argon2`, was
rejected: it adds a native dependency and still leaves no ML-KEM.

## Consequences

- One language end to end, shared types between API and web.
- No Docker required for local development; production ships as Docker Compose.
- Native scanner binaries must be fetched per platform with checksum
  verification and pinned versions.
