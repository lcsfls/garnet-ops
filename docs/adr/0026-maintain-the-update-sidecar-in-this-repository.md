# ADR 0026: Maintain the update sidecar in this repository

- Status: accepted (2026-10-28), implemented; proven only by the next real release run
- Date: 2026-10-28
- Decided by: maintainer
- Supersedes in part: ADR 0007 (decision 4, "The SDK is vendored ... the workflow actions are pinned to the same commit", and the
  consequence "Until cicd-updater publishes signed releases, its image must be built or mirrored by the operator")
- Builds on: AGENTS.md rules 1 (security first), 2 (we never break user space) and 3 (clean third-party licensing)

## Context

ADR 0007 chose cicd-updater (Apache-2.0, same copyright holder) for in-app updates. GarnetOps used it in three ways: the workflow
actions (build, smoke, publish, release-json) pinned to commit `b2dd4ef`, the client SDK as a vendored tarball, and the sidecar image
`ghcr.io/restow-backup/cicd-updater:1.0.0` that operators and the release smoke test were told to run.

That image does not exist. The upstream project is not maintained regularly and never published an image or a release. The release
of v0.0.4 failed in the smoke test at "the sidecar did not start: manifest unknown", and installations that follow the guide get
"denied" when they pull it. A release that depends on an image nobody publishes cannot be made, and an operator cannot verify an image
that has no signature (rule 1).

Options:

1. **Wait for or ask upstream to publish.** No date, and the release stays blocked. Rejected.
2. **Mirror an image built from upstream's commit under our name, outside this repository.** The image would be built by a process
   nobody reviews with the release, and a fix would still need a fork. Rejected.
3. **Maintain the sidecar in this repository** and build, test, sign and ship it with every release. Accepted.
4. Drop in-app updates. Rejected: updates that arrive quickly are part of rule 1 and of the Cyber Resilience Act duties, and the
   sidecar exists and works (ADR 0007, verified on 2026-10-21).

## Decision

1. **The sidecar lives in `updater/`**, copied from upstream at commit `b2dd4efd8ff10a5d29ddcfeda762a0ced9a87874` (the commit
   GarnetOps already pinned for its actions and its SDK). The code of the packages and the actions is unchanged; only packaging changed. `updater/VENDORED.md`
   records the origin, what was copied and left out, every change and why, how to compare with upstream and how to take over upstream
   changes. The code keeps its Apache-2.0 licence (`updater/LICENSE`); the rest of the repository stays AGPL-3.0-only with the
   commercial option (ADR 0006).
2. **An isolated pnpm workspace**, not part of the root one: its own `package.json`, `pnpm-workspace.yaml` and `pnpm-lock.yaml`. The
   root workspace (`apps/*`, `packages/*`), the root Biome configuration (it excludes `updater/`), `pnpm -r typecheck` and `pnpm -r test`
   do not see it, and the root `Dockerfile` and `.dockerignore` do not read it. Reasons: a second, different dependency tree (tsup,
   vitest 5, TypeScript 6, hono) stays out of the application's lockfile, images and audits; upstream's style (line width 100) and TypeScript
   settings stay as they are, so upstream patches apply; the sidecar has a different release risk (it holds the Docker socket) and gets its
   own CI job. The cost is a second lockfile to keep current.
3. **Supply-chain parity** with the root workspace: pnpm 12.14.0, `allowBuilds` limited to esbuild, `minimumReleaseAge` of one day,
   frozen lockfile in CI and in the image build; no dependency beyond upstream's (the resolved versions are unchanged); the Node.js base
   image is the root `Dockerfile`'s pin (one `NODE_IMAGE` digest to review); the Docker CLI and cosign images stay pinned by digest;
   `THIRD_PARTY_NOTICES` is generated from the lockfile and fails on a licence outside the permissive list; every component is in
   `docs/COMPONENTS.md`.
4. **One image, built, tested, signed and released like the app and web images** by `.github/workflows/release.yml`:
   - the build job builds `ghcr.io/lcsfls/garnetops-updater` per architecture on native runners and pushes it by digest, without a tag;
   - **the smoke test runs the upgrade from the previous release on that very image** (`updater-image` is the digest just built);
   - after every build and smoke test passed, the release job tags the index with the release version, signs it keyless with this
     workflow's identity and attaches an SBOM, exactly as for `garnetops` and `garnetops-web`;
   - the workflow uses the in-repo actions (`./updater/actions/build`, `smoke`, `publish`, `release-json`) instead of the external
     ones, so the code that signs a release is reviewed in the same pull requests as the release itself.
5. **`release.json` lists the updater image** under the key `updater`. Checked in the code (`updater/packages/engine/src/release-check.ts`):
   the image plan, the signature verification and the platform check iterate over the services configured in `updater.yaml`
   (`api`, `worker`, `web`), so an extra image entry is ignored; the document rules only require that every image tag equals the release
   version, which the image tag does. The benefit is that the signed `release.json` is a trustworthy place to read the digest to pin
   (`images.updater.digest`). The sidecar never installs this image: it does not update itself.
6. **CI** (`.github/workflows/ci.yml`): the job `updater` runs, inside `updater/`, install with the frozen lockfile, Biome, tsc, the
   tests with their coverage gate, the action pin checks, the notices check, a check that the committed action bundle
   (`actions/lib/release-tools.mjs`) equals its sources, a build of the sidecar plus `config check` of `updater.yaml`, and a check that the
   vendored SDK equals `updater/packages/sdk`. The job `updater-image` builds the image for amd64 (not pushed) and runs its tools and
   `config check` inside it, so a broken Dockerfile shows up in the pull request and not in a release. arm64 is built natively by the
   release workflow.
7. **The SDK stays a vendored tarball** (`vendor/cicd-updater/`). Building it from `updater/packages/sdk` for the root workspace would
   need a built `dist/` before every root `pnpm install --frozen-lockfile` and inside the root `Dockerfile`, and would couple the two
   workspaces. CI instead proves the tarball equals the source (`dist/` file by file).
8. **Operators** pin `CICD_UPDATER_IMAGE=ghcr.io/lcsfls/garnetops-updater:<version>@sha256:<digest from the release>` after verifying
   it with cosign against `https://github.com/lcsfls/garnet-ops/.github/workflows/release.yml@refs/tags/v<version>`
   (`docs/updating.md`).

## Taking over upstream changes

Nothing is pulled automatically. A change is read as an untrusted contribution, applied as a patch to `updater/`, and must pass the
checks of decision 6; changes to `packages/sidecar`, `packages/engine` and `docker/` get the same security review as the API. Security
fixes in `updater/` are released with the normal release process, free of charge for every supported line (rule 1). The steps are in
`updater/VENDORED.md`.

## Threat model

The sidecar mounts the Docker socket, which is root on the host. It replaces the project's `.env` image lines, runs `docker compose`,
reads database backups and verifies signatures. It is opt-in, has no published port and answers only the API with a token.

| What can an attacker reach | How it could happen | Control |
| --- | --- | --- |
| Root on the host through a malicious sidecar image | a poisoned npm package or base image, a malicious upstream patch, a tampered build | lockfile frozen, `minimumReleaseAge`, install scripts only for esbuild, digests for every base image, no new dependencies, review of upstream patches (above), SBOM and keyless signature of the image, the operator verifies the signature with the exact identity and pins the digest |
| Root on the host through a malicious release of the app | a compromised release workflow or maintainer account | unchanged from ADR 0007: the sidecar installs only releases signed by this workflow at the release tag; branch and tag protection are still open (ROADMAP) |
| One compromise reaching both the app and the sidecar | **new with this ADR**: before, the sidecar was signed by a different identity (upstream's); now the same workflow identity signs the sidecar and the releases it accepts | accepted trade-off. The sidecar never updates itself and only runs the digest an operator verified and pinned, so installations that already run a pinned sidecar are not reached by a later malicious one; new installations and operators who change the pin trust the same identity as for the app. Branch and tag protection, required reviews for `updater/` and `.github/` and the maintainers' account security are the control |
| A malicious or broken `release.json` | feed content is hostile input | unchanged: the sidecar validates and verifies signatures and digests before anything is pulled; extra entries (the `updater` image) are ignored |
| A release that cannot be made | the sidecar image is missing or broken | the smoke test pulls the digest it just built; nothing is tagged and no release is public before it passed (ADR 0007) |
| An unwanted outbound connection | the optional self-check of the sidecar reads upstream's release list | off by default and off in `updater.yaml`; documented not to be switched on, because it compares with upstream's versions |
| Release workflow code replaced | the actions used to be external code at a pinned commit | they are in the repository now, so a change is a pull request, reviewed with the release it affects |

Failure of the sidecar must never lose data: unchanged from ADR 0007 (backup first, roll back only when provably safe, otherwise
`needs_attention` and a runbook).

## Consequences

- The release no longer depends on an image that nobody publishes. The first release with this change publishes
  `ghcr.io/lcsfls/garnetops-updater`; **after the first push the package must be made public once** (GitHub package settings), like the other
  two, otherwise the sidecar of the smoke test and operators cannot pull it.
- GarnetOps owns the sidecar's bugs and security fixes, its dependency updates (a second lockfile) and the decision which upstream
  changes to take.
- The sidecar's embedded version stays `1.0.0` (the `version` of `updater/packages/sidecar/package.json`); the image tag and OCI version
  label are the GarnetOps release version. `requiresUpdater` in `.cicd-updater/release-policy.yaml` is compared with the embedded version.
- Protocol identifiers keep their upstream spelling (container label prefix, JSON Schema `$id`, SDK package name). Renaming them would
  break the vendored SDK and the Compose labels for no gain.
- Not verified when this was written: building the image (inside a container build the sandbox's proxy breaks TLS for npm and blocks
  Alpine packages), the release workflow and the upgrade smoke test from 0.0.3 on the new image. They are proven by the next real release run;
  the build stage's steps (frozen install, bundle, `--help`) were run outside Docker from a clean copy of the build context.
- Open: translating the upstream runbook for a run in `needs_attention` into `docs/` (today the docs link to upstream's text at the
  pinned commit), and branch and tag protection.
