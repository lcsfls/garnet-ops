# cicd-updater SDK (vendored)

`restow-backup-cicd-updater-1.0.0.tgz` is the npm package `@restow-backup/cicd-updater`
1.0.0 (Apache-2.0, same copyright holder as GarnetOps), the client SDK of the optional update sidecar
(ADR 0007). The project has not published a release yet, so the package is built from a
reviewed commit and kept here. `pnpm-lock.yaml` pins its integrity hash.

| Field | Value |
| --- | --- |
| Source | https://github.com/restow-backup/cicd-updater, `packages/sdk` |
| Commit | `b2dd4efd8ff10a5d29ddcfeda762a0ced9a87874` (2026-10-02) |
| Built with | Node.js 24.22.1, pnpm 9.15.9 (the repository's `packageManager`) |
| SHA-256 | `cf7f2946072edbd5fea2504ae2a9788d5eec908d8af461ed4798eb2b30b9e362` |
| Runtime dependency | `zod` ^4.6.5 (MIT) |

Rebuild and compare:

```sh
git clone https://github.com/restow-backup/cicd-updater && cd cicd-updater
git checkout b2dd4efd8ff10a5d29ddcfeda762a0ced9a87874
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @cicd-updater/protocol --filter @cicd-updater/feed \
  --filter @restow-backup/cicd-updater build
cd packages/sdk && corepack pnpm pack
sha256sum restow-backup-cicd-updater-1.0.0.tgz
```

Once cicd-updater publishes signed releases, replace this file with the release asset
(and its SHA256SUMS and Sigstore bundle) or the npm package, and delete this directory.
