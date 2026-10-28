# ADR 0028: Scanner isolation

- Status: accepted (2026-10-28), implemented in 0.0.9
- Date: 2026-10-28
- Decided by: maintainer (a scanner service of its own, with the worker as fallback for older Compose files)
- Builds on: ADR 0004 (vault: only the worker holds the private key), ADR 0007 (Compose stack and updates), ADR 0024 (system status
  page), AGENTS.md rules 1 (security first: "Scanners run in isolated, non-root containers with read-only mounts, no network unless
  required, and CPU/memory/time limits") and 2 (we never break user space)

## Context

A scan has three steps: the worker clones the repository (git, with the repository's token or deploy key), syft builds an inventory
of its packages (SBOM), and grype matches that inventory against the local vulnerability database. syft parses every lockfile,
manifest, archive and binary of the repository: it is the program that reads the most hostile input GarnetOps has.

Until 0.0.8 syft and grype ran as child processes of the worker. The worker container is already non-root, read-only, without
capabilities, with a memory and CPU limit, and every run has a timeout and an environment without secrets. But the worker holds what
an attacker wants most:

- the vault private key (`/vault/private`), which opens every stored token and deploy key of every organisation;
- the database password (`DATABASE_URL` in the worker's environment, readable through `/proc` by any process of the same user);
- outbound network (clones, vulnerability data), so whatever is read can be sent away;
- the deploy key of a scan while its clone runs, in the worker's temporary directory.

A parser bug in syft that lets a crafted repository run code would reach all of it.

## Decision

1. **A scanner service of its own.** A new Compose service `scanner` runs the same app image with
   `node apps/worker/src/scanner.ts`. It runs syft and grype on request and nothing else:
   - `network_mode: none`: no network interface besides loopback, not even the internal one;
   - no vault volume, no database address, no secret in its environment;
   - the clones read-only (`scan-work` volume), the vulnerability database read-only (`vulndb` volume);
   - a read-only root file system, all capabilities dropped, `no-new-privileges`, uid 1000;
   - limits of its own: `GARNETOPS_SCANNER_CPUS` (default 2), `GARNETOPS_SCANNER_MEMORY` (default 4g), 512 processes, a 2 GB
     temporary file system, and the 15-minute timeout per run as before.
2. **The worker talks to it over a Unix socket** on a small shared volume (`scanner-socket`, mode 0700, uid 1000), with plain HTTP:
   `POST /v1/sbom` with the name of a clone returns syft's SBOM, `POST /v1/match` with that SBOM returns grype's report, `GET /v1/health`
   returns the service's release. A clone is named as `scan-XXXXXX/src` below the work directory and nothing else is accepted; the
   resolved path must stay inside it. Answers are capped at 512 MB and parsed by the worker with the same schemas as before. A failed
   run answers with a code only; nothing a tool prints is passed on or logged.
3. **Only the clone is shared.** The worker clones into `scan-work`, an in-memory volume (tmpfs) it writes and the scanner only reads.
   The deploy key, git's home directory and the reports stay in the worker's own temporary directory. Clones are removed after each
   scan, as before.
4. **The worker remains the fallback.** In-app updates replace images, not the Compose file (ADR 0007). An installation that keeps its
   0.0.8 `docker-compose.yml` has no scanner service and no `GARNETOPS_SCANNER_SOCKET`; its worker then runs syft and grype itself,
   exactly as before, and the system status page says so ("In the worker", needs a look) with the way out: download the Compose file and
   `updater.yaml` of the release. The reverse also works: a 0.0.9 Compose file with an older image starts a scanner container that
   only idles (the image has no `scanner.ts`), and that image's worker scans by itself. The release smoke test starts the previous
   release with the current Compose file, so this path is tested on every release.
5. **Updated with the worker.** `updater.yaml` lists `scanner` next to `worker`, so the update sidecar replaces both. The scanner tells
   its release in the health answer; the status page flags a scanner that runs another release than the worker.
6. **Visible.** The worker reports where the scanners run and whether the service answers (at its start, every 15 minutes and whenever a
   scan cannot reach it) into the `scanners` report; the System status page shows it as the row "Isolation". A scan that cannot reach the
   service fails with "The scanner service did not answer"; it never falls back to scanning in the worker, which would undo the isolation
   without anyone noticing.

## Threat model

| Threat | Mitigation |
| --- | --- |
| A crafted repository exploits syft or grype and runs code | The code runs in the scanner container: no network, no vault key, no database address, read-only file system except its own temporary directory, no capabilities, process, memory and CPU limits. It cannot send anything anywhere. |
| The compromised scanner reads stored tokens or deploy keys | They are only in the worker: the vault key is not mounted, the deploy key of a running clone lives in the worker's private temporary directory, tokens only in the environment of the worker's git process. |
| The compromised scanner changes or plants files the worker later trusts | The clones are mounted read-only into the scanner; it writes only to its own temporary directory, which the worker never reads. |
| The compromised scanner answers with crafted reports | They were always untrusted: the worker caps their size and parses them with schemas; findings are data, rendered as text. A forged report can at worst falsify the findings of the scan it answers. |
| Path traversal through the request (`../`, absolute paths, a symlinked clone) | Only `scan-XXXXXX/src` is accepted; the real path must lie inside the work directory. |
| Resource exhaustion (zip bombs, endless recursion, fork bombs) | Per-run timeout, the container's memory, CPU and process limits, a bounded temporary file system. The worker and the database keep running. |
| Another local process talks to the socket | The socket lives on a volume only the worker and the scanner mount, with mode 0700 for uid 1000; the scanner has no network listener at all. |
| An older Compose file silently keeps scanning unisolated | Allowed so that no installation breaks (rule 2), but shown on the System status page as needing a look, with the steps to switch. |

Remaining risk, accepted and written down: while two scans run at the same time (`GARNETOPS_SCAN_CONCURRENCY`, default 2), a
compromised scanner process can read the other clone in the shared volume and falsify the other scan's results with it. It still
cannot send it anywhere. Setting `GARNETOPS_SCAN_CONCURRENCY=1` removes this. Cloning itself (git) stays in the worker, because it
needs the network and the credentials; git does not run hooks or code from a cloned repository, and a clone is shallow and without
submodules or LFS (`apps/worker/src/git.ts`).

## Consequences

- One more container (the same image, no new dependency).
- New Compose volumes `scan-work` and `scanner-socket` (both in memory) and the variables `GARNETOPS_SCANNER_CPUS` and
  `GARNETOPS_SCANNER_MEMORY`. Existing variables keep their meaning; `GARNETOPS_WORK_TMPFS` now sizes the clones' volume as well.
- Existing installations switch by downloading `docker-compose.yml` and `updater.yaml` of the release (docs/updating.md). Until then
  nothing changes for them except the hint on the System status page.
- `GET /api/v1/system/status` gains `scanners.isolation`; nothing existing changes.
