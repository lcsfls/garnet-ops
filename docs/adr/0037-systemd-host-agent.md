# ADR 0037: A host agent without Docker, as a systemd service

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (a small Go program run by systemd, served by the GarnetOps installation itself, reporting the host's kernel
  and installed packages)
- Builds on: ADR 0034 (host agent, enrolment, signed reports), ADR 0029 (matching package lists), ADR 0033 (modules), AGENTS.md rules
  1, 2 and 3

## Context

The agent of ADR 0034 runs as two containers next to Docker. Many servers that matter run no Docker at all: a database host, a mail
server, a VM with one service. Their risk is in the packages of the operating system and in the kernel, and they should be covered
without installing Docker or a language runtime.

## Decision

1. **A single static Go program** (`apps/host-agent`, standard library only, about 6 MB, linux/amd64 and linux/arm64). It speaks the
   protocol of ADR 0034 unchanged: enrolment with the one-time code, an Ed25519 key per host (the 32-byte seed in the state directory,
   mode 0600), every request signed over method, path, time, nonce and the SHA-256 of the body. A test checks the signed text byte for
   byte against `signingInput` of `@garnetops/core/agent`, and an end-to-end test runs the real program against the API.
2. **What it reads:** `/etc/os-release`, the kernel (`/proc/sys/kernel/osrelease`, `/proc/version`, `/proc/version_signature`) and the
   installed packages: dpkg's status file, apk's database, or `rpm -qa` (run as a separate program with a fixed query format, AGENTS.md
   rule 3). Packages become package URLs in the same form syft writes (distribution, architecture, source package, epoch), so grype
   matches them as it matches an image's packages. Nothing is executed besides rpm; nothing is written besides the state file.
3. **What it sends:** the inventory of ADR 0034 with `runtime: "systemd"`, no containers, the kernel, and the SHA-256 over its sorted
   package URLs. The answer says whether GarnetOps needs the list (`needHostPackages`); only then the list follows
   (`POST /api/v1/agent/host-packages`, at most 50 000 packages, 8 MiB). Unlike an image's list, a host's list changes with every
   update and replaces the previous one.
4. **Matching:** the worker matches the list against the local vulnerability database (queue `hosts.packages`) and again after every
   database update. Findings belong to the host (`host_package_finding`), count in the host's open vulnerabilities and in the menu's
   "needs attention", and do not change repositories, grades or gates.
5. **Installation from the installation itself.** The app image carries both binaries (built in the Dockerfile from a digest-pinned Go
   image). `GET /api/v1/agent/install.sh` returns a POSIX shell script with this installation's address and the SHA-256 of each binary;
   `GET /api/v1/agent/download/linux-{amd64,arm64}` returns the binary. The dialog shows three commands: download the script, read it,
   run it as root with `GARNETOPS_ENROLMENT_CODE` in the environment (never in a URL, so it stays out of proxy and server logs). The
   script checks the binary's checksum, creates the system user `garnetops-agent`, writes `/etc/garnetops-agent/agent.env` (0640) and
   starts the service. It works without internet access, and the agent always matches the server's version.
6. **The service is hardened by systemd:** an unprivileged user, `NoNewPrivileges`, no capabilities, `ProtectSystem=strict`,
   `ProtectHome`, private `/tmp` and devices, kernel and control groups protected, only IP and Unix sockets, a system call filter,
   `MemoryDenyWriteExecute`, at most 256 MB memory and 20 % CPU. HTTPS only (TLS 1.2+, the system's or a configured CA), no redirects;
   plain HTTP exists only in builds with the `e2e` tag that the tests use, never in a release.

## Threat model

| Threat | Control |
| --- | --- |
| The agent is taken over and used against the host | it runs unprivileged under a strict systemd sandbox, holds no Docker socket and no credential, and only reads |
| A tampered binary is installed | the script compares the SHA-256 it was served with over the same HTTPS connection to this installation; the app image that carries the binaries is signed (ADR 0007) |
| The enrolment code leaks through logs or shell history | it is passed in the environment, not in a URL; one host, 24 hours, hashed at rest (ADR 0034) |
| A host sends a false or huge package list | signed by the host's key, schema-checked, 50 000 packages and 8 MiB at most; a host can only change its own list |
| The download endpoints are abused | they serve only the two fixed file names, are rate-limited per address, and hold nothing secret |

## Consequences

- New: `apps/host-agent` (Go), a Go build stage in the Dockerfile and a Go check in CI (both with the same digest-pinned image), the
  binaries in the app image under `/opt/garnetops/agent` (setting `AGENT_BINARIES_DIR`), routes `GET /api/v1/agent/install.sh`,
  `GET /api/v1/agent/download/{target}` and `POST /api/v1/agent/host-packages`, `runtime` and `hostPackages` in `/api/v1/hosts`.
- One additive migration (columns on `agent_host`, table `host_package_finding`).
- Not in this version: Docker containers seen by the systemd agent (use the container agent for that), packages outside the distribution's
  package manager (language packages, binaries in `/opt`), automatic updates of the agent (run the install script again).
