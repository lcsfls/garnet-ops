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

## Addendum (2026-11): containers and Proxmox VE

- The agent reports, as the additive optional inventory field `insideContainer`, whether the host is itself a container (from
  `/run/systemd/container`, the Podman and Docker marker files, or LXCFS mounts in its own mount table; all readable unprivileged).
  Older agents do not send it and older servers ignore it. For such a host the kernel is not matched (`kernelProblem` `container`):
  it belongs to the machine the container runs on. Earlier kernel findings and open kernel early warnings of the host are removed.
- `kernelPackage` names a kernel only as a package of the reported distribution when its flavour or release tag belongs to that
  distribution; a Proxmox VE kernel (`-pve`) is `proxmoxKernel`, any other mismatch `foreignKernel`. A Debian `/proc/version` names
  the compiler's version too; only a version of the running kernel's own series is taken.
- In a container the install script first runs a transient service with the unit's namespace and seccomp settings
  (`systemd-run --wait`) and stops with a next step (Proxmox VE: enable nesting, or use a VM) if systemd cannot set them up. The
  unit's hardening is not weakened. Without a running systemd (Alpine with OpenRC) the script names the alternatives.

## Addendum (2026-11): what can be patched now (apt)

- The agent reads `/var/lib/apt/lists` (world-readable; no apt run, no network request) and adds the optional inventory field `apt`:
  the sources with their Release fields and the file modification times, and only the installed packages with a newer version
  offered or from a source outside the distribution (bounded: 200 sources, 5 000 packages, 8 versions each). An invalid field is
  dropped without failing the inventory; older servers ignore it.
- GarnetOps stores it with the host (`agent_host.apt_facts`, additive migration) and computes per finding, when the host page is
  read, whether it is patchable now, waiting for the mirror, waiting for `apt update`, only in Ubuntu Pro or without a fix
  (`@garnetops/core/apt`, dpkg's version order in `@garnetops/core/deb-version`). Nothing changes findings, counts, grades or gates.
- Packages from third-party sources are listed as not covered by the distribution's security data; PHP from them is judged by its
  upstream version against the end-of-life data of ADR 0038. RPM and apk follow later.

## Addendum (2026-11): OpenRC

- Hosts that boot with OpenRC (Alpine) get the same binary as the OpenRC service `/etc/init.d/garnetops-agent`. The install script
  detects OpenRC by `openrc-run` (or `/sbin/openrc`) and a running `/run/openrc`, prefers systemd where it runs, and names the
  alternatives where neither runs. The user is created with BusyBox's `addgroup -S` and `adduser -S -D -H` where `useradd` is
  missing. BusyBox wget is accepted for the download with an `https://` address only and without a CA file; the SHA-256 check is what
  protects the binary, as before.
- The service runs under `supervise-daemon` (restart 60 seconds after a failure) as `garnetops-agent`, with `umask 077`,
  `no_new_privs` (OpenRC 0.45 or newer), its pid file under `/run`, and cgroup v2 memory and CPU limits (256 MB, 20 %) that OpenRC
  applies where it manages cgroup v2; `GOMEMLIMIT` keeps the Go runtime below them. The environment file is read into an allow-list
  of names, never run as shell. The agent sets its own umask to 077 under any service manager.
- OpenRC has no sandbox: `ProtectSystem`, `ProtectHome`, private `/tmp` and devices, the system call filter, `MemoryDenyWriteExecute`,
  `RestrictAddressFamilies` and `RestrictNamespaces` are missing. This is accepted because the agent never runs as root (no
  capabilities, nothing kernel-related it could change), owns only its state directory and log, cannot replace its own program,
  only reads world-readable files and talks only to this installation. `docs/hosts.md` lists every difference. The systemd unit is
  not weakened.
- The inventory carries the optional field `serviceManager` (`systemd` or `openrc`), stored as `agent_host.service_manager`
  (migration 0049). `runtime` stays `systemd` for every agent without Docker, so the published meaning of `/api/v1/hosts` does not
  change; `serviceManager` is added next to it.

## Addendum (2026-11): SSH server

- The agent reads, as its unprivileged user and from files only, whether `/usr/sbin/sshd` or Dropbear exists, the program
  interpreter and libpam link of sshd from its ELF headers (else the dynamic loaders), the OpenSSH server's package version from the
  package list, and `/etc/ssh/sshd_config` with its includes (regular files under `/etc/ssh` only, 32 files of 256 KiB at most, host
  keys never opened). Of the configuration it keeps the global values of six authentication settings by sshd's first-value rule,
  OpenSSH's upstream defaults where nothing is set, and the values `Match` blocks set apart. `/etc/shadow` is never read. It is
  sent as the optional inventory field `sshd`; a field that does not fit the schema is dropped without failing the inventory, and
  older servers ignore it. GarnetOps stores it as `agent_host.sshd_facts` (migration 0049, additive).
- `@garnetops/core/sshd` derives, when the host page is read, four report-only findings with fixed severities: password logins
  (medium), root login with a password (high), empty passwords (high), and *sshole*, CVE-2026-123158 (critical: musl, OpenSSH
  without PAM, password logins and an affected OpenSSH). Whether OpenSSH is affected is the vulnerability database's finding once the
  database knows the CVE (the worker reports which watched advisories the database holds; a distribution's backported fix then shows
  as no finding); until then the upstream version below 10.6p2 decides.
- Where the host has the CVE-2026-123158 finding but its configuration does not allow the attack, the finding carries a
  `configurationNote` that says why. Findings from the scanner, their severities, counts, the attention count, grades and gates are
  unchanged: configuration can change back, and the update is still due.
- Not in this version: Dropbear's settings, sshd's command-line options and compiled-in distribution defaults, which users or
  addresses a `Match` block covers, Alpine's `sshd.pam` build, and notifications about configuration findings.
