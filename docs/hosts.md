# Hosts and containers

**Infrastructure → Agents** shows which containers run on your servers, what is in their images, which known vulnerabilities those
images carry, which repository each image was built from, and whether a newer image exists ([ADR 0034](adr/0034-host-agent-for-running-containers.md)).
A small agent on each server reports to GarnetOps; GarnetOps never connects to your servers.

## Switch the module on

Hosts and containers are a module and are **off by default**. Owners and admins see **Infrastructure → Agents** in the menu all
along and switch the module on right there, or under **Settings → Modules → Hosts and containers**. While the module is off, agents
cannot report (their requests are refused), nothing is matched and other members do not see the entry. Hosts and their data are
kept; the agents report again once the module is on.

Once it is on, the **+** next to **Agents** in the menu adds a host, and the menu counts the hosts that need a look: no report for
more than a day, or an open critical or high vulnerability in a running image or in the kernel.

## Add a host

1. **Infrastructure → Agents → Add agent**, or the **+** next to **Agents** (owners and admins). Give the host a name if you like.
2. GarnetOps shows a Compose file with a **one-time code**. The code works for one host, for 24 hours, and is shown only now.
3. On the host, save it as `docker-compose.yml` in an empty folder and run `docker compose up -d`.
4. The host appears after its first report, usually within a minute.

The Compose file runs two containers of the signed image `ghcr.io/lcsfls/garnetops-agent` (same version as this installation):

| Service | Has | Does |
| --- | --- | --- |
| `docker-proxy` | the Docker socket, read-only mount; **no network** | Lets `GET` and `HEAD` requests on seven read paths through to Docker (`/_ping`, `/version`, `/info`, `/containers/json`, `/images/json`, `/images/{id}/json`, `/images/get`) and answers everything else with 403 |
| `agent` | only the proxy's socket; HTTPS to GarnetOps | Lists the running containers, reads each image's packages with syft, reports |

Both run with a read-only file system, no capabilities and `no-new-privileges`; the agent runs as an unprivileged user. A read-only
mount of the Docker socket alone would not stop writes through the Docker API, which is why the agent itself never holds the socket.

### Settings of the agent

| Variable | Default | Meaning |
| --- | --- | --- |
| `GARNETOPS_URL` | (from the snippet) | The address of this installation. **https only.** |
| `GARNETOPS_ENROLMENT_CODE` | (from the snippet) | Used once on the first start; you may remove it afterwards. |
| `GARNETOPS_HOST_NAME` | the container's name | The name the host reports. |
| `GARNETOPS_INTERVAL_HOURS` | `6` | How often it reports (1 to 24). |
| `GARNETOPS_CA_FILE` | none | A CA bundle (mounted into the container) if this installation uses an internal certificate authority. |

The `/tmp` file system of the agent is where syft unpacks an image; make it larger than your largest image (4 GB in the snippet).

## Hosts without Docker: the systemd agent

For a server without Docker choose **systemd service, without Docker** in **Add agent** ([ADR 0037](adr/0037-systemd-host-agent.md)).
The dialog shows three commands to run on the host as root:

```sh
curl -fsSLo garnetops-agent-install.sh https://garnetops.example.lan/api/v1/agent/install.sh
less garnetops-agent-install.sh   # read it before you run it
GARNETOPS_ENROLMENT_CODE='goe_...' sh garnetops-agent-install.sh
```

The script comes from your GarnetOps installation, not from the internet, and installs the agent built for this version: a single
program of about 6 MB for linux/amd64 or linux/arm64, checked against the SHA-256 in the script. It creates the system user
`garnetops-agent`, writes `/etc/garnetops-agent/agent.env` (readable by root and the agent only) and starts
`garnetops-agent.service`, which systemd runs unprivileged and read-only with no capabilities, at most 256 MB memory and 20 % CPU.

The systemd agent reports the running kernel and the **packages installed on the host** (dpkg on Debian and Ubuntu, rpm on the RHEL
family and SUSE, apk on Alpine). GarnetOps matches them like an image's packages; the host page shows them under **Packages on the
host**. A list is sent again only when it changed. It does not see Docker containers; for those use the Compose agent.

- Logs: `journalctl -u garnetops-agent`
- Update: run the install script again (from the updated installation).
- Remove: `systemctl disable --now garnetops-agent`, then delete `/usr/local/bin/garnetops-agent`, `/etc/garnetops-agent`,
  `/etc/systemd/system/garnetops-agent.service` and `/var/lib/garnetops-agent`, and remove the host in GarnetOps.

## What leaves the host

Over HTTPS to this installation only:

- the host name, the agent's and Docker's version and the operating system;
- the running kernel: `uname -r`, the kernel's own version lines (`/proc/version`, on Ubuntu `/proc/version_signature`) and the
  distribution and release Docker names (of Docker's `/info` nothing else is kept);
- per running container: its id, name, image reference, image id, state and start time;
- per image: its id, tags, digests, OS and architecture, and only the OCI labels `org.opencontainers.image.source`, `.revision`,
  `.version`, `.title` and `.created`;
- per image GarnetOps does not know yet: syft's package list (package URL, name, version, type);
- systemd agent: the packages installed on the host (package URL, name, version, type), only when the list changed.

Never: file contents, paths inside images, environment variables, command lines, secrets, or the images themselves.

## How a host proves who it is

On its first start the agent creates an Ed25519 key pair; the private key stays in the agent's volume (mode 0600). It enrols with the
one-time code and its public key. Every later request is **signed** with that key, over the method, path, time, a random nonce and the
body: GarnetOps accepts a signature within five minutes and only once. **Remove a host** (owners and admins) and its key stops working
at once; stop the agent on the host as well.

Codes that were not used yet are listed under the hosts table and can be withdrawn.

## Vulnerabilities

GarnetOps matches each image's packages against the **local** vulnerability database (grype, as for repositories) when the package list
arrives and again after every update of the database. The host page shows open vulnerabilities per container; the image page lists
them with the package, the fixed version and whether it is known to be exploited. These findings belong to the image: they do not
change the findings, grades or quality gates of repositories.

## The host's kernel

Containers use the kernel of their host, so a flaw in the kernel (such as a use-after-free in the TCP code) is not in any image.
The agent therefore also reports the **running kernel**, and GarnetOps names it as the distribution's package and matches it like any
other package:

| Distribution | Package and version from |
| --- | --- |
| Ubuntu | `/proc/version_signature` (`Ubuntu 6.8.0-45.45-generic` → `linux-image-6.8.0-45-generic` 6.8.0-45.45, source `linux`, `linux-hwe-*` or `linux-aws` and so on) |
| Debian | `/proc/version` (`Debian 6.1.112-1`) |
| RHEL, AlmaLinux, Rocky, CentOS Stream, Oracle Linux (also UEK), Amazon Linux | `uname -r` (`5.14.0-427.13.1.el9_4.x86_64` → `kernel` 5.14.0-427.13.1.el9_4) |
| Alpine | `uname -r` (`6.6.58-0-lts` → `linux-lts` 6.6.58-r0) |
| SUSE and others | not checked yet; the host page says so |

**What "affected" means, and what it does not.** The host page says **Affected** when the running kernel has a version in which the
distribution lists a flaw as not fixed. It does **not** say the flaw can be exploited on that host: that depends on the host's
configuration (for example which network features its services use, or a live patch), which the agent does not see. The page says
this next to every result.

- **No fix yet** is shown as such. When the distribution ships a fixed kernel, the page names the fixed version; the host stays
  affected until the new kernel runs, which needs a restart.
- **Ratings differ by source.** The distribution's rating is shown first, the highest CVSS score of any source next to it (for
  example "High · CVSS 9.8" when the kernel's own CVE team rates higher than the distribution).
- The kernel is matched again after every update of the vulnerability database, so a flaw published later shows up without a new
  report from the agent.

## Every link leads to the exact result

- An image whose `org.opencontainers.image.source` label names a monitored repository (`https://git.example.com/team/app`, with or
  without `.git`) is **linked to it**. The host page shows the repository next to the container, the image page shows it with the
  revision it was built from, and the repository page lists **Running containers**: which host runs which container built from it.
- A container leads to its image, an image to the hosts that run it and to its repository.
- **Is it the latest?** With the `org.opencontainers.image.revision` label, GarnetOps compares the running commit with the
  repository's last scan: *the latest scanned commit*, *an older commit* (it was scanned before, with the date), or *a commit
  GarnetOps has not scanned* (newer than the last scan, another branch, or a local build). Shown on the host, the image and the
  repository page.
- A private repository (ADR 0030) is linked only for the people who see it.

Add the label when you build your images, for example with `docker build --label org.opencontainers.image.source=https://git.example.com/team/app`
or the `LABEL` instruction; GitHub's and Gitea's build actions set it by default.

## Newer images (optional)

**Settings → External services → Checks of public container registries** (owners and admins, recent sign-in, an acknowledgement). Off by
default, because it sends the names and tags of your running images to their public registries (Docker Hub, GitHub Container
Registry, Quay and others), without credentials. Once a day per image reference GarnetOps asks:

- whether the tag now points to **a newer build** (a `HEAD` of the manifest, which Docker Hub does not count as a pull);
- whether a **newer version tag of the same shape** exists (`1.27.3` → `1.27.4`, `1.28.0` or `2.0.0`; `-alpine` stays `-alpine`;
  release candidates are not suggested for stable tags), shown as a patch, minor or major step.

Limits: public addresses only, HTTPS on port 443, no redirects except to the registry's token service, at most 300 references per
organisation and day, one request a second, 4 MiB per answer. Private registries and registries on other ports are not checked.
If your own resolver is slow, **Public DNS for public names** under Settings → External services can resolve the registries through
Cloudflare, Google or Quad9 next to it ([ADR 0035](adr/0035-public-dns-for-public-names.md)).

## Roles and the audit log

| | Viewer, member | Admin, owner |
| --- | --- | --- |
| See hosts, containers, images, findings | yes | yes |
| Create and withdraw codes, remove hosts | no | yes |
| Switch the module or the registry check | no | yes (the registry check with a recent sign-in) |

The audit log (filter **Hosts**) has: code created and withdrawn, host added by its agent, host removed and renamed, registry check
switched on and off, module switched on and off.

## Limits and what is not tested

- Docker only (the Docker API on a Unix socket); no Kubernetes and no Podman without its Docker API.
- The kernel check cannot see live patches, whether a vulnerable feature is in use, or kernels that a reboot would switch to.
- At most 1 000 containers and 500 images per report, 50 000 packages per image.
- Tested with a fake Docker API, a stand-in syft and fake registries, and once with the real agent image against a real Docker daemon
  and a stand-in server; **not** against real registries or a real installation over the internet.

## API

- For the agent (signed, no cookies): `POST /api/v1/agent/enrol`, `POST /api/v1/agent/inventory`, `POST /api/v1/agent/packages`.
- For people: `GET /api/v1/hosts`, `GET /api/v1/hosts/{id}`, `PATCH` and `DELETE /api/v1/hosts/{id}`, `GET` and `POST /api/v1/hosts/enrolments`,
  `DELETE /api/v1/hosts/enrolments/{id}`, `GET /api/v1/hosts/images/{imageId}`, `GET /api/v1/hosts/by-repository/{repositoryId}`,
  `GET` and `PUT /api/v1/hosts/settings`. Every route answers 409 `module-off` while the module is off.
