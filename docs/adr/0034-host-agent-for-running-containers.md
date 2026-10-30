# ADR 0034: Host agent for running containers

- Status: accepted (2026-10-29), planned for 0.0.12
- Date: 2026-10-29
- Decided by: maintainer (a signed container as agent, outbound HTTPS to GarnetOps only, the packages of running images matched on
  the server, images linked to their repository by the OCI source label, and an optional check for newer images in public registries)
- Builds on: ADR 0007 (Compose stack, signed images), ADR 0016 (address-checked outbound client), ADR 0025 (focus on the developer
  pipeline), ADR 0028 (scanner isolation), ADR 0029 (early warnings: matching package lists), ADR 0030 (visibility of repositories),
  ADR 0033 (modules), AGENTS.md rules 1, 2, 3 and 7

## Context

GarnetOps knows what a repository depends on. It does not know what actually runs: which images are deployed on which host, whether
those images are the ones built from the scanned repositories, and whether a running image carries a vulnerability that the
repository has long fixed. Teams want that answered without opening SSH to every host and without GarnetOps reaching into their
servers (ADR 0025 removed the agentless SSH inventory for exactly that reason).

The answer is a small agent that the team runs next to Docker, that only reads, and that only talks to GarnetOps over HTTPS.

## Decision

### 1. The agent is a signed container, in two parts

The agent ships as its own image (`garnetops-agent`, same release, signed with cosign like the other images, ADR 0007). The UI hands
out a Compose snippet with two services of that image:

| Service | Docker socket | Network | Does |
| --- | --- | --- | --- |
| `docker-proxy` | the host's socket, read-only mount | none (`network_mode: none`) | Forwards only `GET` and `HEAD` requests on a fixed list of read paths (`/_ping`, `/version`, `/info`, `/containers/json`, `/images/json`, `/images/{id}/json`, `/images/get`) to Docker, on a Unix socket in a volume it shares with the agent; everything else is answered 403 before it reaches Docker |
| `agent` | none, only the proxy's socket | outbound HTTPS to the GarnetOps address | Lists the running containers and their images, reads each image's packages with syft (pinned, checksummed, as in the app image), and reports to GarnetOps |

Both run as non-root users with a read-only root file system, no capabilities and `no-new-privileges`. A read-only mount of the
Docker socket does not make the Docker API read-only, which is why the agent itself never holds the socket: a bug in syft or in the
agent cannot start, stop or create a container. Reading an image (`/images/get`) exports its layers to syft inside the agent
container; nothing of the image leaves the host.

### 2. Talking to GarnetOps: HTTPS on port 443, one-time code, then a key per host

- **Only outbound, only HTTPS.** The agent connects to the address of the GarnetOps installation (`PUBLIC_URL`), verifies its
  certificate against the system store (or a CA file the team sets for an internal CA) and refuses `http://` addresses. Nothing
  connects to the agent. No redirect is followed.
- **Enrolment.** An owner or admin creates an enrolment code (Monitoring → Hosts → Add host). It is 256 random bits, valid for 24 hours
  and for one host, stored only as a SHA-256 hash, and shown once inside the Compose snippet. On its first start the agent creates an
  Ed25519 key pair (the private key stays in the agent's volume, mode 0600) and sends the code and the public key to
  `POST /api/v1/agent/enroll`. The code is spent; the host is created with the public key.
- **Every later request is signed.** `Authorization: GarnetOps-Agent host=<id>, ts=<ms>, nonce=<random>, sig=<Ed25519 signature>` over
  the method, the path, the time, the nonce and the SHA-256 of the body. The API accepts a time within five minutes, refuses a nonce it
  has seen in the last ten minutes, checks the signature against the host's stored public key, and limits the body to 8 MiB. Removing a
  host deletes its key: the agent's next request is refused and it stops reporting.
- No token, password or other secret is ever stored by the server in clear for the agent, and the agent holds no credential of
  GarnetOps users.

### 3. What is reported

At its start and then every six hours (1 to 24 hours, set in the snippet), the agent sends:

1. **An inventory** (`POST /api/v1/agent/inventory`): the host name, the agent's version, Docker's version, the running containers
   (id, name, image reference, image id, state, start time) and the images they use (id, tags, digests, OS and architecture, and only
   the OCI labels `org.opencontainers.image.source`, `.revision`, `.version`, `.title` and `.created`). The answer names the image ids
   whose packages GarnetOps does not have yet.
2. **The packages of those images** (`POST /api/v1/agent/packages`, one image per request): syft's list of packages as package URLs
   (with the distribution qualifier for OS packages), name, version and type, at most 50 000 per image. No file contents, no paths of
   the image's files, no environment variables, no command lines.

Everything the agent sends is hostile input to the server (a compromised host can send anything): strict schemas, lengths cut, control
characters removed, labels other than the five above dropped, shown as text only.

### 3a. The host's kernel

Containers share the host's kernel, so kernel flaws are in no image. The inventory also carries the running kernel: `uname -r`, the
kernel's own `/proc/version` and Ubuntu's `/proc/version_signature` (readable in any container, no extra rights), and the
distribution and release from Docker's `/info` (nothing else of it is kept). The server names the kernel as the distribution's package
(`kernelPackage` in `@garnetops/core/agent`: Ubuntu including hardware enablement and cloud kernels, Debian, the RHEL family, Oracle's
UEK, Amazon Linux, Alpine) and the worker matches it like an image's package, again after every database update. Where the package
cannot be named with certainty (SUSE's release suffix, a missing Ubuntu signature, an unknown distribution) the page says so and
nothing is guessed.

The result is worded as **affected**: the running version is one the distribution lists as not fixed. It is never worded as
exploitable, because exploitability depends on configuration the agent does not see (a feature in use, a live patch). "No fix yet"
is said as such, and the distribution's rating is shown next to the highest CVSS score of any source, since they often differ.

### 4. On the server

- **Matching.** The worker matches an image's package list against the local vulnerability database with grype through the scanner
  service (as early warnings do, ADR 0029), and again after every update of the database. Findings belong to the image and are shown per
  image, host and container. They do not change the findings, grades or gate results of repositories.
- **Linking to the repository.** An image whose `org.opencontainers.image.source` names the address of a monitored repository (compared
  without scheme, `.git`, trailing slash and case of the host) is linked to it. The repository page lists the hosts and containers that
  run images built from it, with the revision label when there is one; a click on a container leads to the image, a click on the
  repository to its page. The link is shown only to people who may see the repository (ADR 0030).
- **Module.** "Hosts and containers" is a module (ADR 0033), off by default. While it is off the agent endpoints answer 409
  `module-off`, nothing is matched and the pages are hidden.

### 5. Newer images (optional, off by default)

For each image reference of a running container (`registry/name:tag`) the worker can ask the registry, without credentials:

- whether the tag now points to another digest than the one running ("a newer build of this tag"), with one `HEAD` of the manifest;
- whether a newer version tag of the same shape exists (`1.27.3` → `1.27.4`, `1.28.0` or `2.0.0`; `-alpine` suffixes kept), from the
  tag list, classified as patch, minor or major.

This sends image names to the registries (Docker Hub, GitHub Container Registry, Quay and others by host name), which is data leaving
the network: an owner or admin switches it on separately, with an acknowledgement that names what is sent where, and it is audited.
Requests go through the address-checked client (public addresses only, HTTPS, TLS 1.2+, no redirects except the registry's token
service on HTTPS), once a day per reference, at most 300 references per organisation and day, one request a second, 4 MiB per answer.
Private registries and registries that need credentials are not supported in this version; their images show "not checked".

## Threat model

| Threat | Control |
| --- | --- |
| The agent (or syft parsing a hostile image) is taken over and uses Docker to take over the host | the agent has no Docker socket; the proxy forwards only `GET`/`HEAD` on seven read paths and has no network |
| Someone sends fake reports for a host | every request is signed with the host's Ed25519 key; time window and nonce stop replays |
| An enrolment code leaks | one host, 24 hours, hashed at rest, shown once; the admin sees which host used it and can remove the host |
| A compromised host sends hostile data (huge lists, script in labels, paths) | schemas, limits per request and per field, only five labels kept, everything rendered as text |
| A host learns about other hosts or the organisation | the agent API returns only which of its own images need packages |
| A compromised host hides the vulnerabilities of an image other hosts run, by sending a false package list for it | an image id names its content, so the first package list of an image stays; a later one is refused (409 `already-known`), and only a host that runs the image may send it |
| Data leaves the customer's network | only between the agent and GarnetOps over HTTPS; registry checks are opt-in and send image names only |
| A registry answer is hostile or huge | 4 MiB cap, schema-checked, tag lists cut to 10 000, no redirect except to the token service |
| SSRF through an image reference | registry hosts must resolve to public addresses only, HTTPS only, port 443 |
| Agent traffic from inside overwhelms the API | rate limit per host, body size limit, one inventory per host at a time |

## Consequences

- New image `garnetops-agent` in the release workflow (signed, with SBOM, like the others), new workspace package `apps/agent`.
- New tables (hosts, enrolment codes, nonces, containers, images, image packages, image findings, image update checks) in one additive
  migration.
- New public API: `/api/v1/hosts` (owners and admins write, members read), `/api/v1/agent/*` (signed, for the agent only), the module
  `hosts` under `/api/v1/organization/modules`, and `running` on repository details.
- Not in this version: Kubernetes, Podman without the Docker API, private registries, notifications about running images, and gates on
  running images.
