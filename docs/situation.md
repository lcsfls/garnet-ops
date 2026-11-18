# Situation

**Daily → Situation** answers the questions a team asks when a flaw is published: where do we have it, and who has to do what
(ADR 0052). Each open vulnerability is listed once, across everything GarnetOps looks at:

- **repositories** (open findings of the last scan),
- **containers** running on hosts with the agent (findings of their images),
- **hosts** (packages of the host's package manager and the kernel).

Hosts and containers are part of it while the Agents module is on ([hosts.md](hosts.md)). Known exploited vulnerabilities come
first, then by severity and by the number of systems. Filter by **Known exploited**, **Critical** or **High** (each with its
number), by the kind of system, and by part of the vulnerability's id or of a package name.

## One vulnerability

A vulnerability's page lists every system that has it, with its state and what fixes it.

| State | Meaning |
| --- | --- |
| **Affected** | The vulnerable version is there. |
| **Not reachable** | The vulnerable version is there, and the system's configuration does not allow the flaw. Today this is known for the SSH server of a host ([hosts.md](hosts.md)); the finding stays as the vulnerability database has it. |
| **Not checked** | GarnetOps has no current answer: a repository never scanned or whose last scan failed, a host that stopped reporting or whose packages could not be matched, a host whose agent reports containers only, an image whose packages are not read yet. Listed on its own, never counted as fine. |

**Checked, without it** counts the systems that were checked and do not have the vulnerable version. They are counted, not
listed, and nothing on this page is green: a system without the flaw is only free of what the vulnerability database knows today.

### What fixes it

The path follows from where the package comes from; no model decides it.

| Fixed by | When | What to do |
| --- | --- | --- |
| **Server: update the package** | a package of the host's package manager, or its kernel | Update on the host. With apt the page says whether the host's sources offer the fix now, and gives the command. A kernel needs a restart. |
| **Server: pull a newer image** | a container from an image no repository of yours builds (for example an official `nginx` image) | Pull a newer image; a newer tag or build is named when the registry check found one. |
| **Repository: raise the dependency** | a language package (npm, PyPI, …) in a repository, or in an image one of your repositories builds | A commit, with the link to the fix proposal ([fix-prs.md](fix-prs.md)). |
| **Repository: raise the base image** | an operating system package, or a binary of the base image, inside an image one of your repositories builds | Raise the base image in the Dockerfile, or rebuild. A commit, not a server action. |
| **No fix yet** | no fixed version is known | Nothing to install yet; a workaround at most. |

**Fixed by** above the table filters the systems: on the server, in a repository, or nobody yet.

A container is linked to a repository by its image's `org.opencontainers.image.source` label ([hosts.md](hosts.md)). You see
that link only for repositories you can see; without it the container reads as an image to pull.

## What you see

Only repositories you can see ([connected-accounts.md](connected-accounts.md)); repositories set aside are left out. Hosts and
their containers are visible to everyone in the organisation, as on the Agents page. Names of packages, images, containers and
hosts are scanned or reported content and are shown as text.

## Planned

ADR 0052 describes the next steps: dependencies without a fixed version shown as "not checked", configuration read by the agent
from a fixed list (for example whether HTTP/2 is on in nginx) so that more flaws can be "not reachable", and advisories read from
open sources with your own model proposing what a person confirms.

## API

- `GET /api/v1/situation` (`q`, `show` = `all` | `exploited` | `critical` | `high`, `kind` = `repository` | `container` |
  `host`, `cursor`, `pageSize`): one item per vulnerability with `severity`, `cvssScore`, `knownExploited`, `repositories`,
  `containers`, `hosts`, `systems`, `fixKnown`, `packages` (up to three names) and `packageCount`; `counts` for the filters;
  `hostsOn`. It pages by position: pass `next` or `prev` as `cursor`.
- `GET /api/v1/situation/{id}`: `vulnerability`, `systems` (each with `kind`, `status`, `severity`, `packages`, `fixPath`,
  `reasons`, and `repository`, `container`, `host`, `patch` where they apply; at most 500, `truncated` counts the rest),
  `counts` (`affected`, `notReachable`, `notChecked`, `checked`, `byPath`) and `notChecked` with a `reason` each. 404 for a
  vulnerability nothing you can see has.
