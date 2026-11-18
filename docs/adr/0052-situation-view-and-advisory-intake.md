# ADR 0052: The situation per vulnerability, what fixes it, and advisories read with the customer's model

- Status: accepted (2026-11-18); phase 1 implemented, phases 2 to 4 planned
- Date: 2026-11-18
- Decided by: maintainer (new flaws in web servers and runtimes arrive almost weekly; the question each time is which of our systems
  are affected, which are not, and which can only be fixed in a repository and not on the server; an agent may read advisory sources
  daily, but not scrape news sites)
- Builds on: ADR 0005 (scans and inventory), ADR 0013 (AI triage), ADR 0014 (fix pull requests), ADR 0029 (early warnings),
  ADR 0030 (visibility), ADR 0033 (modules), ADR 0034 and 0037 (host agent), AGENTS.md rules 1, 2, 3 and 6

## Context

When a flaw such as a remote code execution in a web server is published, a team asks four questions within the hour: where do we
run it, in which version, is the vulnerable feature switched on, and who has to do what. GarnetOps has most of the answers, but in
four places: findings of repositories, findings of the images that containers run, findings of host packages and of the kernel
(ADR 0034, 0037), and a note where a host's configuration rules a flaw out (so far for the SSH server only). Nobody sees one flaw
across all of them, and nothing says whether the fix is an `apt upgrade`, a new image, or a commit.

Three more gaps showed up while planning:

- A repository whose dependencies have no fixed version (a `requirements.txt` with `Django>=5.0`, no lockfile) is scanned
  "successfully" with nothing in it. It then looks clean. That contradicts "an error is never a clean result".
- Whether a flaw can be reached often depends on configuration (HTTP/2 on, a module loaded). Only the SSH server is read today.
- On day zero the vulnerability database does not have the flaw yet. People paste commands from chats; a sed line that matches
  nothing reports "syntax is ok" and reloads.

## Decision

### 1. One view per vulnerability: the situation (phase 1, this change)

- **Situation** lists the vulnerabilities that are open anywhere the person can see, each once: in repositories (open findings),
  in running containers (findings of their images), and on hosts (packages and kernel). Known exploited first, then by severity and
  by the number of systems.
- A vulnerability's page lists every affected **system** (a repository, a container on a host, a host) with a **status** and
  **what fixes it**. The statuses:

  | Status | Meaning |
  | --- | --- |
  | affected | the vulnerable version is there |
  | not reachable | the vulnerable version is there, and the system's configuration does not allow the flaw (today: the SSH server check of ADR 0037) |
  | not checked | GarnetOps has no current answer for this system: a repository never scanned or whose last scan failed, a host that stopped reporting or whose packages could not be matched, an image without a package list |

  Systems that were checked and do not have the vulnerable version are counted, not listed. "Not checked" is never counted as
  fine and is always listed.
- **What fixes it** follows from where the package comes from, not from a model:

  | Fix path | When |
  | --- | --- |
  | `server-package` | a package of the host's package manager, or its kernel: update on the server; with apt facts the patch state says whether the fix is offered now or the mirror is waited for |
  | `server-image` | a container from an image no repository of ours builds: pull a newer image; a newer tag or build is named when the registry check found one |
  | `repository-dependency` | a language package (npm, PyPI, …) in a repository, or in an image one of our repositories builds: raise the dependency, with the link to the fix proposal |
  | `repository-base-image` | an operating system package inside an image one of our repositories builds: raise the base image or rebuild; a commit, not a server action |
  | `vendor` | no fixed version is known yet: nothing to install; a workaround at most |

- Colours follow rule 6: affected carries the severity's colour and word, "not reachable" and "not checked" are neutral with a
  label, and nothing on this page is green: a system without the flaw is only free of what the database knows today.
- Read by everyone who sees the systems: repositories by ADR 0030 (another member's private repository is in nobody else's
  situation; a container's link to a repository is shown only when the person sees that repository), hosts by the hosts module
  (ADR 0033; while it is off, only repositories are listed). Nothing is stored: the view is computed from the findings.

### 2. Dependencies without a fixed version are "not checked" (phase 2)

A dependency a manifest declares without a resolved version (no lockfile entry, a range or no version at all) is counted per
repository and shown as **not checked** on the repository, in Packages and in the situation, with the names and the way out
(a lockfile, `pip-compile`). A gate rule for it ships off (rule 2). No scanner change: the manifests are already read for fix
proposals (ADR 0014).

### 3. Configuration facts from the agent, from a fixed catalogue (phase 3)

- The host agent reads a **fixed list** of facts with parsers of its own, read-only, as it does for sshd: for nginx whether HTTP/2
  is on for any listener and which version runs; later Apache, PHP and Java runtimes. It sends **derived values only** (booleans,
  version strings, counts), never a configuration file, a server name or a path.
- GarnetOps turns a fact into "not reachable" only through a rule shipped in code and reviewed (as `sshole` is today), or through a
  condition a person confirmed (4). The finding itself stays as the vulnerability database has it.
- New fields in the agent protocol are optional; older agents keep working and their systems show "configuration not known".

### 4. Advisories read from open sources, with the customer's own model proposing and a person confirming (phase 4)

- **Sources are feeds, not scraped pages.** A fixed list of structured, openly licensed sources (CISA KEV, NVD, the GitHub Advisory
  Database, OSV, the distributions' security trackers, vendor advisories), fetched a few times a day by the worker. Each source is
  checked against rule 3 and listed in `docs/COMPONENTS.md` before it ships. News sites and blogs are not bundled: an admin may add
  feed addresses of their own; their text is processed locally and never stored, only facts (identifier, product, versions, link).
- **Off by default**, switched on by an admin, the addresses shown in the settings; nothing about the installation is sent, only the
  fetch. Air-gapped installations leave it off and import as before.
- **Filter first, without a model:** only advisories that name a product in the organisation's inventory go on.
- **The model fills a fixed form** from the advisory text (ADR 0013: the customer's own endpoint): package, version range,
  precondition ("only with HTTP/2"), workaround, and the sentence each claim is quoted from. It has no tools and follows no links.
  The answer is validated against the form; identifiers and versions that are not in the text are refused.
- **A person confirms.** The proposal appears in the situation labelled as AI, with the source and the quotes. Only a confirmed
  condition changes a status, and only to "not reachable"; nothing a model writes can mark a system as not affected or close a
  finding. A suggested command is text to copy, never run by GarnetOps or the agent.

## What is deliberately not done

- No command from a model, a feed or GarnetOps is executed on a server, and the agent gets no write access.
- No free crawling, no storing of article text, no bundled news source.
- No status "fixed" or "not affected" from a model or from configuration alone.
- No grade or gate change in phase 1; the situation is a view.

## Threat model

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Another member's private repository shows in the situation | Disclosure of names and flaws | Every repository query goes through ADR 0030; a container's repository link is resolved per reader; tested with two members |
| A system without data is read as fine | A false sense of safety during an incident | "Not checked" is a status of its own, always listed, never in the "checked" count; unpinned dependencies become "not checked" (phase 2) |
| Hostile package names, image references, host names (scanned and reported content) | Markup or script injection | Shown as text; values cut on the server; no value in a URL except as an encoded query parameter |
| A hostile advisory or feed entry steers the model (prompt injection) | Wrong condition, wrong workaround | No tools, a fixed form, quotes checked against the text, a person confirms, and the worst a confirmed condition can do is "not reachable" with the finding still shown (phase 4) |
| A model invents a version range | Systems wrongly ruled out | Values must occur in the source text; ranges are shown next to the quote; the vulnerability database's own match is never overridden |
| A feed address points inside the network | Server-side request forgery | `https` only, address checks on every connection as for registries (ADR 0051), no redirects, size and time limits (phase 4) |
| Configuration leaves the server | Disclosure of server names, paths, secrets in config | The agent sends derived values from a fixed catalogue only; the catalogue is in the documentation (phase 3) |
| A pasted workaround is run blindly | Outage, or no effect while looking fixed | GarnetOps never runs it; the proposal says what it changes and how to check the result (phase 4) |
| Heavy queries during an incident | Slow app | The list reads grouped aggregates over indexed finding tables; the page of one vulnerability is bounded (500 systems listed, the rest counted) |

## Consequences

- Phase 1: API (additive) `GET /api/v1/situation` and `GET /api/v1/situation/{id}`; a page **Situation** under Daily. No migration,
  no new dependency, no change to findings, grades or gates.
- Phase 2 needs no migration either (manifests are stored); phases 3 and 4 add optional protocol fields and tables, each additive.
- The ROADMAP's "Go/Composer deprecated sources" and compose checks are unaffected.
- Open after phase 4: websites in the situation (software versions seen from outside, ADR 0038), and a report of one situation.
