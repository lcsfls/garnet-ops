# ADR 0054: Whether a repository finding's package is in a running image

- Status: accepted (2026-11-18)
- Date: 2026-11-18
- Decided by: maintainer (asked whether GarnetOps can tell by itself what is in the image and what is only in the repository,
  and to filter by it in one click)
- Builds on: ADR 0034 (host agent, the link between an image and its repository), ADR 0052 (the situation), AGENTS.md rules 1
  and 2

## Context

A repository scan reads what the repository declares: lockfiles, `go.mod`, manifests. That is the right question for a
developer ("what do I depend on") and the wrong one for an operator ("what runs"). A service built as a Go binary with static
web files declares a front-end framework and its build tools; none of them is installed in the image. Shown without that
difference, a list of findings reads harder than the facts are, and the answer "none of this is in the image" is half right.

GarnetOps already has both sides. The agent reads the package list of every running image (ADR 0034), including the modules a Go
binary names in its build information, and links an image to the repository it was built from by its
`org.opencontainers.image.source` label.

## Decision

1. **Compare, do not guess.** For a repository finding, GarnetOps looks at the running containers whose image was built from
   that repository and asks whether the image's package list names the package (same package type, name without case). The
   answer is one of:
   - **in a running image**: at least one read image names it (the version there is shown; it can be another one than the
     repository declares when the container runs an older build);
   - **not in the image**: the images were read and none names it;
   - **no answer**: the Agents module is off, no agent reports a container built from the repository, or its image is not read
     yet. No answer is never shown as "not in the image".
2. **A fact, not a decision.** The answer changes nothing: the finding stays open, with its severity; grades, gates, counts,
   notifications and reports are what they were. It is read when the page is, and stored nowhere.
3. **Never good news by itself.** "Not in the image" is written in neutral words and never in green. Two kinds of package get a
   sentence more, because their code can be in the image without the package being found: front-end packages compiled into
   script files (npm), and crates in a binary not built to name them (Rust). Go modules are named by the binary; installed
   packages by their files.
4. **One click.** The findings list marks each row and has two filters, **In a running image** and **Not in the image**, which
   also apply to the counts and the export. Findings without an answer are in neither. The filters are offered while the Agents
   module is on.
5. **Evidence on the finding.** A finding lists the containers the answer rests on: host, image and the version found there.

## Not decided here

- Whether the vulnerable code is reachable (a call graph, for Go the vulnerability database's symbols). It needs the repository
  to be built or loaded by a tool, which is a decision of its own (rule 1: never execute code from a scanned repository).
- Pulling and reading an image from a registry without an agent on a host that runs it.
- A mark for development dependencies. It looks like the same question and is not: a framework declared as a development
  dependency can ship its code in the built files.

## Threat model

| Threat | Impact | Mitigation |
| --- | --- | --- |
| "Not in the image" is read as "not affected" | A real flaw is left open | Neutral wording, no green, the caveat for bundled and compiled code, and the sentence that nothing changes; state, grade and gate are untouched |
| A forged source label links a foreign image to a repository | A wrong answer on that repository's findings | The label only ever adds evidence from containers the organisation's own agents report; it reaches no other organisation; the finding lists the container, host and image the answer rests on |
| A hostile package list from an agent | A crash or injection | Read as data: a list that is not a list counts as not read; names and versions are compared as text and shown as text, cut to a length |
| An older build is running | "In the image" for a version already fixed in the repository, or the reverse | The version found in the image is shown next to the finding's version; the image's own findings stay the source for what the image is affected by |
| Another organisation's images | A leak across tenants | Every query filters by the organisation; tested |

## Consequences

- API (additive): `image` on each finding of `GET /api/v1/findings` and on `GET /api/v1/findings/{id}`; the filter `image=in` or
  `image=not-in` on the list, the counts and the export.
- No migration, no job, nothing stored.
- Open: the same mark on the situation page and on a repository's package list.
