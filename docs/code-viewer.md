# Code of a finding

A finding on a repository shows, on request, **where the vulnerable package is declared** and **where the code imports it**
(ADR 0048). It answers "is this used at all, and where?" without leaving GarnetOps.

## Using it

On a finding's detail, **Show code** (members and above) asks the worker to read the repository. After a few seconds the
section shows:

- **Where it is declared**: the manifests GarnetOps knows from the last scan that name the package, and the lockfile among the
  finding's locations, each with the lines that name it marked and five lines around them.
- **Where the code uses it**: the project's own source files that import the package, found by name with a fixed pattern per
  ecosystem (npm: `import … from`, `require()`, `import()`, also subpaths; Python: `import x`, `from x import`; Go: the module
  path; Rust: `use x::`, `extern crate x`), each with three lines around every place. It is a search by name: it can miss a
  dynamic import or include a namesake. At most 200 places in 50 files are shown; more are counted. Composer, Maven and other
  ecosystems show the declaration only.
- The commit that was read. GarnetOps reads the commit the finding's last scan saw; when the forge does not hand out a single
  commit, it reads the branch as it is now and says so.

## What happens to the code

- Only the worker reads code, with the repository's **read** credential, in a fresh shallow clone that is removed as soon as
  the excerpts are taken. Nothing in the repository is executed; only regular text files inside the clone are read (no
  symbolic links, at most 1 MB per file); `node_modules`, `vendor`, build output and binary files are skipped; the search
  stops after 20,000 files or 30 seconds.
- The excerpts are handed to the person who asked **once** and then deleted (requests are swept after ten minutes in any state).
  The answer is never cached and never part of a backup. The page keeps it in memory until it is left.
- Every request is audited as **Code of a finding viewed** (finding, repository, package and commit; never the content).
- Members and above who see the repository can ask; viewers cannot. 30 requests a minute per person and 200 an hour per
  organisation; one clone at a time per organisation, two at a time in total, so code views never hold up scans.
- Every line is shown as text. Syntax highlighting (highlight.js) is read back token by token; no HTML from the repository or
  from the highlighter reaches the page. Control and bidirectional characters are removed and lines longer than 2,000
  characters are cut.

## API

`POST /api/v1/code/findings/{id}` answers `202` with `{ "id" }`; `GET /api/v1/code/requests/{id}` answers `{ "state": "queued" |
"running" }` until it is done, then once `{ "state": "done", "result" }` or `{ "state": "failed", "error" }`. Both send
`Cache-Control: no-store`. `409 busy` when the organisation already has a request running.
