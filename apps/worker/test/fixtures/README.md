# Worker test fixtures

Repository contents the worker scans in tests. They are data only: nothing
here is installed, built or executed.

The manifests of the two repositories end in `.fixture`
(`package.json.fixture`, `package-lock.json.fixture`) so that scanners and
dependency bots that read this repository (GarnetOps, Dependabot, syft) do not
mistake the deliberately vulnerable packages for real dependencies of the
product. Tests copy a fixture with `copyFixtureRepo()` from
`test/fixture-repo.ts`, which gives the files their real names in a temporary
directory.

- `npm-vulnerable/`: lodash 4.17.15 and minimist 1.2.0, releases with
  published GitHub advisories.
- `npm-fixed/`: the same packages at releases that fix those advisories.
- `grype-npm-vulnerable.json`: grype 0.120.1 output for `npm-vulnerable/`,
  recorded on 2026-10-21 against the vulnerability database built
  2026-10-19. Local paths were replaced by `/fixture` and `/db`.

## Servers

- `host-grype-debian.json`: a **synthetic** grype-shaped report (not recorded
  from a real run, because the vulnerability database cannot be fetched in the
  test environment) for the Debian 12 inventory used in `hosts.test.ts`: one
  critical finding with a fix in `libssl3` and one low finding without a fix in
  `bash`. Vulnerability IDs are the fictional `CVE-2099-…` range. The test that
  runs the real grype against a server inventory is skipped without a
  vulnerability database.
