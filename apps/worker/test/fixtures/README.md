# Worker test fixtures

Repository contents the worker scans in tests. They are data only: nothing
here is installed, built or executed.

- `npm-vulnerable/`: lodash 4.17.15 and minimist 1.2.0, releases with
  published GitHub advisories.
- `npm-fixed/`: the same packages at releases that fix those advisories.
- `grype-npm-vulnerable.json`: grype 0.120.1 output for `npm-vulnerable/`,
  recorded on 2026-10-21 against the vulnerability database built
  2026-10-19. Local paths were replaced by `/fixture` and `/db`.
