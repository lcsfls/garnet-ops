# Packages

**Code → Packages** lists every package of your repositories, from the latest scan of each: name, version, type, repository,
licences, the grade the package gives, and its open findings with the worst severity. Names, versions and licences are scanned
content and are shown as text only.

## Filters

The same filters as on the Repositories page, each with the number it shows:

| Filter | Shows |
| --- | --- |
| **All**, **Critical**, **High**, **No critical or high** | by the package's worst open finding: a critical one; a high one and no critical; neither |
| **Grade** | the grade the package gives (below), A to F, with the number of packages for each |
| **Active**, **Inactive** | packages of active repositories, or of the ones set aside (shown once a repository is set aside); a chosen repository is listed whatever its state |
| **Repository**, **Package type** | one repository; one type as the scanner names it (`npm`, `python`, `go-module`, ...) |
| **With open findings only** | packages with at least one open finding, of any severity |
| **Deprecated or yanked** | with the deprecated packages module on ([deprecated-packages.md](deprecated-packages.md)) |
| Search | part of the name, or `name@version` with a version prefix |

The filters are in the address, so a filtered list can be bookmarked and shared.

## The grade of a package

A package gets a grade by the same rules as a repository ([grades.md](grades.md)), over its own open findings: F for a known
exploited vulnerability with a fix, E for a critical one with a fix, and so on, A without open findings. It says which packages
give their repository its grade. Like every grade it is display only: it never changes a gate result, a notification or a scan.
A package always comes from a scan, so it is never "not graded".

## In the menu

The number next to **Packages** counts the packages of active repositories with an open critical or high finding: **Critical**
plus **High** above. The number next to **Repositories** counts repositories the same way.

## Export

**Export** downloads the list exactly as filtered as CSV, Excel (XLSX), PDF or text: package, version, type, repository, grade,
worst open severity, open findings, licences, what the registry said (deprecated or yanked, with its message) and the package
URL. Dates are in your time zone, column names in your language. CSV and Excel hold up to 50,000 rows, the PDF up to 5,000; the
file says when the list is longer. Every export is in the audit log (`package.exported`).

## API

- `GET /api/v1/packages` (`q`, `repositoryId`, `type`, `vulnerable=1`, `deprecated=1`, `status` = `all` | `blocked` |
  `attention` | `clean`, `grade` = one or more of `A` to `F` separated by commas, `activity` = `active` | `inactive` | `all`,
  `sort` = `name` | `type` | `repository` | `findings` | `severity` | `grade`, `dir`, `cursor`, `pageSize`): each item has
  `grade` since 0.1.8.
- `GET /api/v1/packages/counts` (the same filters): `all`, `blocked`, `attention`, `clean` (the status is left out), `inactive`
  and `types`.
- `GET /api/v1/packages/grades` (the same filters): the number of packages per grade (the grade filter is left out).
- `GET /api/v1/packages/export` (the same filters, plus `format` = `csv` | `xlsx` | `pdf` | `txt`, `lang`, `tz`).

Everything counts only the repositories you can see ([connected-accounts.md](connected-accounts.md)).
