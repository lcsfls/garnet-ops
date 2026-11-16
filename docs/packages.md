# Packages

**Code → Packages** answers two questions, each in a view of its own:

- **With vulnerabilities** (the default): which packages have open findings, and which upgrade helps most? One row per package
  (name, version and type) over all the repositories that have it, what to fix first at the top: by the grade the package gives
  (known exploited and fixable first), then the worst severity and the number of open findings. Each row says the version that
  fixes all of its open findings (the same rule as the fix proposals, [fix-prs.md](fix-prs.md)), whether that is a major
  upgrade, and how many vulnerabilities have no fix yet. With more than one repository, the number opens the list of them.
- **Inventory**: every package of every repository, one row per repository, from the latest scan of each: version, repository,
  open findings, grade, type and licences.

## Where the vulnerabilities come from

A scan reads the packages of a repository with syft (manifests and lockfiles, transitive dependencies included) and matches them
with grype against the local vulnerability database ([vulnerability-database.md](vulnerability-database.md)). Every match is a
finding; this page joins the inventory with the open findings by name, version and type. Names, versions, licences and registry
messages are scanned or fetched content and are shown as text only.

## Filters

Always visible:

| Filter | Shows |
| --- | --- |
| **All**, **Critical**, **High**, then **Medium or lower** (with vulnerabilities) or **No critical or high** (inventory) | by the package's worst open finding, each with its number |
| **Repository** | one repository |
| Search | part of the name, or `name@version` with a version prefix |

Behind **More filters** (open by itself while one of them is set; the button says how many are):

| Filter | Shows |
| --- | --- |
| **Grade** | the grade the package gives (below), A to F, with the number of packages for each |
| **Package type** | one type as the scanner names it (`npm`, `python`, `go-module`, ...), when there is more than one |
| **Active**, **Inactive** | packages of active repositories, or of the ones set aside (shown once a repository is set aside); a chosen repository is listed whatever its state |
| **With open findings only** | inventory only: packages with at least one open finding, of any severity |
| **Deprecated or yanked** | with the deprecated packages module on ([deprecated-packages.md](deprecated-packages.md)) |

The view and the filters are in the address, so a filtered list can be bookmarked and shared.

## The grade of a package

A package gets a grade by the same rules as a repository ([grades.md](grades.md)), over its own open findings: F for a known
exploited vulnerability with a fix, E for a critical one with a fix, and so on, A without open findings. It says which packages
give their repository its grade. Like every grade it is display only: it never changes a gate result, a notification or a scan.
A package always comes from a scan, so it is never "not graded".

## In the menu

The number next to **Packages** counts the packages with an open critical or high finding in active repositories, once each as
the default view lists them: **Critical** plus **High** above. The number next to **Repositories** counts repositories the same
way.

## Export

**Export** downloads the view exactly as filtered as CSV, Excel (XLSX), PDF or text. With vulnerabilities: package, version, type,
worst open severity, open findings, the version that fixes them, the number and names of the repositories, grade and what the
registry said. Inventory: package, version, type, repository, grade, worst open severity, open findings, licences, what the
registry said (deprecated or yanked, with its message) and the package URL. Dates are in your time zone, column names in your language. CSV and Excel hold up to 50,000 rows, the PDF up to 5,000; the
file says when the list is longer. Every export is in the audit log (`package.exported`).

## API

- `GET /api/v1/packages` (`q`, `repositoryId`, `type`, `vulnerable=1`, `deprecated=1`, `status` = `all` | `blocked` |
  `attention` | `clean`, `grade` = one or more of `A` to `F` separated by commas, `activity` = `active` | `inactive` | `all`,
  `sort` = `name` | `type` | `repository` | `findings` | `severity` | `grade`, `dir`, `cursor`, `pageSize`): each item has
  `grade` since 0.1.8.
- `GET /api/v1/packages/counts` (the same filters): `all`, `blocked`, `attention`, `clean` (the status is left out), `inactive`
  and `types`.
- `GET /api/v1/packages/grades` (the same filters): the number of packages per grade (the grade filter is left out).
- `GET /api/v1/packages/affected` (since 0.1.9; the same filters except `vulnerable`, `sort` = `severity` | `findings` |
  `repositories` | `name`, `dir`, `cursor`, `pageSize`): one item per package with `repositories`, `repositoryList` (up to 20,
  `id` and `name`), `openFindings`, `worstSeverityRank`, `grade`, `fix` (`version`, `majorUpgrade`, `unresolved`, or null) and
  `deprecation`. It pages by position: pass `next` or `prev` as `cursor`.
- `GET /api/v1/packages/affected/counts` (the same filters): `all`, `blocked`, `attention`, `clean` (medium or lower) and `grades`,
  counted per package; the status and grade filters are left out.
- `GET /api/v1/packages/export` (the same filters, plus `view` = `inventory` | `affected`, `format` = `csv` | `xlsx` | `pdf` |
  `txt`, `lang`, `tz`).

Everything counts only the repositories you can see ([connected-accounts.md](connected-accounts.md)).
