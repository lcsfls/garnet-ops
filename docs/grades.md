# Grades

Every repository and every server gets a grade from **A** to **F** on its list and on its own page. It answers
one question: which ones do I look at first? (ADR 0018.)

**A grade is display only.** It never changes a quality gate result, a notification, an alert, a scan or
anything else. Gates are explained in [quality-gates.md](quality-gates.md); they do not read grades.

## The rules

Only **open** findings count, and the worst matching rule wins. "With a fix" means a fixed version is known.

| Grade | Given when there is at least one open finding that is... |
| --- | --- |
| **F** | a known exploited vulnerability (CISA KEV) with a fix |
| **E** | a critical vulnerability with a fix |
| **D** | a high vulnerability with a fix, or a critical one without a fix |
| **C** | a medium vulnerability with a fix, or a high one without a fix |
| **B** | anything else: only low findings, or only findings without a fix that the rows above do not cover |
| **A** | no open findings |

A few consequences:

- A known exploited vulnerability **without** a fix is graded by its severity only: critical D, high C, anything
  milder B. Without a fix there is nothing to do yet except look for a workaround.
- The severity is the one shown in the lists. Negligible and unknown severities count as B.
- Fifty low findings are still a B. One medium with a fix is a C.
- When two rules give the same grade, the note names the one with a fix.

**Accepted risks** do not count while the acceptance lasts. When it has run out, the finding counts again right
away, even before the next nightly scan has reopened it. An acceptance without an end date does not expire.
Resolved findings never count.

## Why letters, and why A is grey

A percentage would need weights that nobody can defend, and would suggest a precision the data does not have. Six
letters with rules you can read in ten seconds say what matters: the worst thing that is open, and whether it can
be fixed. The note always gives the reason, so you can check it against the findings.

A is not green. In GarnetOps green means proof (a gate that passed). A repository without open findings is only
free of what the vulnerability database knows today, so A is neutral. The other colours follow the severity scale:
F and E vermilion, D orange, C amber, B grey. The letter is always shown; colour is never the only signal.

## Not scanned, and failed scans

- A repository that has **never been scanned successfully** has no grade ("Not scanned yet"), not an A. The same
  goes for a server that has never been inventoried successfully ("Not read yet"). A server whose host key
  has not been confirmed has not been read.
- If the **latest scan or inventory failed**, the grade of the last successful run stays, marked with a small
  clock and a sentence in the note ("The latest scan failed. This is the grade of the last successful scan.").
  The failure itself is shown as before. Checks of pull requests never affect a repository's grade.

## Where to see it

- **Repositories** and **Servers**: a Grade column right after the name. Hover or focus the letter (or tap it on
  a touch screen) for a note such as *D: 2 high vulnerabilities with a fix (lodash)*, with a link to the findings
  behind it: for a repository the Findings page filtered to this repository, severity and fixes; for a server its
  page, scrolled to the vulnerabilities with the same filters. Escape closes the note.
- Click the **Grade** column header to sort (F first; click again to reverse). The grade drop-down next to the
  search filters by one grade or by "Not graded", with the number in each.
- The page of a repository or server shows the grade and its reason under the title.
- **How grades work** above each table repeats the rules.

## For scripts

The API adds three fields to repositories and servers (`GET /api/v1/repositories`, `/repositories/{id}`,
`/hosts`, `/hosts/{id}`); existing fields are unchanged:

```json
{
  "grade": "D",
  "gradeReason": { "rule": "high-with-fix", "count": 2, "example": "lodash" },
  "gradeStale": false
}
```

`grade` is `null` when nothing was scanned yet (then `gradeReason` is `null` too). `rule` is one of
`known-exploited-with-fix`, `critical-with-fix`, `high-with-fix`, `critical-without-fix`, `medium-with-fix`,
`high-without-fix`, `other-open` and `none`. The lists take `sort=grade` and `grade=F,E,none`;
`GET /api/v1/repositories/grades` and `GET /api/v1/hosts/grades` return the number per grade. Please do not build
a pipeline decision on a grade; use a gate for that.
