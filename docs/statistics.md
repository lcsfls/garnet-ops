# Statistics

**Daily → Statistics** answers a different question than the overview. The overview says what needs attention today; the statistics
page says whether things get better over time: what was found and resolved, how long fixes took, how the quality gates turned out, and
where today's open findings are. Every member of the organisation can open it, viewers included. It only counts what the findings list
shows anyway.

## Time range and days

Choose **30 days**, **90 days** or **365 days** at the top right; the choice is part of the address (`/statistics?days=90`), so a link
shows the same range.

Days are your calendar days: the browser sends its time zone and the database cuts the range with it. A 23-hour or 25-hour day at a
daylight-saving change is exactly one day. With 30 days every bar is one day. With 90 and 365 days every bar is a week from Monday to
Sunday; the first and the last week are cut to the range, and every bar names the days it covers.

## Key figures

| Figure | What it counts |
| --- | --- |
| Found | Findings first seen in the range, with the count of the range of the same length before it. |
| Resolved | Findings that a scan no longer found in the range, with the count of the range before it. |
| Gates passed | The share of quality gate runs in the range that passed, and how many there were. |
| Fix pull requests merged | Fix pull requests that GarnetOps opened and that were merged in the range, and how many it opened. |
| Failed scans | Scans that ended with an error in the range, of all scans that ended in it. |

Each figure links to the list behind it.

## Charts

- **Open findings**: the open findings at the end of each day or week, by severity. A finding counts as open from the day it was first
  seen until the day it was resolved, so the chart also covers days on which no scan ran.
- **Found and resolved**: new findings and findings no longer detected, side by side per day or week.
- **Gate results**: quality gate runs by result (passed, with notes, blocked).

Hover a bar for its days and numbers. Every chart has a legend that names each colour with its total, and **Show as table** lists the
same numbers, so nothing depends on colour or on hovering. Green marks only what is proven: a gate that passed, a finding that a scan
no longer found.

Findings of the severities *negligible* and *unknown* are not counted on this page, as in the overview trend.

## Time to fix

The median time from the first time a finding was seen until it was resolved, per severity, for the findings resolved in the range.
Below one day it is shown in hours. A severity without resolved findings says so instead of showing a number. The median is not
pulled up by a single finding that waited for months, which an average would be.

## Where the open findings are

These lists show today, independent of the range:

- **Repositories** and **packages** with the most open findings, worst first: by critical, then high, then all open findings. Accepted
  risks are not counted.
- **Oldest open critical and high findings**: the ones that have waited longest for a fix. **All findings by age** opens the findings
  list sorted by first seen.

## API

`GET /api/v1/statistics?days=30|90|365&tz=<IANA zone>` returns the same data for the signed-in organisation. Any other range or an
unknown time zone is refused with 422.
