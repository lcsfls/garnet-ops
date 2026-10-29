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

Each figure links to the list behind it. Found, Resolved and Gates passed draw their course over the range as a thin line under the
number.

## Charts

- **Open findings**: the open findings at the end of each day or week, by severity, as stacked areas. A finding counts as open from the
  day it was first seen until the day it was resolved, so the chart also covers days on which no scan ran.
- **Found and resolved**: new findings above the baseline, findings no longer detected below it, per day or week.
- **Gate results**: quality gate runs by result (passed, with notes, blocked), stacked per day or week.

Move the pointer over a chart and a crosshair names the day or week and every number of it, with the total (or, for found and
resolved, the net change). The three charts move their crosshairs together, so one day can be compared across them. With the keyboard,
focus a chart with Tab, move with the left and right arrow keys (Home and End jump to the first and last day), and press Escape to
leave; a screen reader reads the numbers of each day.

A click on a column of **Found and resolved** opens the findings behind it: above the baseline the findings first seen on that day or
week, below it the ones resolved then. Enter opens the found ones. The findings list shows the period as a filter that one click
removes.

Every chart has a legend that names each colour with its total (or last value), and **Show as table** lists the same numbers; in the
found and resolved table every number links to its findings. Nothing depends on colour or on hovering. Green marks only what is
proven: a gate that passed, a finding that a scan no longer found.

Findings of the severities *negligible* and *unknown* are not counted on this page, as in the overview trend.

## Time to fix

The median time from the first time a finding was seen until it was resolved, per severity, for the findings resolved in the range,
as a bar (the longest median is the full width) with its value.
Below one day it is shown in hours. A severity without resolved findings says so instead of showing a number. The median is not
pulled up by a single finding that waited for months, which an average would be.

## Where the open findings are

These lists show today, independent of the range:

- **Repositories** and **packages** with the most open findings, worst first: by critical, then high, then all open findings. Accepted
  risks are not counted. A bar under each name shows its open findings by severity, measured against the first of the list.
- **Oldest open critical and high findings**: the ones that have waited longest for a fix. **All findings by age** opens the findings
  list sorted by first seen.

## API

`GET /api/v1/statistics?days=30|90|365&tz=<IANA zone>` returns the same data for the signed-in organisation. Any other range or an
unknown time zone is refused with 422.

The findings list takes calendar days in the same way: `GET /api/v1/findings?firstSeenFrom=2026-10-12&firstSeenTo=2026-10-18&tz=Europe/Berlin`
(and `resolvedFrom`, `resolvedTo`) lists the findings first seen, or resolved, on these days, both ends included. A date that does not
exist or an unknown time zone is refused with 422; without `tz` the days are UTC days. The findings export takes the same filters.
