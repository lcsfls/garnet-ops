# Reports

GarnetOps summarises what it checked in reports: one per repository, one per host, the websites at a glance, and a security report of
the whole organisation for a period. Each one is on its page and can be downloaded as PDF; the organisation report can also come by
email. Every report is built for the person who asks for it, with exactly what that person can see in GarnetOps
([ADR 0047](adr/0047-reports.md)).

## What a report contains

Reports only say what GarnetOps knows from its own checks: real counts and dates, no scores of their own and no guesses.

| Report | Where | Contents |
| --- | --- | --- |
| Repository | The repository's page, card **Report** | Last scan (in any state) and last successful scan with its commit, the vulnerability database that scan used and whether it was current, open findings by severity (worst first), known exploited, accepted risks (and how many have run out), grade, the latest quality gate result, early warnings, what to do next, and the ten worst open findings. |
| Host | The host's page, card **Report** | When the agent last reported (and whether it stopped), operating system and agent, the running kernel and its open vulnerabilities, the host's own packages (systemd agent), the running containers and images (with critical or high findings, with a newer image), open findings by source, early warnings, what to do next, and the ten worst open findings. |
| Websites at a glance | **Websites**, view **At a glance** | Every website with the state of its daily look: availability, days until the certificate ends, the worst open finding, software behind its line or without fixes, verification and when it was last looked at. Worst first; every column sorts; each row opens the website's report. |
| Organisation | **Statistics**, button **Security report (PDF)** | For the last 7 or 30 days: open findings now by severity, what was found and fixed in the period, the repositories and hosts with the most open findings, the websites at a glance, quality gates passed and blocked, early warnings, accepted risks, coverage (repositories not scanned successfully yet, hosts not reporting, the vulnerability database), and what to do next. |

"What to do next" names the most urgent things first, for example known exploited findings, critical findings that have a fixed
version, a blocked gate, accepted risks that have run out, a host that stopped reporting or a kernel update. When nothing is urgent it
says so.

Severities have their fixed colours in the app, and the severity pill shows the word with a level of four bars (critical four, low
one), so it reads without colour; in the PDF a small square in the same colour as the app's charts stands next to its name. Green
is used for nothing but a passed gate.

## Who sees what

- A report is built with the access of the person who asks for it, exactly as every list and count of the app: repositories shared with
  the organisation, and that person's own private repositories ([connected accounts](connected-accounts.md)). Another member's private
  repository is in nobody else's report, not even an owner's, until it is shared.
- Inactive repositories are left out of the organisation report, as they are left out of the statistics; a repository's own report
  still shows them, with a note.
- Hosts and websites belong to the whole organisation. They are part of the organisation report only while their module is on.
- Downloading a report as PDF is written to the audit log ("Report downloaded"). Downloads are limited to 20 a minute per person.

## Days and time zones

The period of the organisation report is made of your calendar days: the last 7 or 30 days, today included, in the time zone of your
account (or of your browser, if your account has none). A day with 23 or 25 hours at a daylight-saving change is one day. The time zone
is named in the file, and every date in it is written in that zone.

## The security report by email

Under **Account → Notifications → Security report by email**, choose how often the organisation report comes by email:

| Choice | Period | Arrives |
| --- | --- | --- |
| Off (default) | – | Never. |
| Daily | The day before | Every day from 07:00 |
| Weekly | Monday to Sunday of the week before | Mondays from 07:00 |
| Monthly | The month before | On the 1st from 07:00 |

- The time is 07:00 in your own time zone (from your account; otherwise the organisation's nightly scan zone; otherwise UTC). The card
  names the zone.
- The mail is short: the open findings by severity, what was found and fixed, quality gates, websites down and hosts not reporting if
  any, the most urgent next steps, and a link to GarnetOps. It never contains names of findings, packages, paths or code. With
  **Attach the report as PDF** (on by default) the organisation report described above is attached; it contains the names of
  repositories, hosts and websites you can see, and counts.
- It is built with your access, like the download, and goes to your own sign-in address only, never to a channel's recipient list.
- It is sent through the organisation's first enabled mail channel (SMTP or Microsoft Graph, Settings → Notifications), like personal
  notification mail. Without a mail channel the choice is not available; if the channel is switched off later, nothing is sent and the
  period is recorded as skipped.
- Each period is sent at most once: GarnetOps records the period before it sends, so a repeated hour in autumn, a restart or a second
  worker never sends it twice. A mail that fails is not retried; the report is still in the app.
- Choosing a frequency starts from then on: the period that ended just before is not sent at once. Choosing **Off** stops it at once.
- Leaving the organisation stops it.

## API

All under `/api/v1`, with the session of the signed-in person:

| Endpoint | What it returns |
| --- | --- |
| `GET /reports/repositories/{id}` | The repository's report as JSON; `?format=pdf&tz=…&lang=en\|de` for the PDF. 404 for a repository you cannot see. |
| `GET /reports/hosts/{id}` | The host's report; same parameters. 409 `module-off` while hosts are off. |
| `GET /reports/websites` | The websites at a glance, worst first. 409 `module-off` while website monitoring is off. |
| `GET /reports/organization?days=7\|30&tz=…` | The organisation report for the period; `format=pdf` and `lang` as above. |
| `GET /me/report-mail`, `PUT /me/report-mail` | Your report mail: `{ "frequency": null \| "daily" \| "weekly" \| "monthly", "attachPdf": true }`. A frequency is refused (422) while the organisation has no mail channel. |
