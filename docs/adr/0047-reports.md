# ADR 0047: Reports per repository, host and organisation, as PDF and by email

- Status: accepted
- Date: 2026-11-05
- Decided by: maintainer ("improved reporting": a report as PDF and by email, a report per repository and per host; daily, weekly or
  monthly mail; the websites at a glance)
- Builds on: ADR 0005 (time zones), ADR 0010 and 0019 (mail channels, personal mail), ADR 0018 (grades), ADR 0030 (private
  repositories), ADR 0033 and 0034 (modules), ADR 0040 (the website report), ADR 0043 (inactive repositories)

## Context

The pages show everything, one area at a time. People asked for a summary they can read in one go, hand on, or receive without signing
in: what was checked and when, what is open, what changed and what to do next, for one repository, for one host, and for the whole
organisation. The website page already has such a report (ADR 0040); repositories and hosts had none, and nothing summarised the
organisation over a period. The roadmap's "weekly digest" (ADR 0005, point 6) was never built.

## Decision

1. **Four reports, one shape each** (`packages/core/src/reports.ts`): repository, host, the websites at a glance, and the organisation
   for a period. They contain real data only (counts, dates, names, the database the check used); "what to do next" is a list of codes
   with counts, derived from the data by fixed rules, and turned into sentences where it is read.
2. **Built for one person.** Every report is assembled with the visibility conditions of ADR 0030 (`visibleRepository`,
   `repositoryVisibleTo`) for the person who asks or who receives the mail, never for "the organisation". The organisation report
   leaves inactive repositories out (ADR 0043) like the statistics. Hosts and websites are organisation-wide data and are included only
   while their module is on.
3. **Where.** A **Report** card on the repository and host pages, a view **At a glance** on the websites page (the existing list stays
   the default; the overview has its own endpoint, so the list API does not change), and a **Security report (PDF)** button on the
   statistics page with the last 7 or 30 days.
4. **PDF without a dependency.** The PDF writer of the findings export moves to `packages/core/src/pdf.ts` and gains a document mode
   (headings, facts, lists, tables that repeat their header, page numbers; A4 portrait; standard Helvetica, WinAnsi). The findings
   export writes byte-for-byte the same files as before. Severity is a small square in its fixed colour next to its name.
5. **By email, opt-in per person.** `report_subscription` (organisation, person, frequency daily/weekly/monthly, attach PDF, since)
   and `report_mail_run` (organisation, person, period key, state) in migration 0048, additive. The worker ticks every five minutes;
   for each subscriber who is still a member it decides in that person's zone (account, else the organisation's nightly-scan zone,
   else UTC) whether a period is due: the day, the Monday-to-Sunday week or the month before, from 07:00 on the day after. The key
   (`weekly:2026-10-26`) is inserted before anything is sent; whoever inserts it sends, nobody else, never again (ADR 0005, point 6).
   A period whose send time came before the person chose the frequency is not sent.
6. **The mail** goes through the organisation's first enabled SMTP or Graph channel (as personal mail, ADR 0019) to the person's own
   sign-in address only. The body is short: counts, the first next steps, links. It never contains vulnerability ids, package names,
   paths or code (ADR 0010). The PDF attached (on by default, can be switched off) is the organisation report built with the
   recipient's access: names of repositories, hosts and websites they can see, and counts. Without a mail channel the choice is refused
   (422) and shown as unavailable; a run without a channel is recorded as skipped.
7. **Audit and limits.** Each PDF download is audited (`report.exported`) and limited to 20 a minute per person. Choosing the report
   mail is personal and not audited, as the notification matrix (ADR 0019).

## Threat model

| Threat | Control |
| --- | --- |
| A member reads another member's private repository through a report, a PDF or a mail | Every repository query of a report goes through the ADR 0030 conditions for the one person; the repository report is a 404 for a repository they cannot see; the mail's report is built per recipient. Tested in the API (two members, a private repository) and the worker (two recipients, different PDFs). |
| Data leaving the network by mail | Opt-in per person; own address only; summary without ids, packages, paths or code; the PDF only with what the recipient may see; can be switched off without the PDF. |
| Hostile names (repository, host, website, package names from scanned or reported data) in the PDF or the mail | The PDF writer removes control characters and writes every string as an escaped literal; the mail is plain text and the subject loses line breaks; message templates are parsed once, inserted values never. |
| A mail sent twice or skipped at a clock change, or by two workers | The period key is claimed before sending; keys come from local calendar dates in the person's zone; tests around 2026-03-29, 2026-10-25 (Europe/Berlin) and 2026-09-06 (America/Santiago). |
| Heavy report queries used to load the database | PDF downloads limited per person; the organisation report reads aggregates; the website overview is bounded by the 200-asset limit. |
| A large attachment rejected by Graph | Attachments over 2.5 MB are refused before sending and recorded as failed. |

## Consequences

- Migration 0048 (additive): `report_subscription`, `report_mail_run`. No new dependency.
- API (additive): `/api/v1/reports/organization`, `/reports/repositories/{id}`, `/reports/hosts/{id}`, `/reports/websites`,
  `/me/report-mail`. Existing endpoints do not change.
- The findings export uses the shared PDF writer; its output is unchanged.
- `docs/reports.md` describes the reports; the ROADMAP's weekly digest item is done in this form.
- Open: reports in further formats (CSV of the organisation report), a report for one team or a chosen set of repositories, and
  compliance mappings (NIS2, ISO 27001), which stay on the roadmap.

## Addendum 2026-11-16: the vulnerability mail

Decided by the maintainer: besides the summary, a person can choose a mail that lists vulnerabilities by name, so a team sees
what came in without opening GarnetOps; known exploited ones (such as Log4Shell) first.

1. **Opt-in per person**, on Account → Notifications: daily or weekly, from a minimum severity (critical, high or medium), for
   every repository the person sees (also ones added later) or the ones they choose, through the mail channel they choose (SMTP
   or Microsoft Graph; by default the organisation's first enabled one, and that one when the chosen one is off or removed).
2. **What it lists**: the vulnerabilities first seen in the period (the person's calendar days, as for the report mail) that are
   still open, per repository, with the vulnerability id, severity, known exploited, package, version and the versions that fix
   it; how many are open per repository from that severity; how many known exploited ones are still open. At most 150 lines;
   the rest is a count and a link. **Nothing new, no mail**: the period is recorded as skipped.
3. **Names in the mail.** Unlike the summary, this mail names vulnerabilities, packages and repositories. It is built with the
   person's visibility at sending time (a private repository of someone else, a repository set aside or one they no longer see
   is never in it), goes only to their own sign-in address, and the card says so before they switch it on. No code, paths or
   secrets.
4. **Once per period**, recorded in `report_mail_run` with keys `vulnerabilities:daily:…` and `vulnerabilities:weekly:…`, like
   the report mail. Personal and not audited, like the report mail.

| Threat | Control |
| --- | --- |
| Vulnerability and package names of repositories the recipient may not see | Built per recipient at sending time with ADR 0030 visibility and active repositories only; chosen repositories are checked when saved and filtered again when sent; tested with a private repository and two recipients. |
| Data leaving the network | Opt-in, own address only, through the organisation's own mail channel; the card names the address and says the mail names vulnerabilities and packages. |
| Hostile package names or versions (scanned content) in the mail | Plain text; control, line-break and bidirectional characters removed, values cut; the subject carries counts and the organisation's name only. |
| A channel of another organisation | Only enabled mail channels of the person's own organisation can be chosen (422 otherwise); a chosen one that is off falls back to the first enabled one. |

Consequences: migration 0056 (additive): `vulnerability_mail`. API (additive): `GET` and `PUT /api/v1/me/vulnerability-mail`.

