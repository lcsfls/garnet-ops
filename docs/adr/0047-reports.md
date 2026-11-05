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
