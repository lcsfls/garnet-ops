# ADR 0019: In-app notifications, toasts and personal preferences

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (a bell with notifications per person, toast messages for the results of actions, and a
  per-person matrix of what to receive; organisation channels stay as ADR 0010 made them)
- Implements: AGENTS.md "Notifications via SMTP or Microsoft Graph", "Calm UI"
- Builds on: ADR 0005 (time zones), ADR 0009 (roles), ADR 0010 (notification channels), ADR 0013 (the shared LISTEN
  connection of the AI stream), ADR 0017 (the account page)

## Context

ADR 0010 sends a summary to chat tools and shared mailboxes. Nothing told a person who is *signed in* that a scan found
something, a certificate changed or a fix pull request was merged, and the results of a person's own actions (saved,
copied, scan queued) were small text notes scattered over forms. A sysadmin also wants to choose, for themselves, what
reaches them and where, without changing what the whole organisation's channels do.

## Decision

### 1. Personal notifications

- Table `user_notification` (migration 0017, additive): person, organisation, event type, **title key**, a few
  **parameters**, a **relative link**, created, read, and the mail state. A notification stores **no free text**. The
  sentence is built where it is read, in the reader's language (`renderNotificationItem` in `packages/i18n`, used by
  the bell and by the personal mail). Parameters are names and counts only: repository, server and cluster names,
  counts, a version, a role, a person's display name. They are cut to 120 characters, stripped of control and
  bidirectional characters, limited to eight keys, and always shown as text. **No package names, vulnerability ids,
  paths, error text or anything else from scanned content** ever goes in.
- The link is a path inside the app and nothing else (`safeAppLink`: starts with one `/`, no scheme or host, no `//`,
  no backslash, no `..` or encoded dot or slash, only URL-safe characters, at most 300 characters). It is checked when
  it is stored and **again before the web app follows it**; a stored value that fails is shown as plain text.
- **Retention:** each person keeps their newest **500** notifications (enforced on every insert) and nothing older
  than **90 days** (hourly job in the worker).

### 2. Events

Role decides first. A person never receives, and the API never accepts a choice for, an event their role cannot receive.

| Group | Event | Told | Scope | In channels (ADR 0010) |
| --- | --- | --- | --- | --- |
| Code | `finding.new_critical` | everyone | all or mine | yes |
| Code | `gate.blocked` | everyone | all or mine | yes |
| Code | `scan.failed` | member and up | all or mine | yes |
| Code | `fix_pr.merged` | member and up | mine (default) or all | no, in app only |
| Code | `fix_pr.failed` (also a request lost to a worker restart) | member and up | mine (default) or all | no |
| Infrastructure | `infra.host_key_changed` | owner, admin | - | no |
| Infrastructure | `infra.certificate_changed` (Proxmox VE, Wazuh) | owner, admin | - | no |
| Infrastructure | `infra.sync_blocked` (Proxmox VE, Wazuh: the token or account can do more than read and is not acknowledged) | owner, admin | - | no |
| Account and team | `team.invitation_accepted` | owner, admin | - | no |
| Account and team | `team.role_changed` | the person concerned only | - | no |
| System | `system.update_finished` (update succeeded or failed, from the sidecar's journal) | owner, admin | - | no |

"Mine" means: for repository events the repository was added by that person; for fix pull requests the person asked for
the request or added the repository. Infrastructure events fire **once per change**, at the same point where the audit
entry is written, not on every sync. The update event fires when the journal entry is first copied into the audit log.

Not included yet, because nothing detects them today: "update available" (the release list is fetched on demand from the
sidecar) and new vulnerabilities on servers (the channels do not carry them either). They can be added as catalogue
entries without a schema change.

### 3. Preferences: the matrix

- Table `notification_preference` (organisation, person, event): **in app**, **email**, **scope**. Defaults when no row
  exists: in app on for everything the role receives, email off, scope all (fix pull requests: mine). Saving stores
  explicit rows for every event shown, so a later change of a default never silently changes what somebody chose.
- The matrix is on **Account → Notifications** and only lists events the person's role can receive. The **email column
  is available only when the organisation has an enabled SMTP or Graph channel**; without one the checkboxes are
  disabled and a note says why (and, for admins, where to set it up). Saving email while unavailable is refused (422),
  and a stored email choice is reported as off while no mail channel exists.
- **Organisation channels are shared destinations; the matrix is what a person receives.** Both pages say so and link to
  each other: Settings → Notifications (owners and admins) and Account → Notifications. Webhooks and shared mailboxes are
  not affected by anyone's matrix.
- **Audit decision:** preference changes are **not** written to the audit log. They are personal, change nothing for
  anyone else, cannot widen access (role first), and personal mail only ever goes to the person's own sign-in address,
  which cannot be changed. Security-relevant changes (channels, roles, invitations) stay audited as before. The change
  endpoint is rate-limited (30 per minute per person).

### 4. Realtime: one SSE endpoint, the existing shared LISTEN connection

- `GET /api/v1/me/notifications/stream` (session auth, like every route). The worker (or an API route) writes the row and
  `pg_notify('user_notification', {u, id})` **in the same transaction**. The payload names the person and the row id
  only. A single subscription per API process (`UserNotificationBus`) sits on the shared LISTEN connection
  (`lib/listen-bus.ts`, the generalised `ai-bus`) and hands a notice to the open streams of that person. A stream then
  reads **its own person's rows in its own organisation** from the database; it never forwards the payload.
- Events: `ready` (unread count and newest id), `notification` (the row; the SSE id is the row id), `resync` (reload the
  list). **Resume:** a browser that reconnects sends `Last-Event-ID` (or `?after=`) and gets what it missed; more than 50
  at once becomes `resync`. Heartbeat comment every 15 seconds; `cache-control: no-store, no-transform`,
  `x-accel-buffering: no`.
- **Limits:** at most **4 open streams per person** per API process (429 `too-many-streams` otherwise); a stream ends
  after **10 minutes** and the browser reconnects, which re-checks the session (a signed-out or removed person gets 401,
  and the client keeps polling and retrying with growing pauses). The list endpoint is the source of truth: ids are assigned when a row is
  written, so a row committed late with a lower id than one already sent could be missed by the stream; the periodic
  safety poll (5 minutes with the stream up) and every reconnect's `ready` check close that gap.
- **Fallback:** if the stream cannot be opened or breaks, the client polls the list every **30 seconds** and retries the
  stream with a growing pause (5 s to 60 s). The panel says which mode it is in.
- The list endpoint (`GET /me/notifications`, cursor `before`, 30 per page, unread count capped at 1000), marking one
  read, and marking all read up to the newest id the person has seen are all scoped to the person and organisation. A
  foreign or unknown id is a 404.

### 5. Personal mail

- Sent by the worker **through the first enabled SMTP or Graph channel of the organisation**, with that channel's sender,
  **to the person's own sign-in address only** (never to the channel's recipient list). Content is the same **summary and
  link only**, in the person's language, plain text. Disabling or deleting the mail channel stops personal mail too.
- **Rate limit and batching:** at most **one mail per person and event type every 15 minutes**. What piles up meanwhile
  goes out as **one digest** (one line per notification, up to 20, then a count, and a link to the app) when the
  interval is over. A sweep runs every minute.
- Rows are **claimed before sending** (marked sent), so two workers never send the same mail; a mail that fails is marked
  `failed` and **not retried** (the notification is still in the app); without a mail channel, after the person left
  the organisation, or after 24 hours it is dropped.

### 6. Toasts

- A small system of our own (`lib/toast-queue.ts` logic, `lib/toast.ts` store, `components/toast-region.tsx`); no new
  dependency, CSS for the short slide-in (reduced motion switches every animation off globally). Motion is available but
  not needed here.
- Bottom right, **at most three** visible: a fourth pushes out the oldest message that closes by itself; errors are never
  pushed out (with three errors showing, the next message waits). The same message is not stacked, it restarts its timer.
- Success and information close after 6 seconds (10 with an action); **errors stay until closed**. Hovering or focusing a
  message **pauses** it. Each message is its own live region: **`role="alert"` (assertive) for errors, `role="status"`
  (polite)** for the rest, with a visually hidden "Done:", "Error:" or "Note:" and an icon of its own, so colour is never
  the only signal. **Success is neutral, not green** (green means proof, rule 6).
- **Keyboard:** the close button and links are in the tab order; nothing takes focus; **Alt+Shift+T** moves to the first
  message. Messages are text, never markup.
- Used for: saved settings (profile, preferences, scan schedule, AI, quality gate rules, attack overview), password
  changed, authenticator replaced, passkeys added and removed, sessions signed out, scan queued, invitation created,
  channel test queued, copied (and a clipboard refusal), marking notifications read, and failures of those actions that
  are not form-field errors. Errors that belong to a field stay inline on the form.

### 7. The bell

Top right of the header, left of the account menu: an unread badge with the number (**"99+"** from a hundred; no pulsing,
no animation), a panel (disclosure, Escape and click outside close it, focus is never moved) with the newest
notifications **grouped by day in the person's time zone** (ADR 0005: "today", "yesterday", then the date) and relative
times (hours and minutes below 12 hours, calendar days of the person's zone beyond; the exact time on hover), mark one or
all read, a link on each notification, "Show older", and "Notification settings". An unread notification is bold, has a
bar and is announced as "Unread" (not colour alone). New notifications that arrive while the app is open also show a
toast with a "View" link (more than two at once become one message).

## Threat model

| Threat | Control |
| --- | --- |
| Reading another person's or another organisation's notifications (IDOR) | Every query names the signed-in person **and** organisation from the session; ids in the URL are only filters on top of that. A foreign id is a 404. The stream reads rows itself; the NOTIFY payload carries no content. Tested with two people and two organisations. |
| A member sees an admin-only event (certificate changed, update result) | Role is applied first, in one function (`selectRecipients`) used by every producer; stored choices cannot widen it, the matrix lists only the role's events and the API rejects the others. |
| Content injection: a hostile repository or server name (markup, script, bidi tricks, very long text, placeholders) | Parameters are sanitised on write, rendered as React text and filled into the sentence in a single pass; the mail is plain text. Package names, paths and error text are never stored. |
| Link injection: `javascript:`, `//host`, `https://phish`, path tricks | Links are app paths only, validated on write and again in the browser; anything else is shown without a link. |
| Spam or data leak by mail | Recipient is the person's own account address; the channel's recipient list is never used; one mail per type per 15 minutes; summary and link only; a missing mail channel means nothing is sent; no secrets or code. Mail headers are built by nodemailer from the stored address and a subject made of a sanitised name. |
| Exhausting connections or the database (SSE floods, notification floods) | 4 streams per person, 10-minute lifetime, a single LISTEN connection for all, 500 rows and 90 days per person, rate limits on read-marking and preference changes. |
| A stream that outlives a signed-out session | Streams end after 10 minutes and a reconnect needs a valid session. (A signed-out person's open stream is not cut at once; it only ever carries that person's own notifications.) |
| Forged NOTIFY to inject or hide notifications | Needs database access, which already means the attacker owns the data; the notice only triggers a read of the person's own rows. |
| Losing or duplicating a notification | Row and NOTIFY in one transaction; the list is authoritative; stream resume by id; mail claimed before sending (at most once); events fire at state changes, not per sync. |
| Preference tampering | Own rows only, validated against the role's events and the mail channel; defaults are explicit, nothing is read from the request that selects another person. |
| Secrets in notifications or logs | No secret ever enters a notification; logs carry error names only. |

## Consequences

- Migration 0017 (additive): `user_notification`, `notification_preference`. No new dependency.
- API (additive): `/api/v1/me/notifications` (list, `/{id}/read`, `/read-all`, `/stream`) and
  `/api/v1/me/notification-preferences`.
- `ai-bus` is now a thin view of `lib/listen-bus.ts`; behaviour of the AI stream is unchanged.
- Worker: personal notifications for scans, fix pull requests, certificate changes, blocked syncs and host key changes;
  a one-minute mail sweep and an hourly retention job.
- Settings → Notifications and Account → Notifications explain each other; `docs/notifications.md` and
  `docs/account.md` describe the behaviour.
- Open: per-event quiet hours, a full "all notifications" page, notifications for new vulnerabilities on servers, "update
  available", and cutting an open stream when a session is revoked.
