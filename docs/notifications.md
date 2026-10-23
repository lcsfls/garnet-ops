# Notifications

There are two kinds, and they are independent:

- **Organisation channels** (webhooks, SMTP, Microsoft Graph) are *shared destinations* that owners and admins set up
  under **Settings → Notifications** (ADR 0010). They are described below.
- **Your own notifications** are what *you* receive: the bell in the top bar, short messages (toasts) and, if you want
  them, mail to your own address. Everyone chooses their own under **Account → Notifications** (ADR 0019). They are
  described in the second half of this page.

A channel is not changed by anyone's personal choices, and the personal choices do not change a channel. The one thing
they share: personal mail is sent through the organisation's mail channel (see "Personal mail").

## Organisation channels

GarnetOps can tell a chat or a mailbox when a scan of a repository's branch finds **new
critical or known exploited vulnerabilities**, when a **quality gate blocks**, or when a
**scan fails** (ADR 0010). Owners and admins set this up under **Settings →
Notifications**.

## What leaves your network

Only a summary and a link: the repository name, the counts, the gate result and a link to
GarnetOps. Vulnerability ids, package names, paths, code and error output stay inside;
people see the details after signing in. Pull request checks are not notified; the
pipeline shows them.

## Channels

| Type | What you need |
| --- | --- |
| Webhook, Discord format | In Discord: channel settings → Integrations → Webhooks → New Webhook → Copy URL |
| Webhook, Slack format | An incoming webhook in Slack, Mattermost or Rocket.Chat |
| Webhook, generic JSON | Any HTTPS endpoint that accepts a JSON POST |
| Mail via SMTP | Server, port, TLS (465) or STARTTLS (587), optional user and password, sender, recipients |
| Mail via Microsoft Graph | An app registration with `Mail.Send`, limited to the sender's mailbox by an application access policy; tenant id, client id, client secret, sender, recipients |

Each channel chooses its events and the language of its messages, can be switched off,
and has a **Send test** button. The settings show the result of the last delivery.

## Security

- Webhook URLs, SMTP passwords and Graph client secrets are stored encrypted (vault, ADR
  0004) and never shown again; only the worker can open them.
- Webhooks go over HTTPS only. Addresses that point to the host itself, link-local
  addresses (including cloud metadata such as 169.254.169.254), multicast and similar are
  refused, both when saving and when connecting. Internal servers on private networks are
  allowed. Redirects are not followed, and the answer is not stored.
- Adding a channel needs a sign-in from the last ten minutes. Every change and every test
  is in the audit log.
- Discord messages never mention anyone, whatever a repository is called.

The worker sends the messages, so it needs outbound access to the targets, and
`PUBLIC_URL` (set by `deploy/install.sh`) for the links.

## Your own notifications (bell, toasts, personal mail)

### The bell

The bell in the top bar, left of your account menu, shows how many notifications are unread (a number, "99+" from a
hundred). Open it for the latest ones, grouped by day in **your** time zone (Account → Profile), with relative times
("3 hours ago"; the exact time on hover). Click a notification to open the page it is about; it is marked read. **Mark
as read** (the check mark) marks one, **Mark all as read** all of them, **Show older** loads more, and **Notification
settings** opens your matrix. Notifications are kept for 90 days, at most 500 per person.

New notifications appear while GarnetOps is open, without a reload, and also show a short message with a **View** link.
This uses one server-sent event stream per tab (at most four per person). If it cannot be opened, for example behind a
proxy that buffers it, the bell checks every 30 seconds instead and says so at the bottom of the panel.

A notification holds a summary and a link, never details: a repository, server or cluster name, a count, a version. No
vulnerability ids, package names, paths, error output or code. You only get notifications about what your role may see.

### What you can be told about

| Group | Event | Who gets it |
| --- | --- | --- |
| Code | New critical or known exploited vulnerabilities in a scan | everyone |
| Code | A quality gate blocked | everyone |
| Code | A scan failed | members, admins, owners |
| Code | A fix pull request was merged, or failed | members, admins, owners (default: only requests you made or repositories you added) |
| Infrastructure | A server's SSH host key changed | admins, owners |
| Infrastructure | A Proxmox VE or Wazuh certificate changed | admins, owners |
| Infrastructure | A Proxmox VE or Wazuh sync, or the UniFi IPS preview, is blocked because the token or user can do more than read | admins, owners |
| Infrastructure | A UniFi certificate changed | admins, owners |
| Infrastructure | A UniFi device is offline (in two syncs in a row; once until it was online again) | admins, owners |
| Infrastructure | A UniFi firmware update is available (once per device and firmware version) | admins, owners |
| Infrastructure | An exposed certificate expires soon or has expired (Exposure; once at 30, 14, 7 days and when expired) | admins, owners |
| Infrastructure | An asset lost its verification (Exposure; stage 2 stopped) | admins, owners |
| Infrastructure | A new port is open on an asset (Exposure, stage 2; not for the first run) | admins, owners |
| Infrastructure | A risky service is reachable from the internet (Exposure, stage 2; once while it stays open) | admins, owners |
| Account and team | An invitation was accepted | admins, owners |
| Account and team | Your role changed | you |
| System | An update finished or failed | admins, owners |

The first three are also events of the organisation channels; the others are only for the people in the app. Changes in
infrastructure are announced **once per change**, not on every sync. "Update available" and new vulnerabilities on
servers are not announced yet.

### The matrix: Account → Notifications

One row per event your role can receive, two columns: **In app** and **Email**.

- **Defaults:** in app on, email off.
- **Applies to** (events about repositories): *All repositories* or *Only repositories I added*; for fix pull requests
  *All requests* or *Only requests I made*. If you switch both columns off, the event does not reach you.
- **Email** needs an organisation mail channel (SMTP or Graph, above). Without one the column is disabled and the page
  says so; owners and admins get a link to set one up.
- **Restore defaults** only changes the form; nothing is saved until you press **Save**.

Changes to your own choices are not written to the audit log: they are personal, cannot widen what your role may see,
and mail only ever goes to your own address.

### Personal mail

- Sent by the worker through the **first enabled** SMTP or Graph channel of the organisation, with that channel's sender
  address, **to your sign-in address only**. The channel's own recipients are not used. If an owner switches the mail
  channel off or deletes it, personal mail stops too.
- Same content as the channels: a summary and a link, in your language. Never secrets, code or details.
- **At most one mail per event type every 15 minutes.** If more happen in the meantime, you get **one digest** when the
  15 minutes are over (one line each, up to 20, and a link). A mail that cannot be sent is not retried; the
  notification is still in the bell. A mail that could not be sent within a day is dropped.

### Toasts

Short messages at the bottom right tell you the result of what you just did: saved, copied, scan queued, invitation
created, and failures that do not belong to a field. They close by themselves after a few seconds; **errors stay until
you close them**. Hovering over a message or moving focus into it pauses it. At most three are shown. They do not take
the keyboard focus: use Tab to reach the close button and link, or **Alt+Shift+T** to jump to the first message. With
"reduce motion" set in your system, nothing slides. Screen readers announce errors at once and everything else politely.
