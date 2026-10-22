# Notifications

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
