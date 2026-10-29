# ADR 0010: Notifications by webhook and mail

- Status: accepted (2026-10-21)
- Date: 2026-10-21
- Decided by: maintainer (summary and link only; webhooks only over HTTPS and never to
  loopback, link-local or metadata addresses; nodemailer allowed for SMTP)
- Implements: AGENTS.md "Notifications via SMTP or Microsoft Graph `sendMail`"; ROADMAP
  Phase 5 "Mail via SMTP or Graph", brought forward; webhooks for chat tools

## Context

People want to hear about a new critical vulnerability or a blocked gate without keeping
GarnetOps open. Every notification leaves the customer's network on purpose, so it must
carry as little as possible (AGENTS.md: "no customer code, finding or log leaves the
customer's network unless the customer explicitly configures it").

## Decision

1. **Channels** are configured per organisation by owners and admins (audited):
   - **Webhook** with a format: generic JSON, Discord, or Slack-compatible (Slack,
     Mattermost, Rocket.Chat, and any tool that accepts `{"text": …}`).
   - **Mail via SMTP** (host, port, TLS mode, user, sender, recipients).
   - **Mail via Microsoft Graph** `sendMail` with an app registration restricted to one
     sending mailbox (tenant, client id, client secret, sender, recipients).
   Each channel picks its events and can be switched off and tested.
2. **Events** in the first version: a scan of a repository's branch found **new critical
   or known exploited** vulnerabilities; a **gate blocked**; a **scan failed**; and a
   **test** message.
3. **Content: summary and link only.** Repository name, counts and severities, gate result,
   and a link to GarnetOps. No vulnerability ids, package names, paths, code or error
   output; the details are behind the sign-in.
4. **Secrets are sealed** in the vault (ADR 0004): the webhook URL (it carries the access
   token for Discord and Slack), the SMTP password and the Graph client secret. The API
   seals; only the worker can open them, and the worker sends. They are never shown again;
   the settings show the host only.
5. **Webhook targets**: HTTPS only. Before connecting, every address the host resolves to
   is checked, and connecting re-checks the address it actually uses (no DNS rebinding):
   loopback, link-local (including cloud metadata at 169.254.169.254), unspecified,
   multicast and broadcast addresses are refused; private network addresses are allowed
   (an internal Mattermost). Redirects are not followed; 10-second timeout; the answer's
   body is neither stored nor shown.
6. **Deliveries** are recorded per channel (sent or failed, a short safe reason) and shown
   in the settings; failed deliveries are retried twice by the job queue.

## Threat model

- **Data leaving the network**: limited to the summary in decision 3, only to channels an
  admin configured, only for chosen events.
- **SSRF through a webhook URL** (an admin, or a stolen admin session, points GarnetOps at
  an internal service or the cloud metadata endpoint): HTTPS only, address checks at
  resolve and connect time, no redirects, no response body, admin-only and audited,
  step-up for creating and changing channels.
- **Leaked channel secrets**: sealed at rest, never returned by the API, never logged.
- **Mail as a phishing vector**: fixed templates, plain text, no user-supplied content
  except repository names.
- SMTP and Graph hosts are admin configuration; SMTP may point to an internal relay.

## Consequences

- New tables `notification_channel` and `notification_delivery` (additive migration).
- New dependency nodemailer (MIT-0) in the worker; MIT-0 joins the allowed licences.
- New settings section "Notifications".

## Amendment (0.0.10): filters per channel and Discord embeds

- A new event `finding.new` counts a scan's new open findings per severity. Each channel sets a minimum severity for it
  (`filters.minSeverity`, high unless chosen) and receives only the counts from that severity on; a scan with new findings only
  below the minimum sends nothing to it. `finding.new_critical` is unchanged, so existing channels receive exactly what they
  did before (AGENTS.md rule 2).
- A channel can be limited to chosen repositories (`filters.repositoryIds`, repositories of its own organisation only; empty
  means all, including later ones). The worker applies both filters before it queues a message.
- Discord messages are sent as one embed (title linking to GarnetOps, a colour per kind of event, the organisation in the
  footer) instead of plain text. What a message contains does not change: a summary and a link, no vulnerability ids, package
  names, paths or code. Markdown characters in repository names are escaped, and mentions stay switched off.
