# ADR 0040: Availability of websites

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (show hosting problems next to certificates and software versions; off per asset until switched on)
- Builds on: ADR 0023 and 0033 (website monitoring), ADR 0035 (public DNS), AGENTS.md rules 1 (security first) and 2 (no silent
  changes)

## Context

Website monitoring looks at a site once a day. That finds an expiring certificate or an old PHP line, but not a site that stops
answering at noon, or a host that answers in eight seconds. Teams asked for both next to the other website results, without a
second tool.

## Decision

1. **One request, the one stage 1 already makes.** An availability check resolves the asset under the same address policy as
   stage 1 (public addresses only, the organisation's public DNS choice), connects to port 443, verifies the certificate and sends
   `GET /` with the asset's name. Only the status line and headers are read; the body is never read. Timeout 10 seconds. No other
   path, port or method.
2. **Off per asset**, switched on by an owner or admin, every 1, 5, 15 or 60 minutes (default 5). Switching website monitoring off
   for the organisation stops every check. Switching an asset off forgets its state, so switching on again tells nobody about an
   old outage. Both directions are in the audit log.
3. **Up means the server answered**: a status below 500, so a redirect, 401 or 404 counts as up. Down means no answer in time, a
   refused connection, a failed TLS handshake (including an invalid certificate), an answer that is not HTTP, a name that does not
   resolve or resolves only to non-public addresses, or a 5xx.
4. **Down after three failures in a row**, up again with the first success, so one lost packet is not an outage. A change is told
   once to every member who wants the event **A website is down or back up** (in the app, by mail if chosen). An asset that is down
   counts under **Needs attention** and in the menu.
5. **Slow is a hosting problem, not an outage.** An average answer time over 3 seconds in the last 24 hours is shown as a note.
6. **History**: every check is stored with its time, result, status, answer time and reason; 30 days are kept. The page shows the
   shares for 24 hours, 7 and 30 days, the last 24 hours hour by hour, and the outages.

## Threat model

| Threat | Control |
| --- | --- |
| A name is pointed at an internal address to make GarnetOps probe the network | the address policy of stage 1: non-public addresses are never connected to; the check fails with `address` |
| A hostile server sends a huge or endless body | the body is never read; the connection closes after the headers |
| A hostile server never answers, or trickles headers | 10-second timeout; at most 8 checks run at the same time, at most 200 per minute |
| Checks are used to load someone else's site | assets belong to an organisation and are added by admins; one GET per asset at most once a minute, the same request a browser makes |
| An outage floods people with messages | one message when an asset goes down and one when it comes back, never per failed check |
| Remote text in the history | only a status number and a fixed reason code are stored; nothing the server sends is shown |

## Consequences

- New: table `exposure_uptime_check`, columns `uptime_*` on `exposure_asset` (expand only), `@garnetops/core/uptime`, the worker
  queue `websites.uptime` (every minute), `PUT /api/v1/exposure/{id}/uptime`, `uptime` on every asset and `availability` in
  `GET /api/v1/exposure/{id}`, the notification event `exposure.down`, and the **Availability** tab of a website.
- Checks run from the GarnetOps installation: a site that is down only for the installation's network shows as down, and a site
  that blocks the installation's address shows as down too. There is no second location to confirm an outage.
- Not in this version: other paths, keywords in the page, TCP or ICMP checks, status pages, maintenance windows.
