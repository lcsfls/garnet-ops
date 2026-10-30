# ADR 0035: Public DNS next to the local resolver, for public names only

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (an option in the interface, per organisation, off by default; only for lookups of public names; Cloudflare,
  Google or Quad9)
- Builds on: ADR 0016 (address-checked outbound client), ADR 0023 and 0033 (website monitoring), ADR 0034 (registry checks),
  AGENTS.md rules 1 and 7

## Context

Website checks ask many DNS questions per website (addresses, CNAME, MX, NS, CAA, TXT, SPF, DMARC), and the proof of control and the
registry checks add more. Behind a slow local resolver (a firewall or router that forwards DNS slowly) the checks run into their
time-outs and report "DNS failed", although nothing is wrong with the websites.

Replacing the containers' resolver (Compose `dns:`) would send every lookup to a public provider, including internal names a public
resolver cannot know (the forge at `git.example.lan`, the directory server, the mail relay), and a resolver listed second is only
asked when the first one does not answer at all, not when it is slow.

## Decision

1. **Per organisation, in the interface, off by default.** Settings → Modules → **Public DNS for public names**: only our own resolver
   (the default), Cloudflare (1.1.1.1, 1.0.0.1), Google Public DNS (8.8.8.8, 8.8.4.4) or Quad9 (9.9.9.9, 149.112.112.112). Choosing a
   provider needs an owner or admin, a recent sign-in and an acknowledgement that names what is sent where; going back to our own
   resolver needs neither. Both are audited (`organization.public_dns_enabled` with provider and servers,
   `organization.public_dns_disabled`). API: `GET` and `PUT /api/v1/organization/dns`.
2. **Only lookups of public names.** The website checks (stage 1 and 2), the proof of control, the registry checks and the
   Certificate Transparency requests. Everything that may reach an internal host keeps the local resolver alone: forges, clones,
   directory sign-in, mail, the AI endpoint, notifications.
3. **Next to the local resolver, not instead.** Each query goes to both at once; the first clear answer counts (records, or "no such
   record"). A failure (time-out, SERVFAIL) waits for the other one; when both fail, the local resolver's error is reported. A slow
   local resolver no longer holds a check up, and a provider that cannot be reached changes nothing.
4. **The address policy is unchanged.** Whichever resolver answers, the answers go through the same checks as before: website checks
   connect only to public addresses, outgoing HTTPS (registries, crt.sh) refuses a name with any non-public answer.

## Threat model

| Threat | Control |
| --- | --- |
| Names of the organisation's websites and the registries it uses reach a DNS provider | off by default; an owner or admin chooses with a recent sign-in and an acknowledgement naming the provider and its addresses; audited; the page shows who chose it and when |
| Internal names leak to a public resolver | only lookups of public names use it; internal targets keep the local resolver |
| A spoofed or manipulated answer aims a check at the internal network | the address policy applies to every answer, from either resolver |
| The provider answers differently than the local resolver (split horizon) | website checks want the outside view anyway; the proof of control also asks the zone's own name servers (ADR 0033 amendment) |
| The provider is down or blocked | the local resolver still answers; nothing waits for longer than before |

## Consequences

- New table `public_dns_settings` (one additive migration), new routes `GET`/`PUT /api/v1/organization/dns`.
- DNS to the provider is plain DNS over port 53; DNS over HTTPS or TLS is not in this version.
