# ADR 0033: Website monitoring as a module

- Status: accepted (2026-10-29), planned for 0.0.12
- Date: 2026-10-29
- Decided by: maintainer (bring back the external checks of ADR 0023 as a module that is off by default, with the proof of control by
  DNS TXT record or file before anything beyond what a browser does)
- Supersedes: ADR 0025 in part (for external exposure only: section 2 and section 4 no longer apply to it)
- Builds on: ADR 0023 (the design of the checks, kept as it was), ADR 0019 (notifications), AGENTS.md rules 1, 2, 3 and 6

## Context

ADR 0025 removed external exposure together with the infrastructure modules, to keep GarnetOps a developer pipeline. Teams that run
their own websites asked for it back: which certificate expires, whether mail authentication is set up, which security headers are
missing, and, for names they control, which ports answer from the internet. The checks of ADR 0023 were sound and well tested; what
did not fit was having them always present.

AGENTS.md describes modules that an organisation switches on independently. Website monitoring is the first one that is off by
default, because once it is on the installation connects to public hosts that an admin names.

## Decision

1. **The checks are those of ADR 0023**, restored from `v0.0.3` (core rules, worker, API) with these changes:
   - **No location.** The GeoIP and ASN data of ADR 0016 is gone with ADR 0025; snapshots no longer carry a `geo` field and the pages
     show no location.
   - **New queue names** (`websites.verify`, `websites.run`, `websites.tick`). The `exposure.*` queues of 0.0.3 stay on the list the
     worker removes on start (ADR 0025), so nothing left in an old queue runs unasked.
   - **The interface is rebuilt in Svelte** (ADR 0027) under **Infrastructure → Websites** (named Monitoring until 0.0.12) (`/websites`); `/exposure` links of 0.0.3 lead
     there. The API keeps its 0.0.3 paths (`/api/v1/exposure/...`) and shapes, minus the location fields.
2. **A module switch per organisation** (`exposure_settings.enabled`, off by default, migration `0030`). Owners and admins switch it
   under **Settings → Modules** (`PUT /api/v1/organization/modules/websites`), audited as `organization.module_enabled` and
   `organization.module_disabled`. `GET /api/v1/me` tells the web app (`organization.modules.websites`).
3. **While the module is off nothing happens:** the worker's schedule skips the organisation, a queued run fails as `moduleOff` before
   it connects anywhere, proofs are not checked, every `/api/v1/exposure` route answers 409 `module-off`, the page and the menu entry are
   hidden, the global search lists no websites and the notification preferences do not offer the four website events.
4. **Switching off is the safe direction.** It keeps websites, findings and history (rule 2), but switches stage 2 off for every website
   and voids the acknowledgements, and fails runs that were still waiting. Switching on again starts from stage 1 only; stage 2 needs a
   fresh proof (48 hours, ADR 0023) and a new acknowledgement per website.
5. **Proof of control** stays as in ADR 0023: a TXT record `_garnetops-challenge.<name>` with `garnetops-verify=<code>`, or the file
   `/.well-known/garnetops-verify.txt`, checked daily and before every stage 2 run; a definite loss stops stage 2 at once.

## Amendment (after 0.0.12): the modules can be found, and the proof is asked at the source

- **Owners and admins see a module's menu entry while it is off.** Hidden entries meant that nobody found the features. The entries
  sit under **Infrastructure** (Agents, Websites); while a module is off its page says what it does and offers the switch (the same
  `PUT /api/v1/organization/modules/{name}`, audited as before). Other members still see an entry only while the module is on.
  Nothing else changes while a module is off: no connection, no proof check, 409 `module-off`.
- **The menu counts what needs a look** (`GET /api/v1/exposure/attention`, `GET /api/v1/hosts/attention`): the websites of the
  "attention" filter, the hosts that stopped reporting or run something with an open critical or high vulnerability, coloured by the
  worst severity. A "+" next to each entry opens its add dialog.
- **Adding a website opens its proof.** The new website's page opens with the verification dialog, so the TXT record is the next step.
- **The TXT record is also asked of the domain's own name servers.** The first check runs right after adding, before the record can
  exist; recursive resolvers then keep that "not there" for the zone's negative TTL, and resolvers with an internal view of the own
  domain never see the public record. The worker therefore finds the zone's name servers (NS of the name or its nearest parent),
  resolves them under the address policy (public addresses only, so no internal server is ever asked), and sends each at most one TXT
  query for `_garnetops-challenge.<name>`, at most three servers. The answer is merged with the system resolver's: either one finding
  the record verifies, so networks that block outgoing DNS behave as before. No new data leaves: the challenge name was already asked
  through the resolver.

## Threat model

Everything in the threat model of ADR 0023 applies unchanged (hostile remote text, address policy and rebinding, no payloads, rate
limits, proof of control as an accountability control, Certificate Transparency as an opt-in data flow). In addition:

| Threat | Control |
| --- | --- |
| An installation that updates to 0.0.12 starts connecting to public hosts without anyone deciding so | the module is off by default; the 0.0.3 data was deleted by ADR 0025, so there is nothing to resume |
| A run queued before the switch-off still connects | the worker checks the switch when it claims a run and before a proof check; switching off also fails waiting runs |
| Stage 2 resumes silently after switching the module off and on | switching off switches stage 2 off and voids the acknowledgements |
| Old `exposure.*` jobs in a database restored from 0.0.3 | the worker keeps removing those queues on start; the new queues have other names |
| A member switches the module on | owners and admins only (403 otherwise), audited |

## Consequences

- New: `GET /api/v1/organization/modules`, `PUT /api/v1/organization/modules/{name}`, `organization.modules` in `GET /api/v1/me`,
  `websites` in `GET /api/v1/search`. `/api/v1/exposure` is back (it was removed in 0.0.4). Nothing that exists today changes meaning.
- crt.sh is again a possible external service, opt-in as in ADR 0023 (`docs/COMPONENTS.md`).
- The tables of ADR 0023 are in use again and are no longer dropped in 1.0.
