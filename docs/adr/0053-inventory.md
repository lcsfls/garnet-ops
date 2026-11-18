# ADR 0053: An inventory of systems and their software, entered by hand or by a script

- Status: accepted (2026-11-18)
- Date: 2026-11-18
- Decided by: maintainer (a plain inventory table that can be filled and read by a script, without proving control of anything;
  chosen: a system with its software list, tokens of their own for scripts with separate read and write scopes, no matching
  against the vulnerability database)
- Builds on: ADR 0008 (gate tokens), ADR 0033 (modules), ADR 0034 and 0037 (host agent), ADR 0052 (the situation), AGENTS.md rules
  1, 2 and 7

## Context

The day before a security release ("all supported PHP versions, details tomorrow") the only useful question is: where do we run
it, and in which version? GarnetOps knows that for repositories and for hosts with the agent. It does not know it for anything
else a team runs: shared hosting, appliances, a customer's server nobody may install an agent on, a switch. Those live in a
spreadsheet today.

Website monitoring asks for a DNS TXT record before it looks at a name (ADR 0023), because GarnetOps then sends requests to it.
An inventory sends nothing anywhere: it stores what a person or a script tells it. So it needs no proof of control, and it must
never become a list of targets for anything GarnetOps does.

## Decision

1. **A system with its software.** An inventory entry is a system: a **key** (the stable name a script addresses it by, for
   example its host name; unique in the organisation), a name, a kind (server, virtual machine, container, website, network
   device, appliance, workstation, other), an environment, notes, tags, and a list of software, each a name and a version. At most
   5,000 systems per organisation and 5,000 software entries per system.
2. **By hand or by script.** Members and above add, change and remove systems in the app. A script does the same through the
   API with an **inventory token**: `PUT` a system by its key (the software list is replaced, other fields only when sent, so
   notes and tags kept by hand survive), `DELETE` it, or read everything as JSON.
3. **Tokens of their own.** Inventory tokens (`goi_…`) are created by owners and admins with a recent sign-in, are shown once,
   stored as a SHA-256 hash only, and audited when created and revoked; a script that adds or removes a system is audited too
   (routine updates are not: a nightly report of every server would bury the log). A token has one
   **scope**: `write` (put and delete systems, read nothing) or `read` (read the inventory, change nothing), so a token left on
   a server cannot read the list of every other system. 120 requests a minute per token. A token reaches nothing else in
   GarnetOps.
4. **No verification, no connection.** GarnetOps never connects to an inventory entry, resolves its name or scans it. Nothing in
   the product takes inventory entries as targets; website monitoring and its proof of control stay as they are.
5. **No matching.** Inventory software is **not checked** against the vulnerability database: a typed "nginx 1.26" cannot be
   matched reliably to a distribution's package. The page says so, and such systems are never counted as checked. Matching is
   the agent's job.
6. **Where does it run?** One search over software names across the inventory, the packages of hosts with the agent, the images
   of running containers and the repositories' packages (each as far as the person may see it): the answer to "where do we have
   PHP" in one table.
7. **Read by everyone in the organisation**, like hosts. Always on: it makes no request and stores only what it is given, so it
   is not a module.

## Threat model

| Threat | Impact | Mitigation |
| --- | --- | --- |
| A write token leaks from a server | False or hostile entries | It can only put and delete inventory systems; it reads nothing. Entries are text, cleaned and limited; revoked in one click; systems it adds or removes are audited and its last use is shown |
| A read token leaks | The inventory (names, versions) is reconnaissance for an attacker | A scope of its own, never needed on the reporting servers; hashed, revocable, audited, rate limited |
| Hostile names, versions, notes | Markup or script injection, mail or CSV injection | Shown as text; control characters removed; lengths limited; exports escape per format as the other reports do |
| An entry is taken as proof of ownership | GarnetOps sends requests to a system it was merely told about | Nothing reads inventory entries as targets: no inventory code path makes an outbound request, and no job reads these tables |
| A typed version is read as "checked" | A false sense of safety | The page and the software search label inventory entries "not checked"; they never count as checked in the situation |
| A script floods the inventory | Storage, slow pages | 5,000 systems, 5,000 software entries each, 1 MB per request, 120 requests a minute per token |
| Another organisation's token or key | Cross-tenant write | The token names its organisation; keys are unique per organisation; every query filters by it; tested |

## Consequences

- Migration 0057 (additive): `inventory_system`, `inventory_software`, `inventory_token`.
- API (additive): `/api/v1/inventory` (session) and `/api/v1/inventory-feed` (inventory token).
- A page **Inventory** under Infrastructure, with an example script to copy ([docs/inventory.md](../inventory.md)).
- A report that says what the last one said rewrites nothing: only the time of the report changes.
- Open: inventory systems on the situation page as "not checked" rows; importing a CSV; an inventory report.
