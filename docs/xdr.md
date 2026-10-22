# XDR (Wazuh)

**Infrastructure → XDR** shows what your own Wazuh sees: how many alerts of which severity in the
last day, week and month (with the change against the period before), which MITRE ATT&CK tactics
they fall under, which agents are busiest, which files changed (file integrity monitoring), how
many vulnerabilities each agent has, and a table of all agents with their status. It can link an
agent to a server you already have, and it prints the official commands to install a Wazuh agent
(ADR 0015).

**GarnetOps only reads.** It does not build, ship or run a Wazuh agent, it is not a SIEM, and it
cannot change anything in Wazuh: it cannot restart an agent, run an active response, edit a rule or
delete an alert. You run Wazuh (GPL-2.0, a separate program, not part of GarnetOps); GarnetOps
talks to its two network APIs and nothing else. No Wazuh code or client library is part of
GarnetOps.

Everyone in your organisation can see the XDR page once a connection exists (the entry is not in
the navigation before that). Owners and admins connect and manage it under **Settings → XDR /
Wazuh**.

> **Status.** Tested against recorded synthetic answers of Wazuh 4.12 and 5.0 and against local
> fake servers, **not** against a real Wazuh installation. Wazuh 5.x is shown as **preview**: its
> index and field names follow the documentation of the release candidates and are an assumption
> until 5.0 is generally available. If something does not read, the sync run says which part.

## What you need

- A Wazuh 4.x or 5.x manager **and** indexer that you run. Both are in the all-in-one install.
- Network access **from the GarnetOps worker to port 55000 (manager API) and port 9200
  (indexer)**. Nothing else needs to reach out: the page works from what the worker stored.
- Someone with administrator rights on Wazuh, once, to create two read-only users (below).

GarnetOps reads two things, with **two separate users** so that each can be limited to what it
needs:

| Endpoint | Default port | What GarnetOps reads there |
| --- | --- | --- |
| Manager API | 55000 | its version, the list of agents, the permissions of its own user |
| Indexer | 9200 | counts and top lists of alerts, the latest file integrity events, vulnerability counts per agent, the roles of its own user |

## 1. Create the read-only user on the manager

The names are examples; use your own. In the Wazuh dashboard this is **Server management →
Security** (policies, roles, users). The same with the API, as an administrator (replace the
address, the token and the password; `ca.pem` is your Wazuh root certificate):

```sh
# 1. Log in as an administrator and keep the token in a variable.
TOKEN=$(curl --cacert ca.pem -s -u admin -X POST \
  "https://wazuh.example.lan:55000/security/user/authenticate?raw=true")

# 2. A policy that can only read agents.
curl --cacert ca.pem -s -X POST "https://wazuh.example.lan:55000/security/policies" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"garnetops_agents_read","policy":{"actions":["agent:read"],"resources":["agent:id:*","agent:group:*"],"effect":"allow"}}'

# 3. A role, and a user with a strong password of your own.
curl --cacert ca.pem -s -X POST "https://wazuh.example.lan:55000/security/roles" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"garnetops_reader"}'
curl --cacert ca.pem -s -X POST "https://wazuh.example.lan:55000/security/users" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"garnetops-api","password":"<A-STRONG-PASSWORD>"}'

# 4. Connect them: look up the ids (GET /security/policies, /security/roles, /security/users),
#    then link policy -> role -> user.
curl --cacert ca.pem -s -X POST \
  "https://wazuh.example.lan:55000/security/roles/<ROLE_ID>/policies?policy_ids=<POLICY_ID>" \
  -H "Authorization: Bearer $TOKEN"
curl --cacert ca.pem -s -X POST \
  "https://wazuh.example.lan:55000/security/users/<USER_ID>/roles?role_ids=<ROLE_ID>" \
  -H "Authorization: Bearer $TOKEN"
```

- `agent:read` on `agent:id:*` and `agent:group:*` is all GarnetOps needs: it lists agents and
  their groups. **Do not** give this user the built-in `administrator` role.
- GarnetOps never calls `/agents/{id}/key`, which returns an agent's registration key, and it
  never asks for `agent:read_secrets` or `cluster:read_secrets`. If you grant them anyway, the
  next sync warns you (see "Extra privileges").
- Do not use the built-in `wazuh` or `wazuh-wui` users; GarnetOps refuses `admin`, `wazuh` and
  `wazuh-wui` as the service user.

## 2. Create the read-only user on the indexer

The Wazuh indexer is OpenSearch-based. Create an internal user, a role that may only read the two
indices, and map the user to the role. As an indexer administrator (replace address and
passwords; the commands need a user that may use the security API):

```sh
# A role that can only read alerts and vulnerability states.
curl --cacert ca.pem -s -u admin -X PUT \
  "https://wazuh.example.lan:9200/_plugins/_security/api/roles/garnetops_read" \
  -H "Content-Type: application/json" \
  -d '{"cluster_permissions":[],"index_permissions":[{"index_patterns":["wazuh-alerts-*","wazuh-states-vulnerabilities-*"],"allowed_actions":["read"]}]}'

# The user.
curl --cacert ca.pem -s -u admin -X PUT \
  "https://wazuh.example.lan:9200/_plugins/_security/api/internalusers/garnetops-indexer" \
  -H "Content-Type: application/json" \
  -d '{"password":"<A-STRONG-PASSWORD>","description":"GarnetOps read-only"}'

# The mapping.
curl --cacert ca.pem -s -u admin -X PUT \
  "https://wazuh.example.lan:9200/_plugins/_security/api/rolesmapping/garnetops_read" \
  -H "Content-Type: application/json" \
  -d '{"users":["garnetops-indexer"]}'
```

- `read` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*` is everything the sync asks
  for. Wazuh's inventory indices (`wazuh-states-inventory-*`) are **not** in the role: GarnetOps
  does not read them in this version.
- Do not use `admin` or `kibanaserver`, and do not map the user to `all_access`.
- The `wazuh-alerts-*` index contains the log lines that triggered an alert. GarnetOps does not
  ask for them: it asks for counts and for six fields of file integrity events. The role is
  still the right place to limit what a stolen password could read.

## 3. Connect Wazuh in GarnetOps

**Settings → XDR / Wazuh → Connect Wazuh** (owners and admins, with a sign-in in the last 10
minutes). Enter a name, the address and the user for the manager API and for the indexer (HTTPS
only), and the two passwords. Optional: the address of your Wazuh dashboard (for the "Open Wazuh
dashboard" link) and the address your agents use to reach the manager (used by the enrollment helper,
below). The passwords are encrypted and never shown again; only the worker opens them.

The address must be one the worker can reach. Loopback, link-local and reserved addresses are
refused. Private addresses (RFC 1918) are allowed, because Wazuh normally runs inside your network.

### Trust the certificate

Wazuh installs its own certificates. Each of the two endpoints is trusted in one of two ways:

- **Pin the certificate (default).** GarnetOps connects once **without a user name or password**,
  shows the SHA-256 fingerprint, the subject, the issuer and the validity, and waits. Compare the
  fingerprint with the one on the Wazuh server, for example
  `openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout -fingerprint -sha256`, and
  confirm it. If the certificate ever changes, the sync **stops** and an admin sees both
  fingerprints; nothing is read until the new one is confirmed.
- **Upload your certificate authority** (PEM, one to five certificates, no key; the root
  certificate of your Wazuh installation). The server certificate must be signed by it and match
  the address you entered. A pasted private key is refused. The authority is public information
  and is stored as it is.

### Extra privileges

Right after connecting and on every sync GarnetOps reads the permissions of the two users
themselves. If a user can do more than read (for example the manager user may read agent keys or
write, or the indexer user holds the role `all_access`), the sync **does not run** until an
owner or admin has read the list and acknowledged it (with a sign-in in the last 10 minutes; it
is audited). Changing the password forgets the acknowledgement. GarnetOps cannot see what a
**custom** indexer role allows, only the names of the built-in powerful roles; that is why the
role above is spelled out.

## 4. What the page shows

- **Status**: the connection, the adapter (`wazuh4`, `wazuh5` preview), the Wazuh versions, when
  the last sync ran, and what could not be read. A button syncs now; otherwise it runs every 15
  minutes.
- **Alerts** for 24 hours, 7 days and 30 days: the total and the count per severity, each with
  the change against the period of the same length before. A period that could not be read keeps
  its earlier numbers and says when they were read.
- **Vulnerabilities on agents**: how many agents the indexer reports vulnerability states for, and
  the counts by severity.
- **MITRE ATT&CK tactics** in a table, top 20, and the **ten busiest agents**.
- **Latest alerts**: the newest attack and authentication-failure alerts as they arrive, a compact list of
  eight from the live feed ([attacks.md](attacks.md), section 4), with a line that says honestly whether it is live
  ("Live — last event 12 s ago"), waiting, paused or switched off. Description and agent name are text from the alert
  and are shown as plain text.
- **File integrity**: the latest 25 events (time, agent, event and path). The path is **text**,
  never a link, and control and direction-changing characters are removed.
- **Agents**: sortable, filterable (status, linked server) and searchable; on wider screens more
  columns (address, operating system, version, groups, last keep-alive, vulnerabilities).
- A link to your Wazuh dashboard for everything deeper. GarnetOps does not try to replace it.

### Severity

Wazuh rules have a level from 0 to 15. GarnetOps shows four steps:

| Wazuh level | Severity |
| --- | --- |
| 12 to 15 | critical |
| 9 to 11 | high |
| 6 to 8 | medium |
| 1 to 5 | low |

Level 0 never raises an alert. The same colours as everywhere in GarnetOps apply: a severity is
never decoration, and green is not used for anything here, because an agent that is merely online
proves nothing.

### What the sync reads

Manager API (`GET`, plus the one `POST` that logs in):

- `GET /` (the version), `GET /agents` with a fixed list of fields, in pages of 500, up to 5,000
  agents, and `GET /security/users/me/policies` (what the user may do).
- `POST /security/user/authenticate` to get a token. The token lives in the memory of the worker
  for the length of one sync and is never stored.

Indexer:

- `GET /`, `GET /_plugins/_security/authinfo` and `GET /_plugins/_security/api/permissionsinfo`
  (the version and the roles of the user itself).
- `POST …/_search` and `…/_count` on `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`,
  with queries built from fixed templates. The only input is the period (24h, 7d, 30d). They ask
  for counts by level, by MITRE tactic, by agent and by source address, 25 file integrity events
  and vulnerability counts per agent.

Every 30 seconds by default (15 to 300, per connection) the worker also asks the indexer for the **newest attack
alerts** with one more fixed template (the live feed, [ADR 0021](adr/0021-globe-view-and-live-attack-feed.md)):
one `POST …/wazuh-alerts-*/_search`, at most 50 alerts, oldest first, from the last alert it saw, at the rule level
you chose (7 and up by default), and only these fields: time, rule id, level, description and groups, agent id and
name, and the source address. It never reads `full_log`, the source port, the user name that was tried or any other
field. It runs only while the connection is switched on and healthy (both certificates confirmed and unchanged, extra
privileges acknowledged, one sync done), backs off on errors (up to ten minutes), and can be switched off under
Settings, Attack overview, Live feed. It needs no new permission: the indexer role in section 2 already reads
`wazuh-alerts-*`.

Any other method or path is refused inside GarnetOps **before** a connection is opened. Limits per
sync: 8 MB per answer, 200 requests, 5 minutes. A sync that cannot read one part (a role without
access to an index, a field Wazuh 5 renamed) keeps the earlier numbers of that part, says so in
the run, and carries on with the rest.

Source addresses of attack and authentication-failure alerts are collected (top 100 per period, with
first and last time and the agents they attacked) for the Attacks page ([attacks.md](attacks.md)).

## 5. Agents and servers

Every agent is listed on **Infrastructure → Servers → Wazuh** as a read-only row. There are two
ways to relate an agent to a server:

- **Show it as a server.** "Add as server" opens the usual add-server flow, prefilled with the
  agent's name and address. The new server is marked as coming from Wazuh and linked to the agent
  (`source: "wazuh"`, reference `<connection>:<agent id>`).
- **Link it to an existing server.** GarnetOps suggests a match when exactly one server has the
  same address, the same name, or the same short host name. A suggestion changes nothing: an
  admin confirms the link, it is audited, and it can be removed again. A server linked to an agent
  shows the agent's status and last keep-alive on its page.

Nothing is merged or overwritten: the server keeps its own inventory (agentless SSH or manual).
Reading Wazuh's own package inventory into the host inventory is planned (ROADMAP, Phase 4).

## 6. Summarise with AI (optional)

If you switched on AI (see [ai.md](ai.md)), the XDR page has a **Summarise with AI** button. It
sends the model **numbers only**: counts by severity and period, tactic names, agent counts. No
agent name, address, path, rule text or log line is sent, because all of that is written by
whoever can make a monitored machine log something. The call is made by the worker, rate limited
and audited (`ai.request`), the answer is labelled **AI suggestion**, shown as text through the
safe renderer (no HTML, no images), and changes nothing. Without AI the button is not there.

## 7. Enroll an agent (helper)

On the XDR page ("Enroll an agent") and in the add-server flow ("Monitor with Wazuh instead")
GarnetOps prints the **official Wazuh commands** to install an agent on a machine, filled in with
your manager's address:

1. Choose the operating system (Debian and Ubuntu, RHEL family, SUSE, Windows, macOS) and the
   architecture (amd64, arm64).
2. Optionally set an agent group and a name. Only letters, digits, dot, underscore and hyphen
   are accepted, and every value is quoted for the target shell.
3. Copy the commands, review them, and run them on the machine as an administrator.

Details:

- The commands pin the package version of **your** manager (an agent must not be newer than its
  manager) and come from the repository `packages.wazuh.com`, signed with Wazuh's key.
- If your manager asks for an enrollment password, tick the box. The command then contains the
  marked placeholder `<ENROLLMENT_PASSWORD>`. **GarnetOps never asks for, stores or prints a real
  password**; replace it on the machine.
- The address for `WAZUH_MANAGER` is the "address agents use" of the connection, or the manager
  address if that is not set. Set it if agents reach the manager under another name.
- The commands for Wazuh 5.x follow the documentation of the release candidates and are marked
  preview.
- GarnetOps does not run these commands, does not log in to the machine and does not install
  anything. Wazuh is GPL-2.0 free software by Wazuh Inc.; installing it is your decision and
  falls under its license, not GarnetOps' (the page says so).
- The command text comes from a versioned template (`packages/core/src/wazuh-enroll.ts`).

## Firewall and ports

| From | To | Port | Purpose |
| --- | --- | --- | --- |
| GarnetOps worker | Wazuh manager | 55000/tcp | REST API |
| GarnetOps worker | Wazuh indexer | 9200/tcp | alerts and vulnerability states |
| Wazuh agents | Wazuh manager | 1514/tcp, 1515/tcp | agent connection and enrollment (Wazuh, not GarnetOps) |

The worker is the only GarnetOps part that talks to Wazuh. In a default Compose install it can
reach your network; if you restrict the worker's outgoing traffic, allow these two ports to the
Wazuh hosts.

## Audit log

Everything security-relevant is in the audit log under **XDR**: connection created, changed or
removed, user or password changed (never the password), certificate authority uploaded or removed,
certificate check requested, confirmed or found changed, extra privileges detected or
acknowledged, agent linked or unlinked, sync started by hand, AI summary requested. Changes to the live feed
(on or off, interval, lowest rule level) and to the home location of the attack overview are under **Attacks**. The log never contains a password, a token or a certificate.

## Limits and what is not done yet

- One Wazuh connection per organisation in this version.
- Not tested against a real Wazuh installation; the 5.x field and index names are assumptions
  until 5.0 is generally available.
- No alert drill-down and no history of single alerts: the latest alerts are a window on the newest 50 (kept as
  the newest 500 per connection, and only as long as the retention period of the attack overview). Use the link
  to your Wazuh dashboard for everything deeper.
- Wazuh's package inventory in the host inventory is on the roadmap. The attack overview is
  described in [attacks.md](attacks.md).
- Windows and macOS command templates follow the Wazuh documentation but are not tested on those
  systems.
