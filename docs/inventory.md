# Inventory

**Infrastructure → Inventory** is a list of systems and the software on them, as you or a script tell GarnetOps (ADR 0053). It
is for everything no scan reaches: shared hosting, appliances, a customer's server without an agent, a switch. It answers one
question quickly: where do we run this, and in which version?

It is a list, not a scan:

- GarnetOps **never connects** to an entry, resolves its name or checks it. That is why an entry needs no proof of control (no
  DNS record as for [websites](websites.md)).
- The software is **not checked** against the vulnerability database. A typed "nginx 1.26" cannot be matched reliably to a
  distribution's package. The page says so wherever inventory software is shown. For checked results use the agent
  ([hosts.md](hosts.md)) or a repository scan.

The inventory is always there; it is not a module.

## A system

| Field | Meaning |
| --- | --- |
| **Name** | What people call it. |
| **Key** | The stable name a script addresses the system by, for example its host name. Unique in the organisation. Letters, digits, dot, dash, underscore and colon, at most 120 characters. For a system added by hand the key follows the name until you type one. |
| **Kind** | Server, virtual machine, container, website, network device, appliance, workstation or other. |
| **Environment**, **Tags**, **Notes** | Free text to filter by and to remember things. |
| **Software** | Each a name and a version. In the app: one per line, the name and then the version (`nginx 1.26.0`). |

Everyone in the organisation reads the inventory. Members and above add, change and remove systems; viewers read. At most 5,000
systems, and 5,000 pieces of software per system.

Filter the list by kind, by who entered a system (by hand or a script), and by part of a name, key, tag or software name. The
filters are in the address, so a filtered list can be shared. **Export** downloads the list as filtered (CSV, Excel, PDF or
text), one row per system and piece of software.

## Where does it run?

The second view searches a software name across everything GarnetOps knows:

- the **inventory** (not checked),
- the packages of **hosts** with the agent and the images of running **containers** (while the Agents module is on),
- the packages of the **repositories** you may see.

Each row says where it is known from and whether it was checked by scans. Type at least two characters.

## Filling and reading it with a script

Owners and admins create **inventory tokens** on the page (a recent sign-in is asked for). A token is shown once; GarnetOps
keeps only a hash of it. A token has one scope:

| Scope | May | May not |
| --- | --- | --- |
| **Write** | report a system (`PUT`) and remove one (`DELETE`) | read anything |
| **Read** | read the inventory (`GET`) | change anything |

So the token on a reporting server cannot read the list of all your other systems. A token reaches nothing else in GarnetOps.
Keep it out of scripts in a repository: read it from the environment or from a file only root can read. Revoke a token on the
page; it stops working at once. 120 requests a minute per token, 1 MB per request.

### Report a system

`PUT /api/v1/inventory-feed/systems/{key}` creates the system when the key is new. Otherwise it replaces the software list and
sets the fields that were sent; what was not sent stays (notes and tags kept by hand survive the next report).

```sh
curl -fsS -X PUT "https://garnetops.example.com/api/v1/inventory-feed/systems/web-1.example.lan" \
  -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Web server 1","kind":"server","environment":"production",
       "software":[{"name":"nginx","version":"1.26.0"},{"name":"php","version":"8.3.12"}]}'
```

| Field | |
| --- | --- |
| `software` | Required. A list of `{"name": …, "version": …}`; the version may be left out. It replaces the stored list. |
| `name`, `kind`, `environment`, `notes`, `tags` | Optional. `kind` is one of `server`, `vm`, `container`, `website`, `network`, `appliance`, `workstation`, `other`. A new system without a name is named after its key. |

The answer is `201` for a new system and `200` for a known one: `{"key": "…", "created": true, "software": 2}`.

Every package of a Debian or Ubuntu server, from cron (needs `jq`):

```sh
#!/bin/sh
set -eu
dpkg-query -W -f '${Package}\t${Version}\n' \
  | jq -Rn '{kind: "server", software: [inputs | split("\t") | {name: .[0], version: .[1]}]}' \
  | curl -fsS -X PUT "https://garnetops.example.com/api/v1/inventory-feed/systems/$(hostname -f)" \
      -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN" \
      -H "Content-Type: application/json" --data-binary @-
```

On RPM systems use `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'` in place of `dpkg-query`.

### Remove a system

```sh
curl -fsS -X DELETE "https://garnetops.example.com/api/v1/inventory-feed/systems/web-1.example.lan" \
  -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN"
```

### Read the inventory

`GET /api/v1/inventory-feed/systems` with a read token answers `{"systems": [...]}`: every system by key with its fields and its
whole software list.

```sh
# Every system that lists php, with the version
curl -fsS "https://garnetops.example.com/api/v1/inventory-feed/systems" \
  -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN" \
  | jq -r '.systems[] | . as $s | .software[] | select(.name == "php") | "\($s.key)\t\(.version)"'
```

### Answers

| Status | Meaning |
| --- | --- |
| `401` | No token, or one that is unknown or revoked. |
| `403` | The token has the other scope. |
| `404` | No system with this key (or a key that is not valid). |
| `409` | The inventory is full. |
| `422` | The body is not valid, for example more than 5,000 pieces of software. Nothing was stored. |
| `429` | More than 120 requests in a minute. |

## Audit log

Recorded: a token created or revoked, a system added, changed or removed in the app, a system added or removed by a script
(with the token's first characters), and each export. A script's routine report of a known system is not recorded: a nightly
report of every server would bury the log. The page shows when each token was last used.

## Session API

The page uses `GET /api/v1/inventory` (`q`, `kind`, `source`, `cursor`, `pageSize`), `GET /api/v1/inventory/{id}`,
`POST /api/v1/inventory`, `PUT` and `DELETE /api/v1/inventory/{id}`, `GET /api/v1/inventory/software?q=`,
`GET /api/v1/inventory/export` and `GET`, `POST`, `DELETE /api/v1/inventory/tokens`.
