# Proxmox VE

**Infrastructure → Servers → Proxmox** shows your Proxmox VE clusters next to your servers:
every node, virtual machine and container with status, resources, uptime, operating system
type, backups, snapshots, high-availability state and the node's own pending updates. It tells
you which guests are stale (stopped for months, no recent backup, an old snapshot) and which
running guests GarnetOps does not know as servers yet (ADR 0012).

**GarnetOps only reads.** It sends `GET` requests to a short list of Proxmox endpoints and
nothing else. It never starts, stops, migrates, snapshots or changes anything, never opens a
console, never runs a command in a guest and never logs in to a node. No Proxmox code or
library is part of GarnetOps; it talks to the REST API over HTTPS.

Everyone in your organisation can see the inventory. Owners and admins connect and manage
clusters under **Settings → Proxmox**.

## What you need

- Proxmox VE 8 or 9 (the REST API on port 8006 of at least one node).
- Network access **from the GarnetOps worker to port 8006 of the nodes** (see Firewall below).
- Someone with administrator rights on Proxmox, once, to create a user and a token.

## 1. Create a read-only token on Proxmox

Open a shell on one Proxmox node as an administrator (the shell in the Proxmox web interface
is fine) and run the following. The names are examples; use your own. The same commands are
shown, with a copy button, in the "Add connection" dialog.

```sh
pveum user add garnetops@pve --comment "GarnetOps read-only inventory"
pveum acl modify / --users garnetops@pve --roles PVEAuditor
pveum user token add garnetops@pve inventory --privsep 1
pveum acl modify / --tokens 'garnetops@pve!inventory' --roles PVEAuditor
```

- The first command creates a **dedicated user** in the Proxmox realm `pve`. It has no
  password and cannot sign in.
- The role `PVEAuditor` only has `*.Audit` privileges (`Sys.Audit`, `VM.Audit`,
  `Datastore.Audit`, `Pool.Audit`, `SDN.Audit`, …): it can look, not change.
- `--privsep 1` switches **privilege separation on**: the token has only the privileges of its
  own ACL (the fourth command), never more than the user. With privilege separation off, the
  token inherits everything the user can do.
- The third command prints the **token secret** (a UUID) **once**. Copy it into GarnetOps
  right away. The token ID is `garnetops@pve!inventory`.

**Never use `root@pam`, an administrator or a password.** GarnetOps does not ask for one and
refuses tokens of `root`.

## 2. Connect the cluster

**Settings → Proxmox → Add connection.**

1. Enter a name, the **API address** (`https://pve1.example.lan:8006`, https only; the port is
   8006 unless you give another; any one node of the cluster is enough), the **token ID**
   and the **token secret**. The secret is sealed in the vault at once; GarnetOps never shows
   it again, and only the worker can open it. Adding a connection needs a sign-in from the
   last ten minutes.
2. **Confirm the certificate.** Proxmox usually has a self-signed certificate, so GarnetOps
   cannot ask a certificate authority whether it is genuine. Instead it reads the certificate
   the node presents (**without sending the token**), and shows its SHA-256 fingerprint,
   subject, issuer and validity. Compare the fingerprint with the node: run `pvenode cert
   info` there, or open *Datacenter → node → System → Certificates* in the Proxmox web
   interface. Confirm only if they match. Confirming needs a recent sign-in and is audited.
3. The **first sync** starts. If the token can do more than read (below), you are asked to
   acknowledge it first.

From then on every request must present exactly the confirmed certificate.

### The certificate changed

If the node presents another certificate (a new installation, a renewed certificate, or
someone intercepting the connection), the connection turns **Certificate changed**, **no
request is sent, the token included**, and no sync runs. GarnetOps looks at the certificate again
every 15 minutes (a handshake only); if the pinned one is back, the warning clears itself.
Otherwise an admin compares the new fingerprint and confirms it (both certificates are
shown; step-up, audited with the previous fingerprint).

If you use a certificate that is **renewed often** (for example from an ACME client every
60 to 90 days), you have to confirm it each time. Proxmox's own certificate (valid for years),
or a certificate with a long validity, avoids that.

### A token that can do more than read

At the start of every sync GarnetOps reads the token's own permissions
(`GET /access/permissions`). If the token has any privilege that is not an audit privilege,
GarnetOps shows a clear warning with the list, **does not sync, and has asked Proxmox nothing
but the version and these permissions**, until an admin acknowledges exactly those privileges
(step-up, audited). A better fix is on the Proxmox side: give the user and the token only
`PVEAuditor` (`pveum acl delete …`, or create a new token) and use **Check again**. A token
whose privileges grow later blocks the sync again.

Even then GarnetOps sends only read requests. The warning is about what **someone else** could
do with a stolen token.

## What is read

| Endpoint (all `GET`) | For |
| --- | --- |
| `/version` | Proxmox VE version |
| `/access/permissions` | the token's own privileges (the only thing read under `/access`) |
| `/cluster/status` | cluster name, quorum, node states |
| `/cluster/resources` | nodes, VMs, containers and storage with usage |
| `/cluster/ha/resources` | high-availability state of guests |
| `/cluster/backup` | which guests an enabled backup job includes |
| `/nodes/{node}/status` | node usage, Proxmox VE version, kernel |
| `/nodes/{node}/apt/update` | the packages the node's own cache lists as upgradable |
| `/nodes/{node}/storage/{storage}/content?content=backup` | the newest backup of each guest (needs the right to list the storage; refused is fine) |
| `/nodes/{node}/{qemu\|lxc}/{vmid}/config` | OS type, template flag, guest agent switch, static addresses |
| `/nodes/{node}/{qemu\|lxc}/{vmid}/snapshot` | number and age of snapshots |
| `/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` | addresses, for running guests whose agent is switched on |
| `/nodes/{node}/lxc/{vmid}/interfaces` | addresses of running containers |

Pending node updates come from the node's own package cache. GarnetOps **never** refreshes it
(that would be a `POST` to `apt/update`), so the list is as old as the node's last `apt update`.

A refused or missing endpoint (the token may not list backups, the guest agent is not running,
a node is offline) does not fail the sync. The sync says what it could not read; backups that
cannot be listed switch off the "no recent backup" flag for that connection instead of
flagging every guest.

## What never happens

- No `POST`, `PUT`, `DELETE` or `PATCH`; no path outside the list above. The client refuses
  them before it opens a connection (tested).
- No console, terminal or VNC; no `agent/exec`, `qm guest exec` or `pct exec`; no SSH to a node.
- No guest descriptions, snapshot descriptions, notes, cloud-init data or SSH keys are read.
- No redirects are followed; no answer above 8 MiB is accepted; the token is not sent to a
  server whose certificate you did not confirm.
- Nothing is sent anywhere else: no telemetry, no data to third parties.

## The Proxmox view

- **Cluster cards**: version, nodes online, guests (running of all), stale guests,
  untracked guests, nodes with updates, last sync, the state of the certificate and token.
- **Nodes**: status, CPU, memory, disk, uptime (wide), version and kernel (wide), guests and
  pending updates with the count. Sort by any column. An offline node shows no figures.
- **Storage**: capacity as Proxmox reports it.
- **Guests**: sortable by name, node, status, CPU, memory, disk, uptime, last backup and oldest
  snapshot; filter by flag, type, status, node, cluster and text (name, ID, address, system,
  tag). More columns appear on wide and very wide screens. Click a guest for a detail dialog.

### Stale and untracked

| Flag | Meaning | Threshold |
| --- | --- | --- |
| Stopped for long | status `stopped` for more than | **30 days** |
| No recent backup | no backup newer than (or none at all) | **7 days** |
| Old snapshot | the oldest snapshot is older than | **30 days** |
| Untracked | running, not a template, and no server in GarnetOps is linked to it | – |

- Proxmox does not say since when a guest is stopped. GarnetOps counts from the moment it
  **first saw** the guest stopped, so a guest that was already stopped when you connected the
  cluster can be flagged 30 days after that, not earlier.
- "No recent backup" needs the right to list backup storage. If any backup storage cannot be
  listed, the flag is off for that connection and the connection says so.
- Templates are never flagged.
- The thresholds are fixed in this version (`packages/core/src/proxmox-flags.ts`).

## Guests become servers

On a guest row (or in its dialog), **Add as server** opens the usual add-server wizard with
the guest's name and its first known address filled in. It then works exactly like any other
server (see [servers.md](servers.md)): the setup script is run **on the guest**, the SSH host
key is confirmed, and GarnetOps reads the package inventory over SSH. **Nothing is ever run
through Proxmox**, and no access to the node is needed. A server created this way is linked to
the guest: the guest shows "Server: name", and the server shows a "VM 100" link back to the
guest. The link is the guest's cluster ID and VM ID (`host.source_ref`); removing the server
or the connection does not delete the other.

Addresses are known from the QEMU guest agent, the container's interfaces or a static address
in the guest's configuration. A guest on DHCP without a guest agent has none: enter its
address in the wizard. Guests that already have a server added by hand are not linked
automatically; remove the server and add it from the guest, or leave them as they are.

## Sync

A sync runs **every 15 minutes** for every enabled connection with a confirmed certificate,
and on request (**Sync now**). It is sequential (one request at a time, with a short pause),
bounded (10 minutes, 6000 requests, 8 MiB per answer, 2000 guests per connection) and stops
when Proxmox stops answering. The cost is roughly two requests per guest and a handful per
node per cycle. You can switch a connection's sync off under Settings → Proxmox. Syncs and
their warnings are in the connection's history.

A failure shows as a short message on the connection (token rejected, certificate changed,
the token may not read the inventory, …). What Proxmox sent is never shown in a message.

## Firewall

Connections come from the **worker only**. Allow **GarnetOps worker → each Proxmox node, TCP
8006**. In the Compose stack the worker is on the `egress` network; restrict that network to
port 8006 of your Proxmox nodes (and port 22 of your servers). On Proxmox, nothing needs to
reach GarnetOps. GarnetOps refuses to connect to loopback, link-local (including cloud
metadata), unspecified and multicast addresses; a host name is resolved by the worker, and the
address that was checked is the address it connects to.

## What can go wrong

| Message | What to do |
| --- | --- |
| The Proxmox server could not be reached | Check address, port 8006, routing and firewall from the worker. |
| The TLS connection failed | The node does not speak TLS 1.2 or newer on that port, or the port is not Proxmox. |
| The certificate is not confirmed yet / changed | Compare the fingerprint on the node, then confirm it. |
| Proxmox rejected the API token | Check the token ID (`user@realm!tokenid`) and the secret; the token may have been deleted or expired. |
| The token may not read the inventory | Give both the user and the token the role `PVEAuditor` on `/`. With privilege separation on, the token needs its own ACL. |
| The token can do more than read | Remove the extra roles on Proxmox and check again, or acknowledge. |
| The server did not answer like Proxmox VE | The address is not a Proxmox API (a proxy page, another product). |
| A Proxmox answer is larger than the limit | A very large cluster or a hostile server; the log of the worker has details. |
| The sync took longer than 10 minutes | Slow or overloaded Proxmox API; try again later. |

## Security notes

- The token's secret is sealed (envelope encryption, ADR 0004) and bound to your organisation
  and the connection. Only the worker holds the key to open it.
- A stolen token can read the inventory (audit privileges) and nothing more, if you created it
  as described. You can revoke it on Proxmox at any time; the sync then fails with "token rejected".
- Everything an admin does is in the audit log (filter Proxmox): connections added, changed
  and removed, certificates looked at, confirmed and changed, privileges detected and
  acknowledged, syncs requested.
- Names, tags and addresses from Proxmox are untrusted input: parsed strictly, bounded, stored
  as text and shown escaped.

## API

`/api/v1/proxmox` (see ADR 0012): `clusters` (list, add, change, remove), `clusters/:id/certificate/scan`,
`clusters/:id/certificate/confirm`, `clusters/:id/privileges/acknowledge`, `clusters/:id/sync`,
`clusters/:id/runs`, `nodes`, `storage`, `guests` (keyset pagination, sort, filters),
`guests/counts` and `guests/:id`. Everyone in the organisation reads; owners and admins change.
`POST /api/v1/hosts` accepts `source: "proxmox"` and `sourceRef: "<cluster id>:<vmid>"`.
