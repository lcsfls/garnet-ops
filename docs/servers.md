# Servers

**Infrastructure → Servers** shows what runs on your Linux servers: the installed packages,
the known vulnerabilities among them and the pending updates. GarnetOps reads this over SSH
(ADR 0002, ADR 0011). **There is no agent**: nothing is installed that keeps running, and
nothing is written on the server except one account, one read-only script and one key line,
which a setup script prepares and can remove again.

Everyone in your organisation can read the list. Owners and admins add, remove and re-read
servers.

## What you need

- SSH (port 22 or another) reachable **from the GarnetOps worker** to the server, with
  public key authentication allowed.
- A Debian-family (Debian, Ubuntu), Red Hat-family (RHEL, Rocky, Alma, Fedora, Oracle, Amazon
  Linux) or Alpine system. Others are read as far as their package manager is supported
  (dpkg, rpm, apk); vulnerabilities are matched by grype and need a distribution it knows.
- Root on the server, once, to run the setup script.
- The vulnerability database that repository scans already use. Without it, packages are
  listed, but the run is marked failed with the reason, so a server never looks clean when it
  could not be checked.

## Adding a server

1. **Servers → Add server.** Enter the address (host name or IP address), optionally a name
   and the SSH port, and the **allowed source address**: the address GarnetOps connects
   from, **as the server sees it**. The access key works from there only. With the Compose
   stack the worker is behind Docker's network address translation, so this is the address
   of the machine running GarnetOps, not a container address. An IP address or a range
   (`192.0.2.10`, `192.0.2.0/24`, IPv6 too) is required; "any address" is refused.
2. **Prepare the server.** Run the setup script on it, as root. Three ways:
   - **One command**: GarnetOps creates a link that works once and for 60 minutes. The
     command downloads the script, checks its SHA-256 and only then runs it:
     `curl -fsSLo garnetops-host-setup.sh '<link>' && echo "<sha256>  garnetops-host-setup.sh" | sha256sum -c - && sudo sh garnetops-host-setup.sh`
   - **Download** the file, copy it to the server, `sudo sh garnetops-host-setup.sh`.
   - **Copy** the text of the script.
3. **Confirm the host key.** GarnetOps reads the server's SSH host key with `ssh-keyscan` and
   shows its fingerprint. The setup script prints the server's own fingerprints on the
   server's console; compare them, and confirm only if they match. Confirming needs a sign-in
   from the last ten minutes.
4. The **first inventory** runs. Packages and vulnerabilities appear on the server's page.

If your GarnetOps uses a certificate from its own CA (for example Caddy's internal CA when no
public certificate is available), `curl` does not trust it: add `--cacert <ca-file>` to the
command, or use Download or Copy script.

Many servers at once: **Import CSV**. One server per line: `address,name,port`; a header
line is optional (columns are found by the names `address` or `host`, `name`, `port`), comma
and semicolon both work, at most 500 rows. Every row is checked on its own: valid rows are
added, duplicates skipped, the rest listed with the reason. Run the setup script on each
server, then confirm the keys in the list.

## What the setup script does

Read it before you run it; it contains no secret. As root it:

1. creates the system account `garnetops` (password `*`; the shell is `/bin/sh` because sshd
   runs a forced command through it; nothing but the key below can log in);
2. installs `/usr/local/lib/garnetops/inventory`, owned by root. The wrapper ignores every
   request except the exact word `inventory`, then prints `/etc/os-release`, the kernel
   version, the architecture, the package lists (`dpkg-query`, `rpm -qa`, `apk list -I`) and
   the pending updates **from the local package cache** (`apt list --upgradable`,
   `dnf -C check-update` or `yum -C`, `apk version -l '<'`). It writes nothing, uses no
   network and needs no root;
3. writes `/var/lib/garnetops/.ssh/authorized_keys`, owned by root, with one line:
   `restrict,from="<allowed source>",command="/usr/local/lib/garnetops/inventory" ssh-ed25519 …`
   (no terminal, no forwarding, only that command, only from that address);
4. prints the SSH host key fingerprints of the server.

It stops if the wrapper's checksum is wrong, refuses to touch an existing `garnetops` account
whose home directory is somewhere else, and can run again at any time (it only changes what
differs). Run `sudo sh garnetops-host-setup.sh --uninstall` to remove the key, the wrapper
and the account.

If you restrict logins in `sshd` with `AllowUsers` or `AllowGroups`, add `garnetops`; the
script prints a note if it finds such a restriction.

## The host key

GarnetOps pins the host key on first contact, after you confirmed its fingerprint. Every
inventory checks the key strictly. If the server presents another key (reinstalled, or
someone intercepts the connection), the server turns **Host key changed**, **no inventory
runs**, and an admin must compare and confirm the new fingerprint (step-up, audit-logged
with the old and the new fingerprint).

## Inventory and vulnerabilities

- **Nightly**, at the time of the repository scans (Settings → Scanning), for every server
  with a confirmed host key; **on demand** with *Run inventory* (list menu or server page).
- An inventory takes at most 60 seconds and 16 MiB of output. The packages of the last
  successful run are the current list; every run is in the history.
- Packages are matched against the **same local vulnerability database** as repositories
  (grype), by distribution and source package. Findings are deduplicated per server,
  package and vulnerability; a finding that disappears is marked resolved. CVSS, EPSS, known
  exploited and fixed versions are shown as for repositories.
- Packages from third-party repositories (Surý, Remi, vendor repositories) do not follow
  your distribution's security data and can be matched less reliably.
- Pending updates come from the server's own package cache; GarnetOps never refreshes it. If
  the cache is old, so is the list. `apt` marks updates from a security repository.
- Every server that has been read gets a **grade from A to F** from its open vulnerabilities
  (worst one decides; display only, it changes no alert or setting). A server that has not been
  read yet has no grade. See [grades.md](grades.md).

## Network and firewall

Connections come from the worker only. In the Compose stack the worker is on the `egress`
network; restrict that network to the SSH ports of your server networks. On the servers,
allow SSH from the allowed source address only. **Jump hosts are not supported yet**: the
worker must reach every server directly (NetBird addresses are planned).

GarnetOps refuses to connect to loopback, link-local (including cloud metadata addresses),
unspecified and multicast addresses; a host name is resolved by the worker, and the address
that was checked is the address it connects to.

## What can go wrong

| Message | What to do |
| --- | --- |
| The server could not be reached | Check address, port, routing and firewall from the worker. |
| No SSH host key could be read | Same, and that the port speaks SSH. |
| The server refused the access key | Run the setup script again; check the allowed source address (the address the server sees) and `sshd` (`AllowUsers`, `PubkeyAuthentication`). |
| The server's host key changed | Compare the fingerprint with the server, then confirm it. |
| The server did not run the inventory command | The wrapper is missing or changed: run the setup script again. |
| The server offers no secure SSH key exchange | The server's SSH is too old; GarnetOps accepts only the key exchanges of ADR 0004. |
| The operating system is not recognised | The packages are listed, but vulnerabilities cannot be matched. |
| The vulnerability scanner failed | Install or import the vulnerability database. |

## Security notes

- The access key's private half is generated by the worker, sealed in the vault, never shown
  and never leaves the platform; it is on disk for the seconds an inventory runs (a tmpfs in
  the Compose stack). One key per organisation; **rotation is planned**.
- A stolen key is useless from any other address, and from the allowed one it can only run
  the read-only wrapper.
- The output of a server is untrusted: it is parsed strictly, bounded, stored as text, and
  never executed or put into an error message.
- Every change is in the audit log (filter *Servers*): servers added, imported and removed,
  host keys confirmed and changed, inventories requested, setup scripts and links created
  and downloaded.
- Nothing leaves your network: no telemetry, no data to third parties.

## Servers from Proxmox

On **Servers → Proxmox**, a guest of a connected Proxmox VE cluster becomes a server with
**Add as server**: the wizard starts with the guest's name and address and the new server is
linked to the guest (`source` Proxmox). Everything else is as above and happens on the guest
itself; GarnetOps never runs anything on the Proxmox node. See [proxmox.md](proxmox.md).

## API

`/api/v1/hosts` (see ADR 0011): list, counts, detail, add, import, delete, host key confirm
and re-scan, inventory, packages, findings and runs of a server, the access key, the setup
script and one-time links; `/api/v1/host-setup/<token>` is the public one-time download.
