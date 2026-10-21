# ADR 0004: SSH key vault, NetBird networks and Linux firewall monitoring

- Status: accepted
- Date: 2026-10-19
- Decided by: maintainer
- Extends: ADR 0002

## Context

GarnetOps reads package inventories and firewall rules from Linux servers over
SSH. The keys that grant this access are among the most sensitive secrets in
the product. Many customers connect their servers through NetBird (WireGuard
mesh); the platform should use that network instead of exposing SSH to wider
networks.

## Decision

### 1. Key generation and storage

- Keys are **generated inside GarnetOps** (Ed25519) per organisation and,
  optionally, per server group. Customers never upload private keys.
- The **private key never leaves the platform**: no download, no display, no
  export via API. Only the public key and its fingerprint are shown.
- **Envelope encryption at rest:**
  - Each secret gets a fresh 256-bit data key; the secret is sealed with
    AES-256-GCM and a random 96-bit nonce.
  - The data key is wrapped for the **vault key**, a hybrid key pair of
    X25519 and ML-KEM-1024: an ephemeral X25519 key agreement and an ML-KEM
    encapsulation, both shared secrets combined with HKDF-SHA-256, then
    AES-256-GCM (see the amendment below). Anyone with the vault public key
    can seal; only the holder of the vault private key can open.
  - Additional authenticated data binds every ciphertext to its organisation
    ID, record ID and purpose (`ssh-private-key`, `forge-token`, …), so a
    ciphertext copied to another row or tenant fails to decrypt.
  - The vault private key is read from a file (`GARNETOPS_VAULT_KEY_FILE`,
    mode 0400, mounted only into the worker) or an external KMS later. It is
    never stored in the database, never logged and never sent to the web app.
    The public key is configured for the API.
  - Records store a vault key ID so the key can be rotated: new secrets use the
    new key, a background job re-wraps existing data keys.
- **Split privileges:** the API seals secrets with the vault public key; only
  the worker holds the vault private key and can decrypt.
  Decrypted keys live only in worker memory for the duration of a connection;
  buffers are zeroed afterwards.
- **Rotation:** "Rotate key" creates a new key, shows the new
  `authorized_keys` line, verifies that the new key works on each host, and
  only then retires the old key. Hosts that still accept only the old key are
  listed.
- Every key action (create, rotate, retire, use per host) is written to the
  audit log.

### 2. Installing the key on a server

The platform shows a ready-made, reviewable setup for each host. We never pipe
remote scripts into a shell.

1. Create a dedicated, unprivileged user (default `garnetops-scan`, no
   password, no login shell other than the wrapper).
2. Add one `authorized_keys` line, restricted with `from="<platform address>"`,
   `restrict` (no PTY, no forwarding) and `command="/usr/local/lib/garnetops/wrapper"`.
3. Install the wrapper script (shown in full, with its SHA-256). It reads
   `SSH_ORIGINAL_COMMAND` and runs only commands from a fixed allowlist.
4. Optional, for firewall monitoring: a sudoers drop-in that allows exactly
   the read-only firewall commands (section 4) with fixed arguments, nothing
   else.
5. Confirm the host key fingerprint on first connection (trust on first use
   with explicit confirmation). A later change blocks scanning until an admin
   confirms it again.

### 3. NetBird

- Optional integration with the NetBird Management API using a
  customer-provided access token, stored in the vault like any other secret.
- GarnetOps lists NetBird peers (name, NetBird IP, OS, groups, connection
  status) so admins can add servers from that list instead of typing
  addresses.
- When a host is added via NetBird, GarnetOps connects only to its NetBird
  address, and the `from=` restriction uses the platform's own NetBird address.
  SSH on those servers can then be limited to the NetBird interface.
- GarnetOps does not change NetBird configuration (no ACL writes) in this
  phase; it only reads. A later phase may suggest access-control policies.
- Works with NetBird Cloud and self-hosted management; the base URL is
  configurable.

### 4. Linux firewall monitoring (read-only)

Commands in the wrapper allowlist, chosen per detected firewall:

| Firewall | Command |
|---|---|
| nftables | `nft --json list ruleset` |
| iptables / ip6tables (legacy or nft backend) | `iptables-save`, `ip6tables-save` |
| ufw | `ufw status verbose` |
| firewalld | `firewall-cmd --list-all-zones` |
| Listening sockets | `ss -H -tuln` (no root needed) |

Reading rules requires root on most distributions, hence the sudoers drop-in
with exact command lines. GarnetOps then:

- stores a normalised snapshot per scan and shows **drift** (rule added,
  removed or changed) with a diff;
- flags risky states: firewall inactive, default input policy `ACCEPT`,
  SSH or database ports open to `0.0.0.0/0` or `::/0`, listening services not
  covered by any rule, IPv6 left open while IPv4 is filtered;
- compares listening ports with the firewall exposure;
- lets admins accept a finding with a reason (audit log) or mark a snapshot as
  the approved baseline.

GarnetOps never writes firewall rules. Suggested changes are shown as
commands for a human to review and run.

## Amendment 2026-10-21: post-quantum vault

Decided by the maintainer, prompted by the BSI's guidance on post-quantum
cryptography. Sealed secrets live in the database for years; anyone who copies
a dump today could open X25519-only ciphertexts once a large quantum computer
exists ("store now, decrypt later"). The vault format therefore moves to
version 2 before the first release:

- The vault key consists of an X25519 key **and** an ML-KEM-1024 key (FIPS 203).
  Key files hold both as PEM blocks; a file with only one of them is refused.
- Wrapping key = HKDF-SHA-256 over both shared secrets (ML-KEM first), with a
  salt that hashes the ephemeral X25519 key, the ML-KEM ciphertext and both
  recipient public keys. It stays secret as long as either algorithm holds.
- The key ID is derived from both public keys.
- Version 1 (X25519 only) is removed without a migration: it never shipped.
  Development keys are replaced by `scripts/dev.mjs` automatically.
- Not covered here and tracked separately: post-quantum key exchange for SSH
  (`mlkem768x25519-sha256`) and TLS (X25519MLKEM768), and a check of the
  parameters against BSI TR-02102-1 before the first release.

## Amendment 2026-10-21: repository deploy keys (accepted)

Repositories cloned over SSH get a deploy key generated by GarnetOps. Two
points differ from section 1; the maintainer accepted both on 2026-10-21:

1. **The API generates the deploy key**, not the worker. It seals the private
   half with the vault public key in the same request and keeps only the
   public half. The API already sees forge tokens in plaintext for the same
   moment, so the exposure is the same; asking the worker would make adding a
   repository asynchronous. JavaScript strings cannot be zeroed, so the key
   stays in API memory until garbage collection. Server keys (section 1) are
   still to be generated by the worker as decided.
2. **The decrypted key is written to a file for the clone**, because ssh(1)
   reads keys from files or an agent, not from memory. The file lies in the
   scan's private directory (0700, file 0600), is removed as soon as git
   exits and the whole directory is removed after the scan. In the Compose
   stack the work directory will be a tmpfs, so the key never reaches a disk.
   An alternative is a per-clone ssh-agent fed through stdin; it adds a
   process and a socket per clone and is not portable to the development
   setup on Windows.

Further decisions in this amendment:

- **Ed25519** for deploy keys. SSH has no post-quantum signature that forges
  support; authentication is not exposed to "store now, decrypt later". The
  session is: the worker offers `mlkem768x25519-sha256` and
  `sntrup761x25519-sha512` first, then only the classical exchanges BSI
  TR-02102-4 accepts (curve25519, NIST P-curves, DH groups 14 to 18 with
  SHA-2). Only names the installed ssh client supports are offered.
- **Host keys: trust on first use, then pinned.** The first contact records
  the server's host key (also when authentication fails, because the key is
  not on the forge yet); every later clone requires exactly that key. Only
  plain known_hosts entries are stored. The fingerprint is shown so users can
  compare it with the one their forge publishes. Owners and admins can forget
  a pinned key; that is audit-logged with the old fingerprints. A first
  contact through an attacker is the known weakness of TOFU; entering the
  expected fingerprint up front is on the roadmap.
- ssh runs with `-F none`, `BatchMode`, `IdentitiesOnly`, no agent, no
  forwarding, no proxy jump, no local commands and no host key updates.

## Consequences

- A database dump alone never reveals SSH keys or tokens.
- Losing the vault private key means losing access to stored secrets;
  installation docs must cover its backup separately from the database backup.
- SSH keys are generated by the worker (it needs the private key anyway); the
  API asks the worker to create a key and receives only the public half.
- The sudoers drop-in is a deliberate, narrowly scoped privilege; it is
  optional and only needed for firewall monitoring.
- NetBird is an integration, not a requirement: hosts on plain networks work
  the same way with their regular address.
