# ADR 0046: Backup of the whole installation, restore in the setup

- Status: accepted (2026-11-05)

## Context

Users must always be able to take their data with them (AGENTS.md rule 2), and moving GarnetOps to another server should not
mean setting everything up again. A `pg_dump` (docs/updating.md) is not enough on its own: the stored secrets are sealed for the
vault key in the `vault` volume (ADR 0004), and the second factors and webhook secrets are encrypted with `BETTER_AUTH_SECRET`
from `.env`. Whoever restores only the database ends up with accounts nobody can sign in to and connections that do not work.

At the same time such a backup is the most valuable thing an attacker could take: every forge token, key and service password
of the installation. The design has to keep it that way only for the person who holds the passphrase.

## Decision

**What is in it.** One file holds every table of the installation except sign-in sessions, one-time tokens, rate-limit counters,
the backups themselves, the worker's heartbeat and the update sidecar's journal cursor; plus the vault's private key and the session
secret. Format (packages/core/src/backup.ts): an **age** file (passphrase recipient, scrypt work factor 2^18), inside gzip-compressed
lines of JSON: a manifest (version, the hashes of the applied migrations, the tables), the keys, then per table its rows as
PostgreSQL's `row_to_json` writes them, and an end line with the row count. age is an open, reviewed format: the file can be opened
without GarnetOps (`age -d … | gunzip`), so a backup does not depend on GarnetOps still existing. The library is typage
(age-encryption, BSD-3-Clause), the reference implementation in JavaScript.

**Who makes it.** Owners only, with a sign-in in the last ten minutes, at most three an hour, one at a time, and only while the
installation has exactly one organisation (a backup carries everything; with several organisations an owner of one would get the
others' data. When several organisations become possible, a backup of one organisation needs its own design). The passphrase must
have at least 16 characters.

**Where it is made.** In the worker, because only the worker holds the vault's private key; the API never sees it. The API seals the
passphrase and its own session secret for the worker (vault purpose `backup-request`, bound to the organisation and the row) and
queues a job with ids only. The worker reads the sealed request once and deletes it before it does anything else, in every outcome.
It reads all tables in one read-only, repeatable-read transaction (one consistent moment), compresses, encrypts and stores the file
in pieces in `backup_chunk`. The file is never on a disk outside the database, so no compose change is needed.

**Download.** For the owner who asked, for one hour after it is ready; then the worker deletes the file and keeps the row as the
record (size, SHA-256, row count, times). The download does not ask for another sign-in: asking did, and a slow build would
otherwise end in a second one. Asking and every download are audited; the first download tells every owner (event
`system.backup_created`, owners only).

**Restore.** Only on an installation without any account, in the setup (the setup token proves the person runs the server), in two
requests so the passphrase never travels in a URL or header and the file can stream: the first checks the token and keeps the
passphrase in the API's memory for ten minutes; the second sends the file as the body (up to `GARNETOPS_MAX_RESTORE_MB`, default
4096). The API decrypts while reading; a wrong passphrase fails before the database is touched. Then, in **one transaction**:
the tables are dropped, the migrations are applied again up to the backup's (its migration hashes must be the first of this
version's: an older backup is fine, a newer one is refused), the foreign keys are lifted, the rows go in with
`json_populate_recordset`, the foreign keys come back (checking every row), the sequences continue, the remaining migrations run,
every vault secret is opened with the old key and sealed for this installation's, the second factors and webhook secrets are
re-encrypted from the old session secret to this one, sessions are deleted and the restore is audited. Anything that fails rolls
everything back: the fresh installation stays as it was. The old keys exist only in the API's memory during this one request.

## Threat model

| Threat | Impact | Control |
| --- | --- | --- |
| The file is stolen | Every stored secret | age with scrypt (2^18) and a passphrase of at least 16 characters; the passphrase is never stored readable; the file is deleted after an hour |
| A member or admin takes a backup | Every secret of the installation | Owners only; recent sign-in; audited; every owner is told about a download |
| Someone else downloads an owner's backup | As above | Only the owner who asked can download it, only while signed in, only for an hour |
| The passphrase leaks from the server | As above | Sealed for the worker (only it can open it), deleted at once; never in a job, a log or an error |
| A compromised API reads the vault private key | Every secret, on every backup | The API never gets it: the worker builds the file. During a restore the API holds the *old* key of the backup, which it decrypted with the passphrase the person typed into it |
| Someone restores over a running installation | Data loss, takeover | Only while no account exists, only with the setup token, rate-limited, and in one transaction |
| A crafted or broken file | Injection, half a restore | age authenticates every 64 KiB piece and the end; table and column names are checked against a fixed shape and the catalogue; rows go through `json_populate_recordset`, never into SQL text; lines are capped at 64 MiB; any failure rolls back |
| A backup of a newer version | Data the code does not understand | Refused ("newer"); install that version first |

## Consequences

- An installation can be moved or rebuilt with one file and one passphrase; `.env` and the vault volume of the old server are no
  longer needed for it.
- A lost passphrase means the backup is lost; GarnetOps cannot help, by design.
- Passkeys are bound to the address; after a move to another address, people sign in with the authenticator app or a backup code
  and add the passkey again.
- The database briefly holds the encrypted file (about the size of the compressed data) until it is downloaded or expires.
- Queued jobs are not in a backup; scheduled work starts again on its own, a webhook registration that was pending fails after its
  sweep.
