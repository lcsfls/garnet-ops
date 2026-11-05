# Backup and restore

GarnetOps can make a backup of the whole installation in one encrypted file, and restore it on a new installation, for example
when you move to another server ([ADR 0046](adr/0046-backup-and-restore.md)).

## What is in a backup

Everything: organisations, accounts and their second factors, repositories, scans, findings, gates, hosts, websites, settings,
notification channels, the audit log, and every stored access secret (forge tokens, deploy keys, passwords and keys of services).
Left out are sign-in sessions (everyone signs in again), one-time tokens, rate-limit counters and the backups themselves.

The file is protected by your passphrase alone. Keep it apart from the file, and keep the file where only you can reach it.

## Make a backup

**Settings → Backup** (owners only):

1. Enter a passphrase of at least 16 characters twice. A few unrelated words are easy to type and hard to guess.
2. **Create backup.** If you have not signed in during the last ten minutes, GarnetOps asks you to confirm it is you.
3. The worker makes the backup; the list shows it as **Ready** with its size and SHA-256 after a moment.
4. **Download.** The file is called `garnetops-backup-YYYY-MM-DD.age`. It can be downloaded for one hour by the owner who asked;
   then it is deleted from GarnetOps.

Every request and download is in the audit log, and every owner gets a notification when a backup is downloaded. At most three
backups an hour can be made, one at a time. Backups are only possible on an installation with one organisation.

## Restore

1. Install GarnetOps on the new server ([installation](installation.md)), the same version as the backup or a newer one.
2. Open it. On the first start it asks: **Set up a new installation** or **Restore from a backup**. Choose the restore.
3. Enter the setup token (printed in the API's log), choose the backup file and enter its passphrase. **Restore.**

The restore runs in one step: if anything does not fit, nothing is changed and the installation stays empty. After it, everyone
signs in with their account and second factor as before. Passkeys only work if GarnetOps has the same address as before;
otherwise sign in with the authenticator app or a backup code and add the passkey again.

The largest file a restore accepts is set with `GARNETOPS_MAX_RESTORE_MB` in `.env` (default 4096).

What the restore does: the stored secrets are moved to the new installation's vault key, and the second factors and webhook
secrets to its session secret, so neither the old `.env` nor the old `vault` volume is needed.

## Open the file without GarnetOps

The file is an [age](https://age-encryption.org) file with a passphrase. Inside are gzip-compressed lines of JSON: a manifest, the
keys, then each table's rows. With the age tools:

```sh
age -d garnetops-backup-2026-11-05.age | gunzip | head -1
```

## API

For owners, with a session: `GET /api/v1/backup` (the last ten), `POST /api/v1/backup` with `{ "passphrase": "…" }` (recent
sign-in; 202 with the id), `GET /api/v1/backup/{id}`, `GET /api/v1/backup/{id}/download`.

Restore, before the first account exists: `POST /api/v1/setup/restore` with `{ "token", "passphrase" }` returns an id;
`PUT /api/v1/setup/restore/{id}` with the file as the body (`application/octet-stream`).
