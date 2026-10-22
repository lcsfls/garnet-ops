# Your account

Open the account page from the round avatar at the top right: **Account settings**. It is yours alone; nobody
else can change anything here, and it is the same for every role. The sections are on the left, like Settings
(above the form on a narrow window), and the section is part of the address, so a link opens it directly.

The design decisions and the threat model are in [ADR 0017](adr/0017-account-settings-and-passkeys.md); the
Notifications section is [ADR 0019](adr/0019-in-app-notifications-toasts-and-personal-preferences.md).

## Profile

- **Display name:** shown to your team and in the audit log.
- **Email address:** shown, not editable. It is the address you sign in with. Changing it is not supported yet.
- **Language and time zone** are saved on your account, so they follow you to every browser. The language is the
  one of the menu (English or German). The time zone decides how times are shown (audit log, scans, updates);
  "Automatic" follows the browser. Schedules such as the nightly scan keep the zone they were set with, and the
  day-based figures of the charts and exports still follow the browser's zone.
- **Directory accounts** (you sign in with your LDAP or Active Directory account, [docs/ldap.md](ldap.md)): the
  display name comes from the directory and is updated at every sign-in, so it is read-only here.

## Password

If you sign in with your directory account, this page only says so: the password belongs to the directory and
GarnetOps never stores it. Everything below is for local accounts.

Changing it needs a sign-in from the last ten minutes ("Confirm it is you" asks if it is older) and the current
password. Enter both and a new one (at least 12 characters; a passphrase of several words works well, and
a password manager is better still). By default every **other** session is signed out, which is what you want
if someone else may have known the old password; untick the box to keep them. After five attempts in a minute you
are asked to wait.

## Authenticator app

The six-digit code from your authenticator app is asked for at every sign-in (or a passkey, see below). Every
account needs a second factor, so it can be **replaced but never switched off**.

To replace it: **Replace authenticator app**, enter your password, scan the new QR code (or type the key) with
the new app and confirm with its first six digits. Until you confirm, the old app keeps working, so a failed
attempt locks you out of nothing. This asks for a sign-in from the last ten minutes ("Confirm it is you"). A directory
account has no GarnetOps password to enter: that recent sign-in (directory user name, password and code) is the proof.

**Backup codes** each work once if you cannot use your authenticator app or passkey. **Create new backup codes**
replaces all old ones and shows the new ones once; copy them or write them down before you close the dialog. The
page only ever says how many are unused.

## Passkeys

A passkey lets you sign in with the PIN, fingerprint or face of your device (or a security key with a PIN)
instead of a password and a code. It counts as your second factor too.

- **Add a passkey** (needs a sign-in from the last ten minutes): give it a name you will recognise, such as
  "Work laptop", and confirm with your device. Passkeys that sync between your devices (a password manager, the
  platform's keychain) are marked as synced; others stay on one device.
- **Sign in with a passkey** is on the sign-in page. You do not type an address; your device offers the passkeys
  it has for this installation. On the second step after a password there is "Use a passkey instead", and the
  "Confirm it is you" dialog has "Confirm with a passkey".
- **User verification is required.** A passkey is only accepted when your device checked that it is you (PIN,
  fingerprint or face). A device that only asks you to touch it is refused, both when you add the passkey and
  when you sign in. GarnetOps checks this itself on the server.
- **Rename** and **Remove** are on each row; removing needs a recent sign-in. The last second factor cannot be
  removed: while you have an authenticator app, you can remove every passkey.
- Passkeys are tied to the domain of GarnetOps and only work there. They need GarnetOps to be reached through a
  **domain name over HTTPS** (or on `localhost`); with an IP address or plain `http` the page explains that
  passkeys are unavailable.

### For operators: which address passkeys use

The domain and origin of the passkeys come from `PUBLIC_URL` of the API (for example
`https://garnetops.example.lan`), never from a request header. Passkeys registered under one address do not work
under another. Change `PUBLIC_URL` only if you accept that people add their passkeys again (the authenticator app
and password keep working).

## Sessions

Every browser or device that is signed in to your account, with browser and system, address, when it signed in and
when it was last active (updated about every 30 minutes). **This session** is marked. **Sign out** ends one other
session, **Sign out all other sessions** ends the rest; the current one ends with **Sign out** in the avatar menu.
Signing in again ("Confirm it is you") replaces the session it started from, so the list does not grow.

## Notifications

What you are told about, in the app (the bell in the top bar and short messages) and by email. One row per event your
role can receive, with **In app** and **Email** boxes and, for events about repositories, a choice between all and
only the ones you added or requested. Defaults are in app on and email off. **Email** is available only when your
organisation has an SMTP or Microsoft Graph channel; mail goes to the address you sign in with, never anywhere else, at
most one per event type every 15 minutes (more are combined). The organisation's shared channels (webhooks, mailboxes)
are separate and are managed by admins under Settings, Notifications. Changing these choices is not audited. Details:
[notifications.md](notifications.md) and [ADR 0019](adr/0019-in-app-notifications-toasts-and-personal-preferences.md).

## A lost second factor

If someone lost the phone with the authenticator app and has no backup code and no passkey, an operator with a
shell in the API container can reset that account's second factor. The web application never offers this.

```sh
# See what would happen (nothing is changed):
docker compose exec api node apps/api/src/cli.ts reset-second-factor person@example.com
# Do it:
docker compose exec api node apps/api/src/cli.ts reset-second-factor person@example.com --yes
```

This removes the authenticator app and all passkeys of that account and signs it out everywhere. The **password
stays**. The next sign-in with the password leads straight to the setup of a new authenticator app, like a new
account. Check that it is really the person (the command cannot) before you run it.

The reset is written to the audit log as "Second factor reset by an operator", with no signed-in person as the
actor, the address and how many factors were removed (Audit log, filter **Account**). Owners and admins see it.

If the only owner is locked out, the same command works for the owner's address.

## What is in the audit log

Owners and admins find these under **Audit log, Account** (and passkey sign-ins and refused calls under
**Sign-in**): display name changed, password changed (and wrong attempts), authenticator replacement started and
finished (or failed), backup codes renewed, passkey added, renamed, removed or refused, sessions signed out, and
operator resets. The log never contains passwords, codes, secrets or session tokens.

## Closed on purpose

The parts of the sign-in library that do the same things without the checks above are switched off and answer
"403": `/api/auth/change-password`, `/api/auth/update-user`, session revocation, reading the authenticator secret
or backup codes, and passkey rename, delete and list. Use the account page; its API is `/api/v1/account`.
