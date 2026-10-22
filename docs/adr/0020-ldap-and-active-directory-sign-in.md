# ADR 0020: LDAP and Active Directory sign-in

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (sign-in with LDAP and Active Directory, owners only to configure; accounts only for people in
  an allowed group; the second factor stays mandatory; the service account's password is protected by the vault)
- Implements: ROADMAP Phase 5 "SSO (OIDC/OAuth) and LDAP with allowed-domain registration" (the LDAP half); AGENTS.md
  "Sign-in of its own ... LDAP/Active Directory", "Self-registration only through an identity provider and only for
  allowed email domains or directory groups"
- Builds on: ADR 0004 (the vault: the API seals, only the worker opens), ADR 0009 (team, roles, step-up), ADR 0015
  (certificate pinning on first contact, as for Proxmox), ADR 0017 (account settings, closed better-auth endpoints,
  second factor), ADR 0019 (notifications)

## Context

Sysadmins run a directory already: Active Directory in most Windows networks, OpenLDAP, 389 Directory Server or
FreeIPA elsewhere. Asking everybody to keep another password for GarnetOps is a cost, and an offboarded colleague
whose directory account is disabled should lose access without anybody remembering a second place. AGENTS.md allows
self-registration only through an identity provider and only for allowed groups or domains, requires a second factor
for every account, and requires that an unknown identity never gets an account implicitly.

A directory is also dangerous to talk to. The user name is typed by anyone who can reach the sign-in page and ends
up in a search filter. The password of a read-only *service account* has to be stored so that GarnetOps can look
people up, and the web-facing API must not be the process that can read it. A wrong guess against the directory
counts toward its account lock-out policy, so GarnetOps could lock real people out. Mail attributes are not a safe
key for linking accounts. Everything the directory returns is untrusted input.

## Decision

### 1. Where the directory is talked to: the worker, through sealed requests

An LDAP bind for sign-in happens at request time, while the vault says "the API seals, only the worker opens"
(ADR 0004). Two ways to keep the service account's password out of the API were weighed:

| Option | What it means | Verdict |
|---|---|---|
| A. A second vault capability in the API for the purpose `ldap-bind-password` | The API gets a private key (or a derived key) that opens exactly this one purpose, and binds itself | Rejected. The web-facing process would hold a decryption key. A flaw in the API (the most exposed component) would then disclose the service account, whose read access to the whole user tree is worth a lot. A purpose-bound key is still a key. |
| B. The worker performs every directory operation; the API queues a request and waits for the answer | The API never sees the service account's password in any form | **Chosen** |

How B works. The API inserts a row in `directory_request` (kinds `sign-in`, `test`, `lookup`, `certificate`) and sends
a job (`directory.request`, polled twice a second, no retries). A password typed at sign-in is **sealed for the vault
public key** into one `secret` row (purpose `ldap-user-password`, bound to the organisation and record) and the
request holds only its id. The worker takes the request atomically, opens the sealed password, **deletes the secret
row at once** (whatever happens next) and writes the answer into the request row. The API polls for the answer (80 ms,
28 s at most), reads it, and deletes the request and, if it is still there, the secret. A sweep in the worker removes
rows older than ten minutes.

Costs and what B does not fix:

- A sign-in costs up to half a second more (polling) plus the LDAP round trips (a few dozen milliseconds on a LAN).
- The typed password is sealed in the database for about a second. It is hybrid post-quantum sealed, bound to its
  record, and gone as soon as the worker has it.
- The API still sees the typed password in memory, because it terminates the HTTP request. That is unavoidable for any
  password sign-in and not different from the local sign-in.
- If the worker is down, directory sign-in is down (503, "the directory cannot be reached right now"). Owners sign in
  with their local password and second factor (decision 7), so nobody is locked out of the installation.

### 2. The connection: TLS or nothing, and trust you can verify

- Only `ldaps://` (default port 636) and `ldap://` (default 389) are accepted. A server given as `ldap://` is
  upgraded with **StartTLS before anything else is sent**; if the server refuses, or the handshake fails, the
  connection is dropped and no bind, search or password has gone over it. There is no setting for plain LDAP and no
  fallback. A server list (up to four) is tried in order.
- The worker resolves the name, checks **every** answer against the same address policy servers and Proxmox use (no
  loopback, link-local or metadata addresses, no numeric oddities such as `127.1`) and connects to the address it
  checked; the name is used for the TLS server name and certificate name check only. Private networks are allowed:
  a directory lives in one.
- TLS 1.2 or newer. Trust is one of three, chosen by the owner:
  - **Certificate store**: the system's roots, chain and host name verified.
  - **Own certificate authority**: only the pasted PEM certificates are trusted (they *replace* the system roots),
    chain and host name verified. A pasted private key is refused.
  - **Pin**, like Proxmox (ADR 0012): the SHA-256 of the server's leaf certificate, **confirmed on first contact**.
    The worker reads the certificate without sending anything; an owner compares the fingerprint with the one the
    server shows and confirms it (step-up). After that, only that certificate is accepted, whatever signed it. A
    different certificate is refused **before the first LDAP byte**, recorded as a candidate for review, audited
    (`directory.certificate_changed`, once per change), announced to owners and admins, and the old pin stays in
    force. If the pinned certificate comes back, the alarm clears itself.
  The trust decision is made on a socket the worker opened itself; the LDAP client (ldapts) is handed a socket that is
  already trusted. Nothing relies on the client library's TLS defaults.
- Referrals are never followed. Paging is not used; searches carry a size limit (2 for the user, 1 for groups) and a
  time limit. Connect and per-operation timeouts are configurable within limits (1-30 s, 1-60 s); a request has a
  25 s overall deadline.

### 3. The sign-in, step by step

1. **Input** (API). The user name must be 1 to 128 characters, start with a letter or digit and contain only letters,
   digits and `. _ @ \ ' + -` (that covers `jdoe`, `jdoe@example.lan`, `EXAMPLE\jdoe`); the password 1 to 512 characters
   without NUL. **An empty password is refused before anything is queued**, because a simple bind with a name and an
   empty password is an "unauthenticated bind" (RFC 4513, 5.1.2) that many servers answer with success. The worker
   checks both again (defence in depth). Nothing that fails the checks reaches the directory.
2. **Search** (worker, as the service account, on its own connection). The user filter is a template that must contain
   `{username}`. The name is substituted **escaped per RFC 4515** (`* ( ) \` NUL and every control character become
   `\xx`) in one pass, so a value can neither end a filter item, open another nor become a wildcard. Search base
   and filter are validated when saved (syntax checked, only the documented placeholders). Exactly one entry must come
   back: none is a refusal, more than one is a misconfiguration (no coin toss), and an entry whose DN is not below the
   search base is not believed.
3. **Password check** (worker). A bind as the entry's DN, with the typed password, on a **second connection**, so the
   service connection is never rebound. The DN is the one the directory returned, never one built from the typed name.
   For a name that does not exist the worker makes the same number of round trips (a bind with a made-up DN and a
   random password) so the answer takes about as long.
4. **Groups** (worker, service connection). Only the groups named in the configuration are asked about; nothing else
   in the user's group list is read or stored. Three modes: `memberOf` (direct), Active Directory's matching rule in
   chain `1.2.840.113556.1.4.1941` (nested groups, evaluated by the server for each configured group), or a
   configurable search filter per group (`(|(member={dn})(uniqueMember={dn}))` for OpenLDAP; `memberUid` for
   `posixGroup`). The DN of the user is escaped when it goes into a filter. A group search that fails is an error,
   **never "not a member"**; a group that does not exist has no members.
5. **Role.** Each configured group gives `admin`, `member` or `viewer`; the highest of the person's groups wins. A
   person in none of them is refused. DNs are compared as names (case-insensitive, escapes decoded, multi-valued RDNs
   ordered), never as text; a DN that does not parse matches nothing. **`owner` is not a role a group can give**
   (types, validation and database writes all exclude it).
6. **Answer.** The worker returns outcome, a reason for the admin, and the facts (unique id, DN, mail, name, matched
   groups, role). Never a password. The API turns anything but a clear "yes" into one generic refusal.

### 4. Who gets an account

An account is linked to a person by the directory's **immutable unique id** (`objectGUID` for Active Directory,
`entryUUID` for OpenLDAP, configurable), kept in `directory_identity` with a unique index per organisation. Binary
`objectGUID` is converted to the usual GUID text.

- **First sign-in.** An account is created only if the person is in an allowed group, the directory gave a plausible
  mail address, and **no other account has that address**. The account has no password. `email_verified` is false
  unless the owner declared the directory trusted for mail addresses (setting "Treat mail addresses from the directory
  as verified"); that flag only marks new accounts and never links anything. Two first sign-ins at once make one account
  (advisory lock per person).
- **Email collision.** An existing account with the same address is **never linked automatically**. The sign-in is
  refused with the generic message, and the audit log gets an entry for the administrators (`auth.directory_sign_in`,
  failure, reason `email-collision`, the address, the existing account, a hint), attributed to the existing account.
  An owner links the account explicitly on the Team page: look the person up, see the directory entry, groups and
  role, confirm (step-up). Linking requires the directory address to equal the account's address, replaces the local
  password by the directory (the credential row is deleted; the authenticator app stays), applies the role of the
  groups and ends every session of the account.
- **Owners cannot be linked.** Owners are local accounts: a directory outage or a changed group must never lock the
  installation out, and nobody becomes an owner by being put in a group. `applyDirectoryRole` never touches an owner.
- **Changing the mail attribute** later does not move the account: the identity is the unique id. The account's
  address follows the directory unless another account has the new address (then it stays, audited as
  `directory.email_conflict`). The display name follows the directory at every sign-in and is read-only in the account
  page.
- **No local password for directory accounts.** The local sign-in refuses their address (same answer and work as a
  wrong password), the password change and name change on the account page answer 409 `managed-by-directory`,
  invitations to their address are refused and an invitation link for a directory account is "gone".

### 5. The second factor stays mandatory

The directory sign-in is a better-auth plugin whose endpoint is `POST /api/auth/sign-in/username`. That path is the
one better-auth's two-factor plugin watches after a password sign-in. So the code that turns a session into "pending
second factor" for `/sign-in/email` does the same here: **a directory sign-in cannot skip the second factor**, and no
second implementation of the second-factor step exists to get wrong. (The `username` plugin of better-auth, which uses
the same path, is not installed.)

- A directory account without a second factor gets a session that may only enrol one (the rule of every account);
  the enrolment page does not ask for a password it does not have. For that, `allowPasswordless` is set on the
  two-factor plugin: it only means "no password check if the account has no credential password", which in
  GarnetOps is exactly the directory accounts. Local accounts still give their password.
- Passkeys work as for local accounts (ADR 0017). A passkey sign-in does not ask the directory, which is why the
  periodic check below also ends membership.
- "Confirm it is you" (step-up) for a directory account asks for the directory name (offered from the last sign-in),
  the directory password and a code: a real sign-in, as for local accounts. Replacing the authenticator app asks for
  that recent sign-in and no local password.

### 6. Roles and access stay true: at every sign-in and every 15 minutes

- **Every sign-in** re-reads the groups: a changed group changes the role (audited `directory.role_changed`, the
  person is told in the app), a person in no allowed group loses the membership **and every session** (audited
  `directory.access_removed`), and a returning person gets the membership back (`directory.access_restored`).
- **A check every 15 minutes** in the worker asks the directory about every directory account, by the stored DN with
  the user filter (so an account the filter no longer matches, for example a disabled one, counts as gone), checks the
  unique id, reads the groups, and applies the same rule. Sessions renew while they are used, so without this a
  busy session of an offboarded person would live indefinitely.
- The check **changes nobody when the directory cannot be asked** or answers unexpectedly (all questions are asked
  first, changes are applied afterwards). An outage must not sign everyone out. Trade-off: during an outage, the
  access of people removed in the meantime lasts until the directory is back.
- Directory accounts' roles cannot be changed on the Team page (409), because the next sign-in would undo it; the role
  column says "Set by the directory groups". They cannot be removed there either, for the same reason: remove the
  person from the groups.

### 7. Rate limits that stay below the directory's lock-out

Directories lock accounts after a number of wrong passwords (Active Directory policies commonly use 5 to 10 within
15 to 30 minutes). GarnetOps must never be the reason an account is locked, nor a way to lock one on purpose:

- better-auth's limit on the endpoint: 5 requests a minute per client address, stored in PostgreSQL.
- **Failures per user name: 3 in 15 minutes** (counted case-insensitively, by a hash of organisation and name). The
  fourth attempt answers 429 without asking the directory. Unknown names count like known ones, so the limit gives
  nothing away. A success clears the count. Only failures are counted, so a person who signs in correctly is never
  throttled.
- **Failures per client address: 20 in 15 minutes** over all names (spraying).
- Not counted: the directory being unreachable, which is not the person's doing.
- Trade-off, stated: anyone can make a name unavailable for 15 minutes by typing three wrong passwords. They could do
  the same against the directory itself (with worse effect); this way the real account is not locked there.
- **The service account is protected the same way**: when the directory refuses its password, GarnetOps stops trying
  for 10 minutes (`bind_blocked_until`; a new password lifts it) and does not try the next server with the same wrong
  password.
- **Uniform refusals.** Unknown name, wrong password, no allowed group, email collision, a switched-off directory and
  an invalid input all answer 401 with the same body, and take at least one second (plus up to 120 ms of jitter). The
  worker equalises the number of directory round trips for unknown names. "Directory unavailable" (503) and "too many
  attempts" (429) are said honestly.

### 8. Configuration: owners only, tested before it goes live, audited

Settings, Sign-in. Only owners see or change it; every change needs a sign-in from the last ten minutes (step-up,
ADR 0009) and is audit-logged with what changed (never the password).

- Fields: server URLs, trust (store, CA PEM, pin), service account DN and password, search base, user filter,
  attribute mapping (mail, name, unique id), group mode and filter, allowed groups with roles (up to 50), whether the
  directory's mail counts as verified, timeouts and a size limit. Presets for Active Directory and OpenLDAP fill the
  usual values (AD filter `(&(objectClass=user)(sAMAccountName={username}))`, OpenLDAP
  `(&(objectClass=inetOrgPerson)(uid={username}))`).
- **The service account password is write-only**: sealed into the vault on save (purpose `ldap-bind-password`,
  bound to the organisation and record), never returned, never logged, never in an audit entry.
- **The connection test** (bind, search base, every configured group exists, and with a user name: DN, mail, name,
  unique id, matched groups and the role) uses the saved settings and shows every server separately. It never needs or
  shows a password.
- **Untested settings never go live.** Switching the sign-in on needs a successful test *with a person found* on the
  saved settings. A save that changes how the directory is reached or read (servers, trust, bind, base, filter,
  attributes, group mode) clears the test and, if the sign-in was on, **switches it off** and says so. Changing the
  allowed groups does not.
- Certificates: scan, review and confirm per server (step-up), as for Proxmox; the confirmation pins exactly the
  fingerprint the owner saw.

### 9. Logging and audit

Audit actions (all visible under Audit log, filter "Directory" and "Sign-in"): `auth.directory_sign_in` (success and
every kind of failure, with a reason), `directory.settings_created`, `directory.settings_changed`,
`directory.test_run`, `directory.certificate_scan_requested`, `directory.certificate_confirmed`,
`directory.certificate_changed`, `directory.account_created`, `directory.account_linked`, `directory.role_changed`,
`directory.access_removed`, `directory.access_restored`, `directory.email_changed`, `directory.email_conflict`.

- A password is in no log, row (beyond the sealed record that lives for one request), audit entry, error message or
  test fixture. The worker logs error *names* only.
- **A typed user name is not written to the audit log for refused attempts** (people paste passwords into name
  fields). The entry carries a short hash reference of the name and, when the directory identified the person, the DN
  of the directory entry and the attributed account, so administrators see whose password was tried.

## Threat model

| Threat | What can an attacker reach | Mitigation |
|---|---|---|
| **LDAP injection** through the user name | Search results for other people, a bind as someone else | Charset and length of the name, RFC 4515 escaping of every substituted value in a single pass, filter templates validated when saved, exactly one result accepted, the DN for the bind comes from the directory. Tests: wildcards, `)(|(...`, NUL, backslash, values that look like placeholders. |
| **Downgrade to plain LDAP** | The service account's and the user's password | No plain LDAP exists. `ldap://` is upgraded with StartTLS first and dropped on refusal; tests prove no bind or search was seen on an unencrypted connection and that a server without StartTLS receives nothing. |
| **Man in the middle** | Passwords, group data | TLS 1.2+, chain and host name verified (store or own CA), or the pinned leaf certificate; decided before any LDAP byte; a changed certificate is refused, audited and announced. |
| **Anonymous or unauthenticated bind** | Sign-in as anyone | An empty password is refused in the API and again in the worker; the service account password must be non-empty; the bind DN is never empty; tests run against a server that accepts unauthenticated binds. |
| **Account takeover through an email collision or a changed mail attribute** | Another person's account and role | Linking by unique id only; an existing local account with the same address is never linked automatically (explicit owner action with the address check); a changed address never moves an account; owners cannot be linked. |
| **Stale group membership** | Access after offboarding | Re-read at every sign-in and every 15 minutes; membership and sessions end together; fail-safe against outages (no change when the directory cannot be asked). |
| **Brute force and spraying, or lock-out of real accounts** | Passwords; availability of directory accounts | Limits below typical lock-out thresholds (3 failures per name, 20 per address, 15 minutes), failure-only counting, no directory contact once limited, service account pause after a refusal, uniform refusals with a time floor. Residual: a name can be made unavailable for 15 minutes by anyone. |
| **Service account compromise** | Read access to the directory | Read-only by design (GarnetOps never writes); password sealed, only the worker can open it, never the web-facing API; documented least-privilege setup; rotation by saving a new password (the old secret is deleted). |
| **A hostile or broken directory** | Our parser, our data | Every value is parsed defensively (DNs, GUIDs, mail, names); a result outside the search base is refused; size and time limits; referrals ignored; nothing from the directory is rendered as HTML or executed. |
| **SSRF through the server address** | Internal services | The same address policy as the other integrations on every resolved address; the connection goes to the checked address. |
| **Web-facing API compromised** | Typed passwords of people signing in meanwhile; sessions | Cannot read the service account password or any other vault secret; cannot read sealed user passwords (the vault key is the worker's). |
| **Secrets in logs** | Passwords | Not logged anywhere; audit entries carry references and DNs only; tests assert that results, rows and log output do not contain the passwords. |
| **Bypassing the second factor** | Sessions without the factor | The two-factor plugin's own after-hook handles the directory endpoint; enrolment is forced for sessions without a factor (`requireActor`); tests cover both. |

## Consequences

- New dependency in the worker: **ldapts 9.2.0** (MIT; its only dependency `strict-event-emitter-types` 2.0.0 is
  ISC), listed in `docs/COMPONENTS.md`. It is pinned exactly; the release is older than two weeks. `ldapjs` (MIT,
  archived/deprecated) was not used, not even for tests: the test server (`apps/worker/test/fake-ldap.ts`) is built on
  the message and filter classes ldapts already exports. LDAP is a small protocol, but BER parsing is not something to
  write twice.
- Migration 0018 (additive, forward-only): `ldap_config`, `directory_identity`, `directory_request`; two new secret
  purposes (`ldap-bind-password`, `ldap-user-password`, no schema change as the column is text); queue
  `directory.request`; title key `certificateChangedDirectory` for notifications.
- API (additive): `GET/PUT /api/v1/directory`, `POST /api/v1/directory/{test,lookup,link}`,
  `POST /api/v1/directory/certificates/{scan,confirm}`; `GET /api/v1/sign-in-options` (public: whether the directory
  is on); `source` on `GET /api/v1/team/members`; `profile.source` and `profile.loginName` on `GET /api/v1/account`;
  better-auth endpoints `POST /api/auth/sign-in/username` and `GET /api/auth/directory/me`. New problem types
  `managed-by-directory`, `directory-account`, `not-tested`, `email-mismatch`, `not-allowed`, `already-linked`,
  `owner`. No existing field changes meaning.
- Operations: no new environment variable and no new key file. Existing installations see no difference until an owner
  switches the sign-in on.

## Not done, and not tested

- **Not tested against a real Active Directory, OpenLDAP, 389 DS or FreeIPA.** Everything is tested against a fake
  LDAP server built for the purpose (protocol level, TLS and StartTLS, both dialects' filters, the matching rule in
  chain, nested groups, size limits, unauthenticated binds). Behaviour that differs in real servers (referrals,
  attribute casing, `objectGUID` filters, lock-out counters, paging limits of 1000 entries in AD) is untested.
- Account linking by an administrator needs the same address on both sides; there is no override. Unlinking is not
  built.
- No SASL/GSSAPI (Kerberos), no client certificates for the service account, no LDAP password change or expiry
  handling (a directory that wants a password change at sign-in just refuses).
- One directory per organisation and one organisation per installation today; the sign-in page picks the first
  organisation with an enabled directory.
- Groups are read for people who sign in and by the 15-minute check; there is no admin-triggered "check now" and the
  interval is fixed.
- OIDC/OAuth sign-in (the other half of the roadmap item) is a separate decision.
