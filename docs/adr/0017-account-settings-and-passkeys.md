# ADR 0017: Account settings and passkeys

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (passkeys with user verification as an additional second factor and sign-in
  method; recovery of a lost second factor only through a command in the API container; the second factor is
  replaced, never switched off)
- Implements: ROADMAP Phase 1 "Passkeys (WebAuthn with user verification) as a second factor" and "Recovery for
  a lost second factor"
- Builds on: ADR 0003 (stack), ADR 0005 (time zones), ADR 0009 (step-up with a recent sign-in)

## Context

Every account has a mandatory second factor (AGENTS.md rule 1), and until now the only one was an authenticator
app (TOTP). A user could not change their name or password, replace a lost or new phone, see where they are
signed in, or use a passkey; and nothing helped someone who lost the phone. The maintainer asked for an account
page (avatar menu, then "Account") with a profile, password, authenticator app, passkeys and sessions, and for a
recovery path that the web application never offers.

## Decision

1. **A page of its own, `/account`,** opened from the avatar menu, readable width, sections on the left like
   Settings (Profile, Password, Authenticator app, Passkeys, Sessions; the section is in the URL). Every signed-in
   user sees it; it only ever touches the signed-in user's own account. Its API is `/api/v1/account`.
2. **Profile.** The display name can change. The **email address is shown and fixed**: it is the sign-in name and
   the key of invitations, and changing it needs verification mail that does not exist yet. Language (English,
   German) and time zone are stored per user (`user.locale`, `user.time_zone`, additive migration 0016). Null follows
   the browser. The language is taken from the account once per page load; the avatar menu's language picker saves
   to the account too. The time zone is applied to the times the app shows (`formatDateTime`, `formatDate`). Per
   ADR 0005, instants stay UTC; schedules keep the zone they were set with; the calendar-day figures of charts and
   exports still use the browser's zone (open item).
3. **Password.** A sign-in from the last ten minutes, the current password and a new one (12 to 256 characters,
   Argon2id through the same hash as sign-in).
   Other sessions are signed out unless the user unticks the box (default on). Rate limit: 5 per minute per user,
   kept in the database. better-auth's `/change-password` is closed (decision 9): with "sign out everywhere" it
   creates a new session without a second factor, which would reset the step-up clock (`createdAt` of the
   session is our "last strong sign-in").
4. **Authenticator app.** Replacing it needs a recent sign-in and the password. The new secret is stored sealed
   (better-auth's symmetric encryption) in the `verification` table for ten minutes under the user's key; **the old
   secret stays in force until the new one is confirmed with its first code**, then it is replaced in one
   transaction (failure counter and lock are reset). An abandoned attempt changes nothing. Backup codes are renewed
   on request after a recent sign-in, replace the old ones, and are shown once; only their count is shown later.
   There is no way to switch the second factor off (the existing refusal of `/two-factor/disable` stays).
5. **Passkeys** through better-auth's `@better-auth/passkey` 1.7.10 (a separate package in 1.7; MIT; it uses
   `@simplewebauthn/server`, MIT) and `@simplewebauthn/browser` in the web app (MIT). Registration and removal need
   a sign-in from the last ten minutes; rename, list and sign-in do not.
   - **User verification is required.** The plugin verifies with `requireUserVerification: false` and requests only
     "preferred" when signing in, so it would accept a passkey that was only touched, which would let a stolen
     security key or an unlocked laptop replace password *and* code. We therefore (a) request `required` for
     registration (`authenticatorSelection`) and, in the browser, for sign-in, and (b) **check the signed
     user-verified flag on the server** for every registration and sign-in (`passkeyOptions` in
     `lib/passkey-policy.ts`, run in the plugin's `afterVerification` hooks, before the counter is updated and
     before a session exists). Only (b) is a control; (a) is for the person's convenience.
   - **A passkey is a full second factor.** A sign-in with a passkey creates a session without password and code,
     because possession plus user verification are two factors. It is offered on the sign-in page, as "Use a
     passkey instead" on the second step, and as "Confirm with a passkey" in the "Confirm it is you" dialog.
   - **The authenticator app stays the baseline factor.** Enrolment at first sign-in is still the authenticator app,
     and a password-only session still ends at the enrolment screen. A passkey is added afterwards. So an account
     always has the authenticator app or has passed through recovery to get one again.
   - **Never zero factors.** Removing a passkey is refused (409 `last-second-factor`, audited as
     `account.passkey_removal_refused`) unless the authenticator app or another passkey remains. The check and the
     delete run in one transaction with the user row locked, so two requests cannot each see the other's factor.
     Today the authenticator app always remains, so the rule is a guard for the day a passkey can be the first factor.
   - **Relying party and origin come from `PUBLIC_URL`** (`rpID` = its host name, `origin` = its origin) and never
     from a request header. A passkey only works on that domain; an IP address or plain `http` (other than
     `localhost`) cannot carry passkeys, and the page says so instead of offering the button.
   - Registration uses `attestation: none` (we do not restrict authenticator models), resident keys are required
     so sign-in needs no address, the passkey's name is a label we store (not what the authenticator shows).
     A credential id is unique across accounts (unique index).
6. **Sessions.** The list shows the user's own active sessions: browser and system (summarised from the user agent,
   the raw string is not sent), address, signed in, last active (updated about every 30 minutes by better-auth's
   `updateAge`). Never a token. The user can sign out one other session or all others; the current one ends with
   sign-out. A fresh sign-in (second factor, backup code, passkey) ends the session it was started from, so
   "Confirm it is you" does not leave sessions behind.
7. **Recovery of a lost second factor: an operator command, never the web UI.**
   `node apps/api/src/cli.ts reset-second-factor <email> [--yes]` runs in the API container. Without `--yes` it only
   prints what it would remove. With it, in one transaction: the authenticator app and all passkeys of that account
   go, all its sessions end, pending second-factor challenges go, `two_factor_enabled` becomes false. The password stays.
   The next sign-in therefore ends at the mandatory enrolment of a new authenticator app, like a new account. The
   authority is a shell in the container (the same trust as the database); there is no route and no UI. It writes
   `account.second_factor_reset` (no signed-in actor, `via: cli`, the address and the counts) to the audit log of the
   account's organisation.
8. **Audit.** Every security-relevant action writes an entry: profile name, password (success and failure), the
   start and end of an authenticator replacement (both outcomes), new backup codes (the count, never the codes),
   passkey registered / renamed / removed / removal refused, session and sessions signed out, the operator reset,
   passkey sign-ins (a refused one is attributed to the account that owns the credential, so admins see it) and
   refused calls of closed endpoints. The audit page has an "Account" filter (`account.`); labels in English and
   German. No password, secret, code or token is ever written.
9. **Closed endpoints.** In `auth.ts` the better-auth routes that duplicate these changes answer 403
   `USE_ACCOUNT_PAGE` and are audited (`auth.endpoint_refused`): `/change-password`, `/set-password`,
   `/change-email`, `/delete-user`, `/update-user`, `/list-sessions` (its answer contains session tokens),
   `/revoke-session`, `/revoke-sessions`, `/revoke-other-sessions`, `/two-factor/get-totp-uri`,
   `/two-factor/generate-backup-codes`, `/passkey/list-user-passkeys`, `/passkey/update-passkey`,
   `/passkey/delete-passkey`. The two ceremony routes of registration are kept but get a before hook: the
   session must be younger than ten minutes (`STEP_UP_REQUIRED`) and the passkey name must be valid. Rate limits
   for the passkey routes are stored in the database like the sign-in limits.
10. **CSP stays strict.** WebAuthn needs no relaxed policy: `script-src 'self'`, `connect-src 'self'` and the
    `Permissions-Policy` stay as they are. The browser library is bundled, not loaded from a CDN.

## Threat model

- **Session hijack** (stolen cookie, unattended browser): every change to a factor or the password needs a sign-in
  from the last ten minutes, i.e. a stolen cookie older than that is useless for them; replacing the authenticator
  app and changing the password also ask for the password, so a cookie alone is not enough even inside the window.
  Renaming a passkey, the profile and ending sessions do not need it (they weaken nothing).
  Rate limits apply per user. Other sessions can be ended from the sessions list and by the password change.
- **Phishing:** a passkey is bound by the browser and the authenticator to the RP ID and origin, so a look-alike site
  cannot obtain a usable assertion; a phished password alone does not sign in (second factor). Challenges are
  random, single-use, bound to a signed cookie and expire after five minutes (better-auth's verification table).
  The origin that is checked is the configured one, not the request's `Origin` header.
- **Downgrade by removing factors:** the second factor can be replaced but not removed; the last factor cannot be
  removed even by racing two requests; `/two-factor/disable` stays refused.
- **Downgrade of passkey strength** (a client that asks for `discouraged`): the server rejects any assertion or
  registration without the user-verified flag; covered by an end-to-end test that sends exactly such a request with
  Chromium's virtual authenticator.
- **Account recovery abuse:** no network route; needs a shell in the container; audited; ends all sessions so a
  session that survived the loss of the device cannot outlive the reset. A reset leaves the password, so the
  account owner still proves the password and sets up a new factor.
- **Enumeration:** passkey sign-in has no address field, so it reveals nothing about accounts; a wrong or unknown
  credential answers the same. Wrong-password answers on the account page say only that the password is wrong (the
  caller is signed in already). Password sign-in is unchanged (same answer for unknown account and wrong password).
- **Cloned or synced authenticators:** the signature counter is stored and checked by the library (authenticators
  that always report 0, such as synced passkeys, are accepted, as the standard allows). Passkeys show whether they
  are synced or bound to one device, so the user can judge.
- **A lost device with a passkey:** remove the passkey from the account page (recent sign-in) or have an operator
  reset the second factor; sessions can be ended.
- **Leaks:** the page and the API never return the TOTP secret (except the one-time QR code of a pending replacement),
  backup codes (except once after renewal, `Cache-Control: no-store`), public keys or credential ids; the audit log
  and the e2e tests assert this.
- **CSRF:** all state-changing requests keep the same-origin check; cookies are `SameSite=Lax`, HttpOnly.
- **Residual risks:** a passkey synced through a cloud account is as strong as that account; the authenticator app
  secret sits in the database encrypted with the auth secret (existing design); the user-verified flag is the
  authenticator's own statement, we do not check attestation.

## Consequences

- New table `passkey` and columns `user.locale`, `user.time_zone` (additive migration 0016, forward-only).
- New dependencies, all MIT or compatible, listed in `docs/COMPONENTS.md`: `@better-auth/passkey` 1.7.10 (with
  `@simplewebauthn/server` 13.3.3 and its `@peculiar/*` and CBOR helpers), `@simplewebauthn/browser` 13.3.0,
  `@better-auth/utils` 0.5.0 (now direct). The plugin pulls `zod` 4 for itself; better-call's optional `zod` peer
  now resolves to the workspace's zod 3, which only its unused OpenAPI generator imports.
- better-auth's two-factor helpers for backup codes are typed but not exported at run time in 1.7.10, so
  `lib/backup-codes.ts` writes the same stored format.
- The sign-in page needs no change for existing users; a user without a passkey sees no difference except the new
  button.
- Open items: changing the email address (needs mail verification); a passkey as the *first* factor at enrolment;
  day-based figures in the chosen time zone; passkey conditional UI (autofill) on the sign-in page; checking
  attestation or restricting authenticator models for customers that need it.
