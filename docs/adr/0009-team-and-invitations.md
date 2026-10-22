# ADR 0009: Team and invitations

- Status: accepted (2026-10-21)
- Date: 2026-10-21
- Decided by: maintainer (invitation by copied link until mail exists; removing a member
  keeps the account; team changes need a recent sign-in)
- Implements: ROADMAP Phase 1 "Roles in practice: invitations, member management"; mockup
  item "Team" (Admin)

## Context

Every installation starts with one owner (first-run setup). Open sign-up is disabled
(AGENTS.md rule 1), so further people need a way in that an owner or admin controls, and
roles (owner, admin, member, viewer) must be manageable without a database console.
Outgoing mail does not exist yet (ROADMAP Phase 5).

## Decision

1. **Invitations.** Owners and admins invite an email address with a role. GarnetOps
   creates a one-time link (`/invite#<token>`, 256 random bits) and shows it once; the
   admin sends it themselves. Only a SHA-256 hash of the token is stored. A link is valid
   for 7 days, works once, and can be revoked. Inviting the same address again replaces
   the open invitation. When mail arrives (Phase 5), it sends the same link.
2. **Accepting.** The link opens a page that shows the organisation, the address and the
   role, then asks for a name and a password (12 characters or more, Argon2id). The new
   account must set up its second factor at the first sign-in, like every account. The
   token is in the URL fragment, so it never reaches server or proxy logs.
   A person whose access was removed earlier keeps their account, password and second
   factor; accepting a new invitation restores the membership without changing them.
3. **Who may do what.** Owners manage everyone and every role. Admins invite, change and
   remove members and viewers only; they cannot create or change owners or admins. Nobody
   changes their own role or removes themselves, and the last owner can neither be demoted
   nor removed.
4. **Removing** someone deletes the membership and every session of that account at once.
   The account stays, so the audit log keeps naming who did what.
5. **Step-up.** Inviting, changing a role and removing someone need a sign-in from the
   last ten minutes (password and code again), as for updates (ADR 0007).
6. **Audit.** Every invitation (created, revoked, accepted), role change and removal is in
   the audit log, with the email address and roles involved.

## Threat model

- **A leaked invitation link** gives its holder one account with the invited role, until
  it is used, revoked or expired. Mitigations: 7-day expiry, single use, revocation, the
  role is fixed by the inviter, a second factor is still required, and the acceptance is
  audited with the client address.
- **Guessing tokens**: 256 random bits; lookups and acceptance are rate-limited per client
  address in the database.
- **An admin escalating**: admins cannot grant admin or owner and cannot touch owners.
- **A hijacked session** (unattended browser): step-up blocks team changes.
- **Lock-out**: the last owner is protected.

## Consequences

- New table `invitation` (additive migration 0008).
- New Admin page "Team" and a public page `/invite`.
- Members whose access was removed appear in the audit log with their name, and can be
  invited again.

## Later changes

- ADR 0020 adds directory accounts (LDAP, Active Directory). Their role comes from directory groups, so changing it or
  removing them on the Team page, and inviting their address, are refused (409 `managed-by-directory`,
  `directory-account`); owners are always local accounts.
