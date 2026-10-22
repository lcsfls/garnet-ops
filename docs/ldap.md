# Sign in with LDAP or Active Directory

People can sign in to GarnetOps with the account they already have in your directory: **Active Directory**,
**OpenLDAP**, 389 Directory Server, FreeIPA or any other LDAP server (ADR 0020). The directory checks the password;
GarnetOps never stores it. **Every account still needs a second factor** (authenticator app or passkey), set up at the
first sign-in, with no exception.

Only owners configure this, under **Settings → Sign-in**. GarnetOps reads from the directory with a **read-only
service account** and never writes to it.

## How it works in short

- A person types their **directory user name** and password on the sign-in page ("Directory account").
- GarnetOps looks the person up with the service account, checks the password by binding as that person, and reads
  which of **your allowed groups** they are in. The highest role of those groups applies (admin, member, viewer).
- A person **in none of the allowed groups gets no account**, and sees the same message as for a wrong password.
- The first successful sign-in creates the account (mail address and name from the directory, no password). It is
  linked to the person by the directory's immutable ID (`objectGUID`, `entryUUID`), **not by mail address**.
- The role is read again at every sign-in and **every 15 minutes**. Someone who leaves all allowed groups, is deleted
  or disabled loses access and every session within 15 minutes.
- **Owners are always local accounts.** A group never makes someone an owner, and a directory outage never locks the
  installation out.

## What you need

- A directory server reachable from the GarnetOps **worker** (not the browser) over **LDAPS** (usually port 636) or
  LDAP with **StartTLS** (port 389). Plain LDAP is not supported, and there is no setting to allow it.
- A **read-only service account**, and one group per role you want to hand out.
- The server's certificate: from a certificate authority this installation trusts, from your own authority (paste
  it), or pinned (confirm its fingerprint once).

### Active Directory, example.lan

Create the service account (PowerShell on a domain controller; names are examples):

```powershell
New-ADUser -Name "svc-garnetops" -SamAccountName "svc-garnetops" `
  -Path "OU=Service,DC=example,DC=lan" -AccountPassword (Read-Host -AsSecureString) `
  -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true
New-ADGroup -Name "GarnetOps-Admins"  -GroupScope Global -Path "OU=Groups,DC=example,DC=lan"
New-ADGroup -Name "GarnetOps-Users"   -GroupScope Global -Path "OU=Groups,DC=example,DC=lan"
New-ADGroup -Name "GarnetOps-Viewers" -GroupScope Global -Path "OU=Groups,DC=example,DC=lan"
```

A normal domain user can already read users and groups, so the service account needs **no extra rights**. Do not make
it a member of any privileged group. Give it a long random password.

| Setting | Value |
|---|---|
| Directory type | Active Directory |
| Servers | `ldaps://dc1.example.lan` and `ldaps://dc2.example.lan` |
| Service account | `CN=svc-garnetops,OU=Service,DC=example,DC=lan` |
| Search base | `OU=Users,DC=example,DC=lan` |
| User filter | `(&(objectClass=user)(sAMAccountName={username}))` |
| Mail / name / unique ID | `mail` / `displayName` / `objectGUID` |
| Groups | Active Directory, including nested groups |
| Allowed groups | `CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan` → Admin, `CN=GarnetOps-Users,…` → Member, `CN=GarnetOps-Viewers,…` → Viewer |

People type `jdoe` (or `jdoe@example.lan` or `EXAMPLE\jdoe` if your filter matches that form; the default filter
matches `sAMAccountName`, so `jdoe`). To also refuse **disabled accounts** (and have the 15-minute check remove them),
use

```
(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

"Including nested groups" asks the domain controller whether the person is a member through groups inside groups
(the matching rule `1.2.840.113556.1.4.1941`). "memberOf attribute" counts only groups the person is a direct member
of. The user's *primary group* (usually Domain Users) is not in `memberOf`; use a dedicated group for GarnetOps.

### OpenLDAP, dc=example,dc=lan

| Setting | Value |
|---|---|
| Directory type | OpenLDAP |
| Servers | `ldaps://ldap.example.lan` |
| Service account | `cn=reader,dc=example,dc=lan` (read access to `ou=people` and `ou=groups`) |
| Search base | `ou=people,dc=example,dc=lan` |
| User filter | `(&(objectClass=inetOrgPerson)(uid={username}))` |
| Mail / name / unique ID | `mail` / `cn` / `entryUUID` |
| Groups | Search the groups, with the filter below |
| Allowed groups | `cn=garnetops-admins,ou=groups,dc=example,dc=lan` → Admin, and so on |

The group filter, run against each allowed group:

```
(|(member={dn})(uniqueMember={dn}))
```

For `posixGroup` use `(memberUid={username})`. `{dn}` and `{username}` are replaced by the person's
distinguished name and the typed name, **escaped**, so they cannot change the filter.

## Set it up

1. **Settings → Sign-in.** Choose the directory type (this fills in the usual filter, attributes and group mode),
   enter the servers (one per line), the certificate trust, the service account, the search base and the allowed
   groups, and **Save**. Saving needs a sign-in from the last ten minutes.
2. **Certificates.** With *Pin the server certificate*, GarnetOps reads each server's certificate (nothing is sent to
   it), shows the fingerprint, and you compare it with the server and **Confirm**. With *Own certificate authority*,
   paste the PEM certificate(s) of your authority; they *replace* the system roots for this connection.
3. **Test the connection** with the user name of someone who should be able to sign in. The test shows each server,
   whether the groups exist, and what the directory says about the person: entry, mail, unique ID, matched groups and
   the **role they would get**. It needs no password. A person without a mail address cannot get an account.
4. **Allow signing in with the directory** (the box is available after a successful test with a person) and Save.

Changing how the directory is reached or read (servers, trust, service account, base, filter, attributes, group mode)
clears the test and **switches the sign-in off** so that untested settings never go live. Changing the allowed groups
does not.

## Signing in

On the sign-in page choose **Directory account**, enter the user name and password. The next step is the second factor:
at the very first sign-in the **setup of your authenticator app** (there is no password to confirm, because the
directory owns it); afterwards a code, or a passkey you added.

"Confirm it is you" (before changing settings, for example) asks for the directory user name, password and a code.

A directory account has no GarnetOps password: the Password page says so, the local sign-in refuses it, and the name
comes from the directory. The role on the **Team** page is read-only ("Set by the directory groups"), and a directory
account is changed by changing the groups, not by removing it there (the directory would bring it back).

## When an account already exists

If someone already has a **local** account with the same mail address (an invitation, or the first owner), their
directory sign-in is **refused**: GarnetOps never links accounts by mail address, because a changed mail attribute
could otherwise take over somebody else's account. The Audit log has an entry for administrators (`auth.directory_sign_in`,
reason `email-collision`) naming the address and the existing account.

An owner **links** the account on the **Team** page (the link button in the person's row): enter the directory user
name, look the person up, check the entry, groups, role and that the address matches, and confirm. The account then
signs in with the directory, loses its local password, takes its role from the groups and is signed out everywhere;
its authenticator app stays. Owners cannot be linked.

## Limits against lock-outs

Directories lock accounts after repeated wrong passwords. GarnetOps stays below that:

- After **3 wrong passwords for one name in 15 minutes**, GarnetOps stops asking the directory for that name until the
  15 minutes are over (the message is "Too many attempts"). Unknown names count like known ones. A correct password
  clears the count. Anyone can therefore make a name unavailable *in GarnetOps* for 15 minutes; they could lock the
  real account in the directory instead.
- **20 failed attempts per client address** in 15 minutes, and 5 requests a minute per address, stop password
  spraying. The limits live in the database and survive restarts.
- If the directory **refuses the service account's password**, GarnetOps stops using it for 10 minutes (and does not
  try the next server with it). Save the correct password in the settings to lift the pause.

Your directory's own policy (for example five wrong passwords in 30 minutes) still applies to wrong passwords that
reach it: at most three per name and quarter hour can come from GarnetOps.

Every refusal answers the same way and takes about a second; the reason (not in a group, wrong password, mail
collision, unreachable) is in the audit log, never the typed name or password.

## Troubleshooting

| The test says | What to check |
|---|---|
| The TLS connection failed | The certificate is not trusted or does not match the name you entered. Use the name in the certificate, add your authority, or pin it. |
| The server refused StartTLS | The server does not offer StartTLS on that port. Use `ldaps://` (usually 636) or enable StartTLS. Nothing was sent. |
| The directory refused the service account | Name or password. GarnetOps pauses the account for 10 minutes; save the right password. |
| The search base does not exist | Check the DN, including `DC=` parts. |
| No user matched the filter | Try the filter in `ldapsearch` or ADSI Edit with the same name. |
| More than one user matched | The filter must match exactly one entry. Add `objectClass` or narrow the base. |
| The user has no usable mail address | The mail attribute is empty. Fill it in the directory or change the attribute. |
| The user is in none of the allowed groups | Check the group DNs (the test lists whether each exists) and the group mode. |
| The server shows another certificate than the pinned one | The certificate was renewed, or someone intercepts the connection. Compare the new fingerprint, then confirm it. |

## What is not covered

Tested against a fake LDAP server built for this purpose (TLS, StartTLS, both dialects, nested groups, size limits),
**not against a real Active Directory or OpenLDAP**. Not supported: Kerberos/SASL, client certificates for the
service account, password change or expiry prompts, referrals, several directories, unlinking an account. OIDC/OAuth
single sign-on is a separate feature. The 15-minute interval is fixed.
