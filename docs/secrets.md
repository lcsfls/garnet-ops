# Secrets in repositories

GarnetOps checks every scanned repository for keys, tokens, passwords and files that do not belong in a repository, and can
check its whole Git history too ([ADR 0049](adr/0049-secret-and-sensitive-file-scanning.md)). The menu shows it as **Secrets**,
beside Findings.

## What is checked

- **Every scan** checks the files of the scanned commit with [gitleaks](https://github.com/gitleaks/gitleaks) (MIT) and its
  default rules: cloud keys, forge and registry tokens, private keys, chat and payment tokens, and a few hundred more.
- **Files that never belong in a repository**, whatever they contain: `.env` files with values (templates such as
  `.env.example` are fine), SSH and PuTTY private key files, key stores (`.p12`, `.pfx`, `.jks`), `.git-credentials` and
  `.netrc`, `.npmrc` and `.pypirc` with credentials, container registry credentials, kubeconfig with credentials, Terraform
  state, database dumps and SQLite files, `.htpasswd`, `wp-config.php` with a database password, and personal AI agent settings
  (`.claude/settings.local.json`).
- **The Git history**, on request: **Check history now** on the repository page (at most once an hour), or switched on for every
  scan in the repository's **Secrets** card (admins, or the owner of a private repository). A history check clones every commit
  instead of one, so it takes longer.
- Pull request checks of the CI gate look at the files of the checked commit, for the gate rule below; they never change
  findings.

GarnetOps always uses its own configuration. A repository's `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments
are ignored: whoever can commit could otherwise hide a secret from the check. A false positive is closed in GarnetOps instead.

## What GarnetOps keeps

Never the value. The scanner replaces it by its SHA-256 before the worker sees it, and GarnetOps stores only an HMAC of that
with your organisation's own key, sealed in the vault: enough to tell the same secret again, not enough to check a guess. Stored
are the rule, the severity, the paths and lines, and for the history the commit and its date. Not the matched line, not the
commit's author.

The same secret in several files is one entry with several places: you rotate it once.

## Severities

Fixed per rule: **critical** for access to infrastructure, code or the supply chain (private keys, cloud providers, forges,
package registries, secret managers, Kubernetes, CI); **high** for other service credentials and most of the files above;
**medium** for rules that guess by shape (`generic-api-key`, JWTs) and database files; **low** for identifiers that are public by
design (client ids, publishable keys).

## What to do

1. **Rotate it first**: revoke it where it was issued and create a new one. Deleting the file does not make it safe; the value
   is in the history and in every clone.
2. Remove it from the files and keep the new one outside the repository, for example in your CI's secret store.
3. If the repository is public or shared, remove it from the history as well (`git filter-repo`) and ask everyone to clone again.

Then mark it **revoked** (with a reason). A secret that is not one (a test value, an example, a public key) is marked **Not a
secret**. Both need a reason of at least 10 characters, are in the audit log, and stay closed if the same value turns up again.
Members and above can do it; a scan never closes a secret, and one that is no longer in the files stays open with "Only in the
history now".

## Ignore rules

Where a repository holds test fixtures or examples, an admin can set them aside with an **ignore rule** on the Secrets page, or
with **Ignore similar** on a secret: a path pattern (`test/fixtures/**`, `**/*.example.env`), a rule (`generic-api-key`) or
both, for one repository or all, with a reason. Making or removing one needs a recent sign-in and is in the audit log.

A secret is set aside only when every place it is known at matches the rule; the same value anywhere else still counts. Set aside
means it is not counted, not in the gate rule or the notifications, but listed under **Ignored** with the rule. Each rule shows how
many secrets it sets aside, and removing it brings them back at once. A pattern that matches everything (`**`) is refused. Rules
live in GarnetOps only: a repository's own `.gitleaksignore` is still ignored.

## Gate rule and notifications

- The quality gate rule **Secret in the code** counts open critical and high secrets in the checked commit. It is **Off** until
  an admin sets it to Report or Block ([quality-gates.md](quality-gates.md)).
- The notification **New secrets** tells channels (once ticked) and people (in the app by default) how many new secrets a scan
  found, by severity; never a path or a rule ([notifications.md](notifications.md)).

## Not checked

Secrets in container images, personal data and internal addresses. Secret findings are never sent to the AI, and are not part of
the dependency counts, grades, exports or reports.

## API

`GET /api/v1/secrets` (`state`, `severity`, `repositoryId`), `GET /api/v1/secrets/counts`, `GET /api/v1/secrets/{id}`,
`POST /api/v1/secrets/{id}/revoke|dismiss` with `{ "reason" }`, `POST /api/v1/secrets/{id}/reopen`;
`GET /api/v1/repositories/{id}/secrets`, `PUT /api/v1/repositories/{id}/secrets/history` with `{ "enabled" }`,
`POST /api/v1/repositories/{id}/secrets/history-check`; `GET /api/v1/secrets/ignore-rules`,
`POST /api/v1/secrets/ignore-rules` with `{ "pathPattern", "ruleId", "repositoryId", "reason" }` (admins, recent sign-in),
`DELETE /api/v1/secrets/ignore-rules/{id}`. `state=ignored` lists what the rules set aside; `GET /api/v1/secrets/counts` gains
`states.ignored`.
