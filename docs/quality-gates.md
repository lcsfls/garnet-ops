# Quality gates

A quality gate decides whether a pipeline may pass. GarnetOps evaluates it after every
scan and on request from your CI (ADR 0008).

## Rules

| Rule | Matches | Default |
| --- | --- | --- |
| Critical vulnerability with a fix | critical, or CVSS 9.0 or more, and a fixed version exists | Report |
| Known exploited vulnerability | listed in the CISA KEV catalogue | Report |
| High vulnerability with a fix | high, and a fixed version exists | Report |
| Licence not allowed | a package uses only licences from your deny list (SPDX ids) | Off |

Each rule is **Off**, **Report** (shown, never fails a pipeline) or **Block** (fails the
pipeline). Owners and admins set the modes under **Code → Quality gates**; every change is
in the audit log and counts from the next run on. Accepted risks never count.

**Nothing blocks by itself.** New rules arrive as Off or Report, and an update never
changes a mode you chose.

The grades A to F on the repositories list ([grades.md](grades.md)) are display
only. They are not an input to a gate, and a gate result never depends on one.

The result of a run is **Passed** (no rule matched), **With notes** (only Report rules
matched) or **Blocked** (a Block rule matched).

## Add the gate to a pipeline

1. Under **Code → Quality gates → Add to your pipeline**, choose the repository and create
   a gate token. Copy it right away: it is shown once.
2. Store it in your forge as the CI secret `GARNETOPS_TOKEN`.
3. Add this step to the workflow that runs on pull requests (Forgejo Actions, Gitea
   Actions and GitHub Actions use the same syntax; the runner needs `curl` and `jq`):

```yaml
- name: GarnetOps quality gate
  env:
    GARNETOPS_URL: https://garnetops.example.com
    GARNETOPS_TOKEN: ${{ secrets.GARNETOPS_TOKEN }}
    REF: refs/pull/${{ github.event.number }}/head
    SHA: ${{ github.event.pull_request.head.sha }}
  run: |
    auth="Authorization: Bearer $GARNETOPS_TOKEN"
    id=$(curl -fsS -X POST "$GARNETOPS_URL/api/v1/gate/checks" -H "$auth" \
      -H "Content-Type: application/json" -d "{\"ref\":\"$REF\",\"sha\":\"$SHA\"}" | jq -r .id)
    while :; do
      r=$(curl -fsS "$GARNETOPS_URL/api/v1/gate/checks/$id" -H "$auth")
      case $(echo "$r" | jq -r .state) in queued|running) sleep 10 ;; *) break ;; esac
    done
    echo "$r" | jq .
    [ "$(echo "$r" | jq -r .state)" = succeeded ] && [ "$(echo "$r" | jq -r .result)" != blocked ]
```

The step fails when a Block rule matches, when the scan fails, and when GarnetOps cannot
be reached (it fails closed). The pull request shows it as a status check; GarnetOps needs
no write access to your forge.

If GarnetOps uses its own certificate authority (`GARNETOPS_TLS=internal`), give the runner
its root certificate (`curl --cacert root.crt …`) or use a certificate the runner trusts.

## What a check does

- `POST /api/v1/gate/checks` with `ref` (a branch, tag or pull request ref such as
  `refs/pull/12/head`) and `sha` (the full commit id) queues a scan of exactly that commit.
  Without `ref`, the repository's configured branch is scanned. A check already waiting
  for the same ref and commit is reused.
- A check of another ref never changes the repository's findings or package inventory,
  which describe its configured branch. It only records its gate result.
- If the fetched ref points to another commit than `sha`, the check fails.
- `GET /api/v1/gate/checks/{id}` answers `queued`, `running`, `succeeded` or `failed`, and
  for a finished check the result with the rule names and counts. It never lists
  vulnerabilities, packages or code: pipeline logs of public projects are public.

## Gate tokens

- One token belongs to one repository. It can request a check of that repository and read
  the result, nothing else: no findings, no packages, no other repository.
- GarnetOps stores only a SHA-256 hash of it. Lost tokens are revoked and replaced.
- Each token may make 30 requests a minute.
- Creating, using and revoking a token is in the audit log.
