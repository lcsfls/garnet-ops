/**
 * The pipeline step that asks GarnetOps for a gate result (ADR 0008), and a whole workflow file around it. Forgejo Actions,
 * Gitea Actions and GitHub Actions share this syntax, and all three read `.github/workflows/`.
 */

/** The pipeline step to copy, with the server's own address. */
export function pipelineStep(origin: string): string {
  return `- name: GarnetOps quality gate
  env:
    GARNETOPS_URL: ${origin}
    GARNETOPS_TOKEN: \${{ secrets.GARNETOPS_TOKEN }}
    REF: refs/pull/\${{ github.event.number }}/head
    SHA: \${{ github.event.pull_request.head.sha }}
  run: |
    auth="Authorization: Bearer $GARNETOPS_TOKEN"
    id=$(curl -fsS -X POST "$GARNETOPS_URL/api/v1/gate/checks" -H "$auth" \\
      -H "Content-Type: application/json" -d "{\\"ref\\":\\"$REF\\",\\"sha\\":\\"$SHA\\"}" | jq -r .id)
    while :; do
      r=$(curl -fsS "$GARNETOPS_URL/api/v1/gate/checks/$id" -H "$auth")
      case $(echo "$r" | jq -r .state) in queued|running) sleep 10 ;; *) break ;; esac
    done
    echo "$r" | jq .
    [ "$(echo "$r" | jq -r .state)" = succeeded ] && [ "$(echo "$r" | jq -r .result)" != blocked ]`;
}

/** Where the workflow file goes; Gitea and Forgejo read this folder as well. */
export const WORKFLOW_PATH = ".github/workflows/garnetops-gate.yml";

/** A complete workflow: on every pull request, one job with the gate step. */
export function workflowFile(origin: string): string {
  const step = pipelineStep(origin)
    .split("\n")
    .map((line) => `      ${line}`)
    .join("\n");
  return `name: GarnetOps quality gate
on:
  pull_request:
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
${step}
`;
}
