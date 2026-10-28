<script lang="ts" module>
  /** The pipeline step to copy, with the server's own address. */
  function pipelineStep(origin: string) {
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

  const GATES_DOCS = "https://github.com/lcsfls/garnet-ops/blob/main/docs/quality-gates.md";
</script>

<script lang="ts">
  import { ExternalLink, KeyRound } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Page, RepositoryRow } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Select from "../ui/Select.svelte";
  import GateTokens from "./GateTokens.svelte";

  /** How a pipeline asks for a gate result (ADR 0008), and the tokens it uses. */
  let {
    admin,
    repositoryId,
    onRepository,
  }: { admin: boolean; repositoryId: string | undefined; onRepository: (id: string | undefined) => void } = $props();

  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
  const step = pipelineStep(window.location.origin);
</script>

<Card>
  <CardHeader title={t("gates.pipelineTitle")} description={t("gates.pipelineDescription")} />
  <div class="grid gap-4 px-5 pb-5">
    <pre class="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed"><code
        >{step}</code
      ></pre>
    <div class="flex flex-wrap items-center gap-3">
      <CopyButton text={step} />
      <a
        href={GATES_DOCS}
        target="_blank"
        rel="noopener noreferrer"
        class="inline-flex items-center gap-1.5 text-sm text-primary-text underline-offset-4 hover:underline"
      >
        {t("gates.pipelineDocs")}
        <ExternalLink aria-hidden="true" class="size-3.5" />
      </a>
    </div>
    <p class="text-sm text-muted-foreground">{t("gates.pipelineHint")}</p>

    <section aria-labelledby="gate-tokens" class="grid gap-3 border-t pt-4">
      <h3 id="gate-tokens" class="flex items-center gap-2 font-medium">
        <KeyRound aria-hidden="true" class="size-4" />
        {t("gates.tokensTitle")}
      </h3>
      {#if admin}
        <Select
          aria-label={t("gates.repository")}
          value={repositoryId ?? ""}
          onchange={(e) => onRepository(e.currentTarget.value || undefined)}
        >
          <option value="">{t("gates.chooseRepository")}</option>
          {#each repositories.data?.items ?? [] as r (r.id)}
            <option value={r.id}>{r.name}</option>
          {/each}
        </Select>
        {#if repositoryId}
          {#key repositoryId}
            <GateTokens {repositoryId} />
          {/key}
        {/if}
      {:else}
        <p class="text-sm text-muted-foreground">{t("gates.adminOnly")}</p>
      {/if}
    </section>
  </div>
</Card>
