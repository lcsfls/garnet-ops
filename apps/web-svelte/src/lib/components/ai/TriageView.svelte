<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { safeLink } from "../../markdown.ts";
  import type { TriageResult } from "../../types.ts";

  /** The facts of a finished triage, as plain text only. */
  let { result }: { result: TriageResult } = $props();
  const links = $derived(result.references.map(safeLink).filter((l): l is NonNullable<typeof l> => l !== null));
</script>

{#snippet fact(label: string, value: string)}
  <div class="bg-card px-2 py-2">
    <dt class="text-[13px] text-muted-foreground">{label}</dt>
    <dd class="font-semibold">{value}</dd>
  </div>
{/snippet}

<div class="grid gap-3">
  <dl class="grid grid-cols-3 gap-px overflow-hidden rounded-lg border bg-border text-center">
    {@render fact(t("ai.exploitability"), t(`ai.value.${result.exploitability}`))}
    {@render fact(t("ai.reachable"), t(`ai.value.${result.reachable}`))}
    {@render fact(t("ai.confidence"), t(`ai.value.${result.confidence}`))}
  </dl>
  <div>
    <h3 class="mb-0.5 text-sm font-medium">{t("ai.summary")}</h3>
    <p class="break-words whitespace-pre-line">{result.summary}</p>
  </div>
  {#if result.recommendation}
    <div>
      <h3 class="mb-0.5 text-sm font-medium">{t("ai.recommendation")}</h3>
      <p class="break-words whitespace-pre-line">{result.recommendation}</p>
    </div>
  {/if}
  {#if result.upgradeTo}
    <p class="text-sm">
      <span class="font-medium">{`${t("ai.upgradeTo")}: `}</span>
      <code class="rounded bg-muted px-1 py-px font-mono">{result.upgradeTo}</code>
      <span class="block text-muted-foreground">{t("ai.upgradeHint")}</span>
    </p>
  {/if}
  {#if links.length > 0}
    <div>
      <h3 class="mb-0.5 text-sm font-medium">{t("ai.references")}</h3>
      <ul class="grid gap-0.5 text-sm">
        <!-- Unkeyed: the references are model output, and a duplicate key would stop the page. -->
        {#each links as link}
          <li>
            <a href={link.href} target="_blank" rel="noopener noreferrer nofollow" class="break-all text-primary-text hover:underline"
              >{link.href}</a
            >
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</div>
