<script lang="ts">
  import { ArrowRight, CircleCheck } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import type { NextStep } from "../../reports.ts";

  /** What to do next, most urgent first: the same sentences as in the PDF. "Nothing urgent" is neutral, not green. */
  let { steps }: { steps: NextStep[] } = $props();
  const titleId = $props.id();
</script>

<section aria-labelledby={titleId}>
  <h3 id={titleId} class="mb-2 text-sm font-medium text-muted-foreground">{t("reports.nextTitle")}</h3>
  <ul class="grid gap-1.5" data-testid="report-next-steps">
    {#each steps as step (step.code)}
      <li class="flex items-start gap-2" data-step={step.code}>
        {#if step.code === "nothing"}
          <CircleCheck aria-hidden="true" class="mt-0.5 size-4 flex-none text-muted-foreground" />
        {:else}
          <ArrowRight aria-hidden="true" class="mt-0.5 size-4 flex-none text-muted-foreground" />
        {/if}
        <span>{t(`reports.next.${step.code}`, { count: step.count ?? 0 })}</span>
      </li>
    {/each}
  </ul>
</section>
