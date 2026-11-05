<script lang="ts">
  import { Check } from "@lucide/svelte";
  import { cn } from "../../cn.ts";

  /**
   * The steps of a wizard as a numbered row: done ones with a check, the current one marked, the rest muted. The current step
   * is announced with aria-current; done steps say so in their label. Neutral (AGENTS.md rule 6): the current step has a heavier
   * ring and weight, never the brand colour.
   */
  let {
    steps,
    current,
    label,
    doneLabel,
  }: { steps: string[]; current: number; label: string; doneLabel: string } = $props();
</script>

<ol aria-label={label} class="flex flex-wrap items-center gap-x-2 gap-y-1">
  {#each steps as step, i (step)}
    {@const done = i < current}
    {@const now = i === current}
    <li class="flex items-center gap-2" aria-current={now ? "step" : undefined}>
      <span
        class={cn(
          "grid size-6 flex-none place-items-center rounded-full border text-xs font-semibold tabular-nums",
          done && "border-border bg-muted text-foreground",
          now && "border-2 border-foreground text-foreground",
          !done && !now && "text-muted-foreground",
        )}
      >
        {#if done}<Check aria-hidden="true" class="size-3.5" />{:else}{i + 1}{/if}
      </span>
      <span class={cn("text-sm", now ? "font-semibold text-foreground" : "text-muted-foreground")}>
        {step}{#if done}<span class="sr-only">, {doneLabel}</span>{/if}
      </span>
      {#if i < steps.length - 1}<span aria-hidden="true" class="h-px w-6 bg-border"></span>{/if}
    </li>
  {/each}
</ol>
