<script lang="ts">
  import type { Snippet } from "svelte";
  import type { GradeFields } from "../../types.ts";
  import { href } from "../../url.ts";
  import { gradeFindingFilter } from "./grade-badge.ts";

  /** Where the findings behind a grade are listed. */
  let {
    id,
    reason,
    class: className,
    children,
    label,
  }: {
    id: string;
    reason: NonNullable<GradeFields["gradeReason"]>;
    class?: string;
    children: Snippet;
    label?: string;
  } = $props();
  const filter = $derived(gradeFindingFilter(reason.rule));
</script>

{#if !filter}
  <span class={className}>{@render children()}</span>
{:else}
  <a href={href("/findings", { repositoryId: id, ...filter })} aria-label={label} class={className}
    >{@render children()}</a
  >
{/if}
