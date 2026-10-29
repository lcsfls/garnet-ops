<script lang="ts" module>
  import type { Snippet } from "svelte";

  /**
   * One row of facts: a muted label and the value as text (monospace for records and addresses), as a list, or as markup a
   * snippet renders. `note` adds a muted line under the text.
   */
  export interface Fact {
    label: string;
    text?: string | null;
    mono?: boolean;
    note?: string | null;
    list?: string[];
    value?: Snippet;
  }
</script>

<script lang="ts">
  /** A two-column list of facts. A row without a value shows a dash. */
  let { rows }: { rows: Fact[] } = $props();
</script>

{#snippet dash()}<span class="text-muted-foreground">–</span>{/snippet}

<dl class="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-5 gap-y-2 px-5 pb-5 text-sm">
  {#each rows as row (row.label)}
    <div class="contents">
      <dt class="text-muted-foreground">{row.label}</dt>
      <dd class="min-w-0 break-words">
        {#if row.value}
          {@render row.value()}
        {:else if row.list}
          {#if row.list.length === 0}
            {@render dash()}
          {:else}
            <ul class="grid gap-0.5">
              {#each row.list as item, i (i)}<li class="font-mono break-all">{item}</li>{/each}
            </ul>
          {/if}
        {:else if row.text}
          <span class={row.mono ? "font-mono break-all" : undefined}>{row.text}</span>
          {#if row.note}<span class="block text-muted-foreground">{row.note}</span>{/if}
        {:else}
          {@render dash()}
        {/if}
      </dd>
    </div>
  {/each}
</dl>
