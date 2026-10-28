<script lang="ts">
  import type { HTMLInputAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";

  /** A native radio button styled to match Checkbox. */
  let {
    class: className,
    group = $bindable(),
    ...rest
  }: Omit<HTMLInputAttributes, "type"> & { group?: unknown } = $props();
</script>

<span class={cn("inline-grid size-4 flex-none place-items-center", className as string)}>
  {#if group === undefined}
    <input
      type="radio"
      class="peer col-start-1 row-start-1 size-4 appearance-none rounded-full border border-input bg-card shadow-xs checked:border-primary checked:bg-primary disabled:opacity-50"
      {...rest}
    />
  {:else}
    <input
      type="radio"
      bind:group
      class="peer col-start-1 row-start-1 size-4 appearance-none rounded-full border border-input bg-card shadow-xs checked:border-primary checked:bg-primary disabled:opacity-50"
      {...rest}
    />
  {/if}
  <span
    aria-hidden="true"
    class="pointer-events-none col-start-1 row-start-1 size-1.5 rounded-full bg-primary-foreground opacity-0 peer-checked:opacity-100"
  ></span>
</span>
