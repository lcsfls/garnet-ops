<script lang="ts">
  import { ChevronDown } from "@lucide/svelte";
  import type { HTMLSelectAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";

  /**
   * Native select with the look of the inputs and our own chevron. The open option list stays the operating system's,
   * which keeps keyboard, touch and screen-reader behaviour reliable.
   */
  let { class: className, value = $bindable(), children, ...rest }: HTMLSelectAttributes = $props();
</script>

<span class={cn("relative inline-flex h-10 text-base", className as string)}>
  <select
    bind:value
    class="h-full w-full appearance-none truncate rounded-md border border-input bg-card py-0 pr-9 pl-3 text-[length:inherit] shadow-xs hover:bg-accent"
    {...rest}
  >
    {@render children?.()}
  </select>
  <ChevronDown
    aria-hidden="true"
    class="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted-foreground"
  />
</span>
