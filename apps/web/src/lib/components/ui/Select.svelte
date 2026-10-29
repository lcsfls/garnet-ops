<script lang="ts">
  import { ChevronDown } from "@lucide/svelte";
  import type { HTMLSelectAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";

  /**
   * Native select with the look of the inputs and our own chevron. Where the browser supports customisable selects the open
   * list is styled too (app.css, .ui-select); it stays a native select either way, which keeps keyboard, touch and
   * screen-reader behaviour reliable.
   */
  let { class: className, value = $bindable(), children, ...rest }: HTMLSelectAttributes = $props();
</script>

<span class={cn("relative inline-flex h-10 text-base", className as string)}>
  <select
    bind:value
    class="ui-select peer h-full w-full truncate rounded-md border border-input bg-card py-0 pr-9 pl-3 text-[length:inherit] shadow-xs hover:bg-accent"
    {...rest}
  >
    {@render children?.()}
  </select>
  <ChevronDown
    aria-hidden="true"
    class="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted-foreground transition-transform duration-150 peer-open:rotate-180"
  />
</span>
