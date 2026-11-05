<script lang="ts">
  import { Check } from "@lucide/svelte";
  import type { HTMLInputAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";

  /**
   * A native checkbox with the look of the inputs: same corner radius checked or not, and our own check mark.
   * Keyboard, labels and screen readers behave as with any checkbox, because it is one. Checked is the text colour, not
   * the brand colour (AGENTS.md rule 6).
   */
  let { class: className, checked = $bindable(false), ...rest }: Omit<HTMLInputAttributes, "type"> = $props();
</script>

<span class={cn("inline-grid size-4 flex-none place-items-center", className as string)}>
  <input
    type="checkbox"
    bind:checked
    class="peer col-start-1 row-start-1 size-4 appearance-none rounded-[4px] border border-input bg-card shadow-xs checked:border-foreground checked:bg-foreground disabled:opacity-50"
    {...rest}
  />
  <Check
    aria-hidden="true"
    strokeWidth={3}
    class="pointer-events-none col-start-1 row-start-1 size-3 text-background opacity-0 peer-checked:opacity-100"
  />
</span>
