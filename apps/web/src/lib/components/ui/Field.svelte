<script lang="ts">
  import type { HTMLInputAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";
  import FieldShell from "./FieldShell.svelte";

  /** Label, input, hint and error wired together for screen readers. */
  let {
    label,
    hint,
    error,
    class: className,
    id,
    value = $bindable(),
    ref = $bindable(null),
    ...rest
  }: HTMLInputAttributes & {
    label: string;
    hint?: string;
    error?: string | null;
    ref?: HTMLInputElement | null;
  } = $props();
  const generated = $props.id();
</script>

<FieldShell {label} {hint} {error} id={id ?? generated}>
  {#snippet control(c)}
    <input
      bind:this={ref}
      bind:value
      {...c}
      class={cn(
        "h-10 w-full rounded-md border border-input bg-card px-3 text-base shadow-xs placeholder:text-muted-foreground aria-invalid:border-destructive disabled:opacity-50",
        className as string,
      )}
      {...rest}
    />
  {/snippet}
</FieldShell>
