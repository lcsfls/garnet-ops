<script lang="ts">
  import type { HTMLTextareaAttributes } from "svelte/elements";
  import { cn } from "../../cn.ts";
  import FieldShell from "./FieldShell.svelte";

  /** Field for several lines, wired like Field. */
  let {
    label,
    hint,
    error,
    class: className,
    id,
    value = $bindable(),
    ...rest
  }: HTMLTextareaAttributes & { label: string; hint?: string; error?: string | null } = $props();
  const generated = $props.id();
</script>

<FieldShell {label} {hint} {error} id={id ?? generated}>
  {#snippet control(c)}
    <textarea
      bind:value
      {...c}
      class={cn(
        "min-h-24 w-full rounded-md border border-input bg-card px-3 py-2 text-base shadow-xs placeholder:text-muted-foreground aria-invalid:border-destructive",
        className as string,
      )}
      {...rest}
    ></textarea>
  {/snippet}
</FieldShell>
