<script lang="ts">
  import type { Snippet } from "svelte";
  import FieldShell from "./FieldShell.svelte";
  import type { ControlProps } from "./form-context.ts";

  /**
   * Label, hint and error around a control that is not a plain input (a select, a time picker with a button). The
   * control gets its id and descriptions as snippet argument:
   * `<FormField label="Zone">{#snippet children(c)}<Select {...c} />{/snippet}</FormField>`.
   */
  let {
    label,
    hint,
    error,
    id,
    children,
  }: { label: string; hint?: string; error?: string | null; id?: string; children: Snippet<[ControlProps]> } = $props();
  const generated = $props.id();
</script>

<FieldShell {label} {hint} {error} id={id ?? generated} control={children} />
