<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import { type ControlProps, hasFormRow, inFormRow } from "./form-context.ts";

  /** Label, control, hint and error. In a FormRow the three parts take the row's shared rows. */
  let {
    label,
    hint,
    error,
    id,
    control,
  }: {
    label: string;
    hint?: string | undefined;
    error?: string | null | undefined;
    id: string;
    control: Snippet<[ControlProps]>;
  } = $props();

  const inRow = hasFormRow() && inFormRow();
  const hintId = $derived(hint ? `${id}-hint` : undefined);
  const errorId = $derived(error ? `${id}-error` : undefined);
  const controlProps: ControlProps = $derived({
    id,
    "aria-describedby": [hintId, errorId].filter(Boolean).join(" ") || undefined,
    "aria-invalid": error ? true : undefined,
  });
</script>

{#snippet notes()}
  {#if hint}<p id={hintId} class={cn("text-sm text-muted-foreground", inRow && "pt-1.5")}>{hint}</p>{/if}
  {#if error}<p id={errorId} class={cn("text-sm text-destructive-text", inRow && "pt-1.5")}>{error}</p>{/if}
{/snippet}

{#if !inRow}
  <div class="grid gap-1.5">
    <label for={id} class="text-sm font-medium">{label}</label>
    <div class="grid" data-field-control>{@render control(controlProps)}</div>
    {@render notes()}
  </div>
{:else}
  <div class="row-span-3 grid grid-rows-subgrid">
    <label for={id} data-field-label class="pb-1.5 text-sm font-medium">{label}</label>
    <div class="grid content-start" data-field-control>{@render control(controlProps)}</div>
    <div class="pb-4" data-field-note>{@render notes()}</div>
  </div>
{/if}
