<script lang="ts">
  import type { Snippet } from "svelte";
  import { cn } from "../../cn.ts";
  import {
    FORM_ROW_STEPS,
    type FormColumns,
    type FormRowStep,
    formColumnTemplate,
  } from "../../form-layout.ts";
  import { setInFormRow } from "./form-context.ts";

  /**
   * Fields side by side. Every field spans three rows of this grid (label, control, note), so the labels sit on one
   * line, the controls on the next and the hints below, however long a label or hint is. Below `from` the fields stack.
   * Use it for every form row with more than one field; a single field needs no row.
   *
   * Each field's box is a subgrid of the row, which is why a plain `grid` per field (whose rows stretch to the tallest
   * neighbour) is not enough: it pushed the shorter field's control down.
   */
  let {
    columns = 2,
    from = "md",
    children,
  }: { columns?: FormColumns; from?: FormRowStep; children: Snippet } = $props();

  /** Container-query steps written out in full so Tailwind finds them; they refer to the row's own box. */
  const SIDE_BY_SIDE: Record<FormRowStep, string> = {
    sm: "@sm:grid-cols-(--form-columns)",
    md: "@md:grid-cols-(--form-columns)",
    lg: "@lg:grid-cols-(--form-columns)",
    xl: "@xl:grid-cols-(--form-columns)",
  };

  // svelte-ignore state_referenced_locally
  if (!FORM_ROW_STEPS.includes(from)) throw new RangeError(`Not a form row step: ${from}`);
  setInFormRow(true);
  // Set through the CSSOM (a `style:` directive), never as a style attribute: the CSP allows no inline styles.
  const template = $derived(formColumnTemplate(columns));
</script>

<!-- Each note row ends with the gap that separates bands of fields; the last one is taken back here. -->
<div class="@container -mb-4">
  <div data-form-row style:--form-columns={template} class={cn("grid grid-cols-1 gap-x-4", SIDE_BY_SIDE[from])}>
    {@render children()}
  </div>
</div>
