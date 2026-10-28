<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { GradeFields } from "../../types.ts";
  import { gradeFindingFilter } from "./grade-badge.ts";
  import { gradeLine } from "./grade-line.ts";
  import GradeLetter from "./GradeLetter.svelte";
  import GradeLink from "./GradeLink.svelte";

  /**
   * The grade of a repository in a list: the letter, and on hover or keyboard focus
   * the reason in plain words with a link to the findings behind it. Escape closes the note.
   * The grade is display only; the note says so. The note opens beside the letter, not under or
   * over it, so it never covers the column header or the letters of the other rows.
   */
  let { row, id }: { row: GradeFields; id: string } = $props();

  let open = $state(false);
  // Escape closes the note wherever the focus is, and it opens again on the next visit of the pointer or focus.
  $effect(() => {
    if (!open) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") open = false;
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  });

  const text = $derived(gradeLine(row));
  const notGraded = $derived(t("grades.notGradedRepository"));
  const stale = $derived(row.gradeStale ? t("grades.staleRepository") : null);
  const name = $derived(text ? [text, stale].filter(Boolean).join(". ") : notGraded);
  // A grade with findings behind it is a link to them; A and "not scanned" have nothing to link to.
  const linked = $derived(Boolean(row.grade && row.gradeReason && gradeFindingFilter(row.gradeReason.rule)));
</script>

<!-- The wrapper only listens to hover and focus for its note; the control inside is the link or the focusable placeholder. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<span
  class="relative inline-block"
  onmouseenter={() => (open = true)}
  onmouseleave={() => (open = false)}
  onfocusin={() => (open = true)}
  onfocusout={(event) => {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) open = false;
  }}
>
  {#if linked && row.grade && row.gradeReason}
    <GradeLink {id} reason={row.gradeReason} label={name} class="inline-flex rounded-md">
      <GradeLetter grade={row.grade} stale={row.gradeStale} />
    </GradeLink>
  {:else}
    <!-- A grade without findings behind it (A), or no grade yet, has nothing to open. It is a button so that keyboard
         and touch can show its note too. -->
    <button type="button" aria-label={name} onclick={() => (open = !open)} class="inline-flex rounded-md">
      {#if row.grade}
        <GradeLetter grade={row.grade} stale={row.gradeStale} />
      {:else}
        <span class="inline-flex h-7 min-w-7 items-center justify-center rounded-md text-muted-foreground">
          <span aria-hidden="true">–</span>
          <span class="sr-only">{t("grades.notGradedShort")}</span>
        </span>
      {/if}
    </button>
  {/if}
  {#if open}
    <!-- The click only keeps the row behind the note from opening. -->
    <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
    <span role="tooltip" class="absolute top-0 left-full z-30 pl-2" onclick={(event) => event.stopPropagation()}>
      <span
        class="block w-72 max-w-[min(18rem,80vw)] rounded-lg border bg-card p-3 text-sm font-normal text-card-foreground shadow-md"
      >
        <span class="block font-medium break-words">{text ?? notGraded}</span>
        {#if stale}<span class="mt-1 block text-muted-foreground">{stale}</span>{/if}
        {#if row.gradeReason && gradeFindingFilter(row.gradeReason.rule)}
          <GradeLink
            {id}
            reason={row.gradeReason}
            class="mt-1.5 inline-block text-primary-text underline-offset-2 hover:underline"
          >
            {t("grades.show")}
          </GradeLink>
        {/if}
        <span class="mt-1.5 block text-muted-foreground">{t("grades.displayOnly")}</span>
      </span>
    </span>
  {/if}
</span>
