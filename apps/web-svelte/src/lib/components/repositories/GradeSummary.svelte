<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { GradeFields } from "../../types.ts";
  import GradeLetter from "./GradeLetter.svelte";
  import GradeLink from "./GradeLink.svelte";
  import { gradeFindingFilter } from "./grade-badge.ts";
  import { gradeLine } from "./grade-line.ts";

  /** The grade under the title of a repository page: letter, reason and link. */
  let { row, id }: { row: GradeFields; id: string } = $props();
  const text = $derived(gradeLine(row));
  const stale = $derived(row.gradeStale ? t("grades.staleRepository") : null);
</script>

<div class="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1" data-testid="grade-summary">
  <span class="text-sm text-muted-foreground">{t("grades.detailLabel")}</span>
  {#if row.grade && row.gradeReason}
    <GradeLetter grade={row.grade} stale={row.gradeStale} large />
    <span class="min-w-0 break-words">{text}</span>
    {#if gradeFindingFilter(row.gradeReason.rule)}
      <GradeLink {id} reason={row.gradeReason} class="text-sm text-primary-text underline-offset-2 hover:underline">
        {t("grades.show")}
      </GradeLink>
    {/if}
  {:else}
    <span class="text-muted-foreground">{t("grades.notGradedRepository")}</span>
  {/if}
  {#if stale}<span class="basis-full text-sm text-muted-foreground">{stale}</span>{/if}
</div>
