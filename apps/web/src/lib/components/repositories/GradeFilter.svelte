<script lang="ts">
  import { GRADE_FILTER_VALUES, GRADES } from "@garnetops/core/grades";
  import { t } from "../../i18n.svelte.ts";
  import type { Grade } from "../../types.ts";
  import Select from "../ui/Select.svelte";

  /** A grade filter for a list header; the counts are those of the whole list. */
  let {
    value,
    counts,
    onChange,
  }: {
    value: Grade | "none" | undefined;
    counts: Record<Grade | "none", number> | undefined;
    onChange: (value: Grade | "none" | undefined) => void;
  } = $props();
  const count = (key: Grade | "none") => (counts ? String(counts[key]) : "–");
  const worstFirst = [...GRADES].reverse();
</script>

<Select
  class="min-w-44"
  aria-label={t("grades.filterLabel")}
  value={value ?? ""}
  onchange={(event) => {
    const next = event.currentTarget.value;
    onChange((GRADE_FILTER_VALUES as readonly string[]).includes(next) ? (next as Grade | "none") : undefined);
  }}
>
  <option value="">{t("grades.filterAll")}</option>
  {#each worstFirst as grade (grade)}
    <option value={grade}>{t("grades.filterOption", { grade, count: count(grade) })}</option>
  {/each}
  <option value="none">{t("grades.filterNone", { count: count("none") })}</option>
</Select>
