<script lang="ts">
  import { GRADES } from "@garnetops/core/grades";
  import { t } from "../../i18n.svelte.ts";
  import GradeLetter from "./GradeLetter.svelte";

  /** What the grades mean, one click away; the same on the repositories list. */
  const worstFirst = [...GRADES].reverse();
</script>

<details class="group mb-4 text-sm text-muted-foreground">
  <summary class="cursor-pointer rounded-sm hover:text-foreground">{t("grades.helpSummary")}</summary>
  <div class="mt-2 max-w-3xl rounded-lg border bg-card p-4 text-card-foreground">
    <p>{t("grades.helpIntro")}</p>
    <ul class="mt-3 grid gap-1.5">
      {#each worstFirst as grade (grade)}
        <li class="flex items-center gap-3">
          <GradeLetter {grade} />
          <span>{t(`grades.helpRule.${grade}`)}</span>
        </li>
      {/each}
    </ul>
    <p class="mt-3 text-muted-foreground">{t("grades.helpOutro")}</p>
  </div>
</details>
