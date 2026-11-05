<script lang="ts">
  import { cn } from "../../cn.ts";
  import { t } from "../../i18n.svelte.ts";
  import { TONE_CLASSES } from "../../severity-meta.ts";
  import { daysUntil } from "../../websites.ts";

  /**
   * When a certificate ends: the days left, in the colour of the warning step (severity-meta.ts): ended is critical, a week
   * or less high, two weeks or less medium. A valid certificate is plain text, not green.
   */
  let { expires }: { expires: string | null } = $props();
  const days = $derived(daysUntil(expires));
  const tone = $derived(
    days === null || days > 30
      ? ""
      : days < 0
        ? cn("font-medium", TONE_CLASSES.critical.text)
        : days <= 7
          ? cn("font-medium", TONE_CLASSES.high.text)
          : days <= 14
            ? TONE_CLASSES.medium.text
            : "text-muted-foreground",
  );
</script>

{#if days === null}
  <span class="text-muted-foreground">–</span>
{:else}
  <span class={tone} title={expires ?? undefined}>
    {days < 0 ? t("websites.expiredDaysAgo", { days: -days }) : t("websites.expiresInDays", { days })}
  </span>
{/if}
