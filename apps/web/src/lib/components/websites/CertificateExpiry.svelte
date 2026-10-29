<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { daysUntil } from "../../websites.ts";

  /** When a certificate ends: the days left, in the colour of the warning step. A valid certificate is plain text, not green. */
  let { expires }: { expires: string | null } = $props();
  const days = $derived(daysUntil(expires));
  const tone = $derived(
    days === null || days > 30
      ? ""
      : days <= 7
        ? "font-medium text-high-text"
        : days <= 14
          ? "text-warning-text"
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
