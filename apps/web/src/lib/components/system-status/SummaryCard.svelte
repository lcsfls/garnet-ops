<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  /** The overall state and when it was checked. The page looks again every minute by itself, so it has no refresh button. */
  let { status }: { status: SystemStatus } = $props();

  const level = $derived(status.overall.level);
  const text = $derived.by(() => {
    const { attention, failed } = status.overall;
    return level === "ok"
      ? t("systemStatus.summary.ok")
      : failed > 0 && attention > 0
        ? t("systemStatus.summary.both", { failed, attention })
        : failed > 0
          ? t("systemStatus.summary.failed", { count: failed })
          : t("systemStatus.summary.attention", { count: attention });
  });
</script>

<Card class="mb-4">
  <div class="flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4" data-testid="system-summary">
    <StatusBadge {level}>{t(`systemStatus.level.${level}`)}</StatusBadge>
    <div class="min-w-0 flex-[1_1_16rem]">
      <p class="font-medium" data-testid="system-summary-text">
        {text}
      </p>
      <p class="text-sm text-muted-foreground">
        {t("systemStatus.summary.checked", { when: formatRelative(status.generatedAt) })}
        <span>{t("systemStatus.legend")}</span>
      </p>
    </div>
  </div>
</Card>
