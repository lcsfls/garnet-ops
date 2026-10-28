<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { RefreshCw } from "@lucide/svelte";
  import { cn } from "../../cn.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import Button from "../ui/Button.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  let {
    status,
    fetching,
    onRefresh,
  }: {
    status: SystemStatus;
    fetching: boolean;
    onRefresh: () => void;
  } = $props();

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
    <Button variant="outline" class="h-9 px-3" disabled={fetching} onclick={onRefresh}>
      <RefreshCw aria-hidden="true" class={cn("size-4", fetching && "motion-safe:animate-spin")} />
      {fetching ? t("systemStatus.summary.refreshing") : t("systemStatus.summary.refresh")}
    </Button>
  </div>
</Card>
