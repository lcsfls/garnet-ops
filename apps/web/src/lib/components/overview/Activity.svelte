<script lang="ts" module>
  import {
    ArrowUpCircle,
    CircleAlert,
    Clock,
    FolderMinus,
    FolderPlus,
    type LucideIcon,
    Moon,
    RotateCcw,
    ScanSearch,
    ShieldCheck,
  } from "@lucide/svelte";

  const ACTIVITY_ICON: Record<string, LucideIcon> = {
    scan: ScanSearch,
    gate: ShieldCheck,
    "repository.created": FolderPlus,
    "repository.deleted": FolderMinus,
    "finding.accepted": ShieldCheck,
    "finding.reopened": RotateCcw,
    "organization.scan_schedule_changed": Clock,
    "update.succeeded": ArrowUpCircle,
    "update.failed": CircleAlert,
    "schedule.run": Moon,
  };
  const SCAN_TRIGGERS = ["manual", "webhook", "schedule", "ci"] as const;
</script>

<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { ActivityItem, GateResult, ScanState } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import GateBadge from "../GateBadge.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import ScanStateBadge from "../ui/ScanStateBadge.svelte";

  /**
   * What happened recently (overview.ts, activity): scans, gate checks from pipelines and organisation events. Each row:
   * what kind of event, about what, its state as a pill (severity-meta: a finished scan is neutral, only a passed gate is
   * green) and when.
   */
  let { items }: { items: ActivityItem[] } = $props();

  const isScan = (item: ActivityItem) => item.kind === "scan" || item.kind === "gate";
  function scanLabel(item: ActivityItem): string {
    if (item.kind === "gate") return t("overview.activity.gate_ci");
    const trigger = (SCAN_TRIGGERS as readonly string[]).includes(item.trigger ?? "") ? item.trigger : "manual";
    return t(`overview.activity.scan_${trigger}` as MessageKey);
  }
</script>

<Card>
  <CardHeader title={t("overview.activityTitle")} description={t("overview.activityDescription")} />
  {#if items.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("overview.activityEmpty")}</p>
  {:else}
    <ul class="px-5 pb-3" data-testid="overview-activity">
      {#each items as item (`${item.kind}-${item.id ?? ""}-${item.at}`)}
        {@const Icon = ACTIVITY_ICON[item.kind] ?? Clock}
        <li class="flex items-center gap-2.5 border-t py-2.5 first:border-t-0" data-kind={item.kind}>
          <span class="grid size-7 flex-none place-items-center rounded-[7px] bg-muted">
            <Icon aria-hidden="true" class="size-3.5" />
          </span>
          <div class="min-w-0 flex-1">
            {#if isScan(item)}
              <div class="truncate">
                {scanLabel(item)}:
                {#if item.repositoryId && item.subject}
                  <RepositoryLink id={item.repositoryId} name={item.subject} class="font-medium" />
                {/if}
              </div>
              {#if item.kind === "scan" && item.status === "succeeded" && item.id && (item.added || item.resolved)}
                <a
                  href={href("/findings", { scanId: item.id, state: "all" })}
                  class="block truncate text-[13px] text-muted-foreground hover:underline"
                >
                  {t("overview.scanSummary", { added: item.added ?? 0, resolved: item.resolved ?? 0 })}
                </a>
              {:else if item.actorName}
                <div class="truncate text-[13px] text-muted-foreground">
                  {t("overview.activityBy", { name: item.actorName })}
                </div>
              {/if}
            {:else}
              <div class="truncate">
                {t(`overview.activity.${item.kind.replaceAll(".", "_")}` as MessageKey, {
                  subject: item.subject ?? "",
                  count: item.count ?? 0,
                })}
              </div>
              {#if item.actorName}
                <div class="truncate text-[13px] text-muted-foreground">
                  {t("overview.activityBy", { name: item.actorName })}
                </div>
              {/if}
            {/if}
          </div>
          {#if item.kind === "scan" && item.status}
            <ScanStateBadge state={item.status as ScanState} />
          {:else if item.kind === "gate" && item.status}
            <GateBadge result={item.status as GateResult} />
          {/if}
          <time
            datetime={item.at}
            title={formatDateTime(item.at)}
            class="dash-time flex-none text-[13px] whitespace-nowrap text-muted-foreground"
          >
            {formatRelative(item.at)}
          </time>
        </li>
      {/each}
    </ul>
  {/if}
</Card>
