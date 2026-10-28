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
    ShieldCheck,
  } from "@lucide/svelte";

  const ACTIVITY_ICON: Record<string, LucideIcon> = {
    "repository.created": FolderPlus,
    "repository.deleted": FolderMinus,
    "finding.accepted": ShieldCheck,
    "finding.reopened": RotateCcw,
    "organization.scan_schedule_changed": Clock,
    "update.succeeded": ArrowUpCircle,
    "update.failed": CircleAlert,
    "schedule.run": Moon,
  };
</script>

<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { ActivityItem } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";

  /** Recent organisation events (mockup "Activity"): icon chip, one line, when. */
  let { items }: { items: ActivityItem[] } = $props();
</script>

<Card class="h-full">
  <CardHeader title={t("overview.activityTitle")} description={t("overview.activityDescription")} />
  {#if items.length === 0}
    <p class="px-5 pb-6 text-muted-foreground">{t("overview.activityEmpty")}</p>
  {:else}
    <ul class="px-5 pb-3">
      {#each items as item (`${item.kind}-${item.at}`)}
        {@const Icon = ACTIVITY_ICON[item.kind] ?? Clock}
        {@const key = item.kind.replaceAll(".", "_")}
        <li class="flex items-center gap-2.5 border-t py-2.5 first:border-t-0">
          <span class="grid size-7 flex-none place-items-center rounded-[7px] bg-muted">
            <Icon aria-hidden="true" class="size-3.5" />
          </span>
          <div class="min-w-0 flex-1">
            <div class="truncate">
              {t(`overview.activity.${key}` as MessageKey, {
                subject: item.subject ?? "",
                count: item.count ?? 0,
              })}
            </div>
            {#if item.actorName}
              <div class="truncate text-[13px] text-muted-foreground">
                {t("overview.activityBy", { name: item.actorName })}
              </div>
            {/if}
          </div>
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
