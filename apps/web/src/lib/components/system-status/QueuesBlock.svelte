<script lang="ts">
  import type { QueueStatus, SystemStatus } from "@garnetops/core/system-status-view";
  import { formatDuration, formatNumber } from "../../format.ts";
  import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";
  import { queueKey } from "../../system-status.ts";
  import StatusBadge from "./StatusBadge.svelte";

  /** Queues with something waiting, running or failing first; the idle ones sit behind a click (progressive disclosure). */
  let { queues }: { queues: SystemStatus["worker"]["queues"] } = $props();

  const busy = $derived(queues.items.filter((q) => q.queued > 0 || q.active > 0 || q.failed24h > 0));
  const idle = $derived(queues.items.filter((q) => !busy.includes(q)));

  function label(name: string): string {
    const key = `systemStatus.worker.queueName.${queueKey(name)}`;
    return hasKey(key) ? t(key as MessageKey) : name;
  }
</script>

{#snippet oldest(q: QueueStatus)}
  {#if q.oldestQueuedSeconds === null}
    –
  {:else if q.level === "attention" && q.failed24h === 0}
    <StatusBadge level="attention">{formatDuration(q.oldestQueuedSeconds)}</StatusBadge>
  {:else}
    {formatDuration(q.oldestQueuedSeconds)}
  {/if}
{/snippet}

{#snippet failed(q: QueueStatus)}
  {#if q.failed24h > 0}
    <StatusBadge level="attention">{formatNumber(q.failed24h)}</StatusBadge>
  {:else}
    {formatNumber(0)}
  {/if}
{/snippet}

{#snippet queueTable(items: QueueStatus[])}
  <!-- Narrow content area: one block per queue, the figures on a line of their own. -->
  <ul class="@3xl:hidden">
    {#each items as q (q.name)}
      <li class="border-t py-1.5 text-sm [overflow-wrap:anywhere]" data-testid="queue-item-{q.name}">
        <div class="font-medium" title={q.name}>
          {label(q.name)}
        </div>
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground tabular-nums">
          <span>{t("systemStatus.worker.queued")}: {formatNumber(q.queued)}</span>
          <span>{t("systemStatus.worker.active")}: {formatNumber(q.active)}</span>
          <span class="inline-flex items-center gap-1">{t("systemStatus.worker.failed24h")}: {@render failed(q)}</span>
          <span class="inline-flex items-center gap-1">{t("systemStatus.worker.oldest")}: {@render oldest(q)}</span>
        </div>
      </li>
    {/each}
  </ul>
  <table class="hidden w-full text-left text-sm @3xl:table">
    <thead class="text-muted-foreground">
      <tr>
        <th class="py-1 pr-3 font-medium">{t("systemStatus.worker.queue")}</th>
        <th class="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.queued")}</th>
        <th class="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.active")}</th>
        <th class="py-1 pr-3 text-right font-medium">{t("systemStatus.worker.failed24h")}</th>
        <th class="py-1 text-right font-medium">{t("systemStatus.worker.oldest")}</th>
      </tr>
    </thead>
    <tbody>
      {#each items as q (q.name)}
        <tr class="border-t align-top" data-testid="queue-{q.name}">
          <td class="py-1 pr-3 [overflow-wrap:anywhere]" title={q.name}>
            {label(q.name)}
          </td>
          <td class="py-1 pr-3 text-right tabular-nums">{formatNumber(q.queued)}</td>
          <td class="py-1 pr-3 text-right tabular-nums">{formatNumber(q.active)}</td>
          <td class="py-1 pr-3 text-right tabular-nums">{@render failed(q)}</td>
          <td class="py-1 text-right tabular-nums">{@render oldest(q)}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/snippet}

<div class="border-t px-5 py-3" data-testid="worker-queues">
  <div class="mb-1.5 flex flex-wrap items-center justify-between gap-2">
    <h3 class="text-sm font-medium">{t("systemStatus.worker.queues")}</h3>
    {#if !queues.available}
      <StatusBadge level="attention">{t("systemStatus.level.attention")}</StatusBadge>
    {/if}
  </div>
  {#if !queues.available}
    <p class="text-sm text-muted-foreground">{t("systemStatus.worker.queuesUnavailable")}</p>
  {:else if queues.items.length === 0}
    <p class="text-sm text-muted-foreground">{t("systemStatus.worker.noQueues")}</p>
  {:else}
    {#if busy.length > 0}
      {@render queueTable(busy)}
    {:else}
      <p class="text-sm text-muted-foreground">{t("systemStatus.worker.queuesIdle")}</p>
    {/if}
    {#if idle.length > 0}
      <details class="mt-2" data-testid="worker-idle-queues">
        <summary class="cursor-pointer text-sm text-primary-text underline-offset-4 hover:underline">
          {t("systemStatus.worker.showIdle", { count: idle.length })}
        </summary>
        <div class="mt-1.5">
          {@render queueTable(idle)}
        </div>
      </details>
    {/if}
  {/if}
</div>
