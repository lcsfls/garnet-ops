<script lang="ts">
  import { UPTIME_INTERVALS, UPTIME_SLOW_MS, type UptimeError } from "@garnetops/core/uptime";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import Select from "../ui/Select.svelte";
  import Facts, { type Fact } from "./Facts.svelte";

  /**
   * Availability (ADR 0040): whether the site answers, how fast, and its outages. Off until an admin switches it on for the asset;
   * a site is down after three failed checks in a row. Up is not proof of anything, so it is plain text; down is a problem.
   */
  let {
    detail,
    canEdit,
    class: className = "",
  }: { detail: ExposureDetail; canEdit: boolean; class?: string } = $props();
  const queryClient = useQueryClient();
  const u = $derived(detail.uptime);
  const av = $derived(detail.availability);
  let interval = $state<string>("");

  const save = createMutation(() => ({
    mutationFn: (body: { enabled: boolean; intervalMinutes?: number }) =>
      api(`/exposure/${detail.id}/uptime`, { method: "PUT", body }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.uptimeSaved"));
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));

  const percent = (p: number | null) => (p === null ? "–" : `${formatNumber(p)} %`);
  const ms = (n: number | null) => (n === null ? "–" : t("websites.uptimeMs", { ms: formatNumber(n) }));
  const reason = (error: UptimeError | null, status: number | null) =>
    error === "status" && status !== null
      ? t("websites.uptimeStatus", { status })
      : t(`websites.uptimeError.${error ?? "timeout"}` as const);

  const rows = $derived.by((): Fact[] => {
    if (!u.enabled) return [];
    return [
      {
        label: t("websites.uptimeState"),
        text:
          u.state === "down"
            ? t("websites.uptimeDown")
            : u.state === "up"
              ? t("websites.uptimeUp")
              : t("websites.uptimeWaiting"),
        note: u.since ? t("websites.uptimeSince", { when: formatDateTime(u.since) }) : null,
      },
      { label: t("websites.uptimeDay"), text: percent(av.day.percent), note: ms(av.day.averageMs) },
      { label: t("websites.uptimeWeek"), text: percent(av.week.percent), note: ms(av.week.averageMs) },
      { label: t("websites.uptimeMonth"), text: percent(av.month.percent), note: ms(av.month.averageMs) },
      { label: t("websites.uptimeChecked"), text: u.checkedAt ? formatRelative(u.checkedAt) : null },
    ];
  });
  const slow = $derived(u.enabled && av.day.averageMs !== null && av.day.averageMs > UPTIME_SLOW_MS);
</script>

<Card class={className}>
  <CardHeader title={t("websites.uptimeTitle")} description={t("websites.uptimeDescription")}>
    {#snippet actions()}
      {#if u.enabled && u.state === "down"}<Badge tone="high">{t("websites.uptimeDown")}</Badge>{/if}
    {/snippet}
  </CardHeader>
  <div data-testid="websites-availability">
    {#if !u.enabled}
      <p class="px-5 pb-3 text-muted-foreground">{t("websites.uptimeOff")}</p>
    {:else}
      <Facts {rows} />
      {#if slow}<p class="px-5 pb-2 text-sm">{t("websites.uptimeSlow", { ms: formatNumber(av.day.averageMs ?? 0) })}</p>{/if}
      {#if av.hours.some((h) => h.checks > 0)}
        <div class="px-5 pb-3">
          <p class="mb-1 text-sm text-muted-foreground">{t("websites.uptimeRecent")}</p>
          <div
            class="flex h-6 items-stretch gap-0.5"
            role="img"
            aria-label={t("websites.uptimeRecentLabel", { percent: percent(av.day.percent) })}
          >
            {#each av.hours as h (h.from)}
              <span
                class={h.checks === 0
                  ? "flex-1 rounded-sm bg-muted"
                  : h.failures > 0
                    ? "flex-1 rounded-sm bg-high"
                    : "flex-1 rounded-sm bg-muted-foreground/40"}
                title={h.checks === 0
                  ? `${formatDateTime(h.from)} · ${t("websites.uptimeNoChecks")}`
                  : h.failures > 0
                    ? `${formatDateTime(h.from)} · ${t("websites.uptimeFailed", { failures: h.failures, checks: h.checks })} · ${reason(h.error, h.status)}`
                    : `${formatDateTime(h.from)} · ${ms(h.averageMs)}`}
              ></span>
            {/each}
          </div>
        </div>
      {/if}
      {#if av.incidents.length > 0}
        <div class="border-t px-5 py-3">
          <h3 class="mb-1 font-medium">{t("websites.uptimeIncidents")}</h3>
          <ul class="grid gap-1 text-sm" data-testid="websites-incidents">
            {#each av.incidents as incident (incident.from)}
              <li>
                {formatDateTime(incident.from)} – {incident.to ? formatDateTime(incident.to) : t("websites.uptimeOngoing")}
                <span class="text-muted-foreground">· {reason(incident.error, incident.status)}</span>
              </li>
            {/each}
          </ul>
        </div>
      {/if}
    {/if}
    {#if canEdit}
      <div class="flex flex-wrap items-end gap-2 border-t px-5 py-3">
        <label class="grid gap-1 text-sm">
          <span>{t("websites.uptimeInterval")}</span>
          <Select
            value={interval || String(u.intervalMinutes)}
            data-testid="websites-uptime-interval"
            onchange={(e) => {
              interval = e.currentTarget.value;
              if (u.enabled) save.mutate({ enabled: true, intervalMinutes: Number(interval) });
            }}
          >
            {#each UPTIME_INTERVALS as m (m)}
              <option value={String(m)}>{t("websites.uptimeEvery", { minutes: m })}</option>
            {/each}
          </Select>
        </label>
        <Button
          variant={u.enabled ? "outline" : "primary"}
          disabled={save.isPending}
          onclick={() =>
            save.mutate({ enabled: !u.enabled, intervalMinutes: Number(interval || u.intervalMinutes) })}
        >
          {u.enabled ? t("websites.uptimeSwitchOff") : t("websites.uptimeSwitchOn")}
        </Button>
      </div>
    {/if}
  </div>
</Card>
