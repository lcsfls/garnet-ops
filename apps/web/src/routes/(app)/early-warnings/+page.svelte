<script lang="ts">
  import { Siren } from "@lucide/svelte";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import HostWarnings from "#lib/components/early-warnings/HostWarnings.svelte";
  import WebsiteWarnings from "#lib/components/early-warnings/WebsiteWarnings.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { moduleOn } from "#lib/nav.ts";
  import { type EarlyWarningSearch, earlyWarningSearch } from "#lib/search.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import type { Page, RepositoryRow, Severity } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * Early warnings (ADR 0029, 0041): new advisories for stored packages until a scan confirms or clears them; for what runs on
   * hosts, when the hosts module is on; and for websites, when website monitoring is on.
   */
  let { data }: { data: PageData } = $props();

  interface Warning {
    id: string;
    state: "open" | "confirmed" | "cleared";
    repositoryId: string;
    repositoryName: string;
    vulnerabilityId: string;
    packageName: string;
    packageVersion: string;
    packageType: string;
    fixedIn: string[];
    severity: Severity;
    knownExploited: boolean;
    detectedAt: string;
    closedAt: string | null;
  }

  const search: EarlyWarningSearch = $derived(parseSearch(earlyWarningSearch, new URL(page.url.href)));
  const state = $derived(search.state ?? "open");
  const sources = $derived([
    "repositories" as const,
    ...(moduleOn(data.me, "hosts") ? (["hosts"] as const) : []),
    ...(moduleOn(data.me, "websites") ? (["websites"] as const) : []),
  ]);
  const source = $derived(search.source && sources.includes(search.source) ? search.source : "repositories");
  const list = createQuery(() => ({
    queryKey: ["early-warnings", search],
    queryFn: () =>
      api<{
        items: Warning[];
        truncated: boolean;
        lastCheck: { checkedAt: string; dbBuiltAt: string | null } | null;
        packages: number;
        repositories: number;
        closedRecently: number;
      }>(href("/early-warnings", { state: search.state, repositoryId: search.repositoryId })),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
    enabled: source === "repositories",
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
    enabled: source === "repositories",
  }));
  const setSearch = (patch: Partial<EarlyWarningSearch>) =>
    goto(href(page.url.pathname, { ...search, ...patch }), { reset: false });

  const canScan = $derived(data.me.role !== "viewer");
  const queryClient = useQueryClient();
  const scan = createMutation(() => ({
    mutationFn: (repo: { id: string; name: string }) =>
      api(`/repositories/${repo.id}/scans`, { method: "POST" }),
    onSuccess: async (_: unknown, repo: { id: string; name: string }) => {
      toast.success(t("toast.scanQueued", { repository: repo.name }));
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  /** The first row of each repository carries its scan button; the others would only repeat it. */
  const firstOfRepository = $derived.by(() => {
    const seen = new Set<string>();
    const first = new Set<string>();
    for (const w of list.data?.items ?? []) {
      if (!seen.has(w.repositoryId)) first.add(w.id);
      seen.add(w.repositoryId);
    }
    return first;
  });
</script>

<PageHeader icon={Siren} title={t("earlyWarnings.title")} description={t("earlyWarnings.description")} />
<div class="mb-4 flex flex-wrap items-center gap-3">
  {#if sources.length > 1}
    <Segmented
      label={t("earlyWarnings.sourceLabel")}
      value={source}
      options={sources.map((x) => ({ value: x, label: t(`earlyWarnings.source.${x}`) }))}
      onChange={(value) =>
        setSearch({ source: value === "repositories" ? undefined : value, repositoryId: undefined, state: undefined })}
    />
  {/if}
  {#if source !== "websites"}
    <Segmented
      label={t("earlyWarnings.view")}
      value={state}
      options={[
        { value: "open", label: t("earlyWarnings.open") },
        { value: "closed", label: t("earlyWarnings.closed") },
      ]}
      onChange={(value) => setSearch({ state: value === "open" ? undefined : value })}
    />
  {/if}
  {#if source === "repositories"}
  <Select
    aria-label={t("findings.repository")}
    value={search.repositoryId ?? ""}
    onchange={(e) => setSearch({ repositoryId: e.currentTarget.value || undefined })}
    class="max-w-56"
  >
    <option value="">{t("findings.allRepositories")}</option>
    {#each repositories.data?.items ?? [] as r (r.id)}
      <option value={r.id}>{r.name}</option>
    {/each}
  </Select>
  {/if}
</div>
{#if source === "hosts"}
  <HostWarnings {state} />
{:else if source === "websites"}
  <WebsiteWarnings />
{:else}
<Card>
  <p class="border-b px-5 py-3 text-sm text-muted-foreground">{t("earlyWarnings.hint")}</p>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("earlyWarnings.columnSeverity")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnAdvisory")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnPackage")}</th>
        <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("earlyWarnings.columnFixedIn")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnRepository")}</th>
        <th class="hidden px-3 py-2.5 font-medium @5xl:table-cell">{t("earlyWarnings.columnDetected")}</th>
        <th class="px-5 py-2.5 font-medium">
          {state === "open" ? "" : t("earlyWarnings.columnOutcome")}
        </th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as w (w.id)}
        <tr class="border-b align-top last:border-0" data-testid="early-warning">
          <td class="px-5 py-2.5"><SeverityBadge severity={w.severity} /></td>
          <td class="px-3 py-2.5">
            <a
              href={href("/findings", { q: w.vulnerabilityId, state: "all" })}
              class="font-mono text-sm break-all text-primary-text hover:underline">{w.vulnerabilityId}</a
            >
            {#if w.knownExploited}
              <div class="mt-1"><Badge tone="critical">{t("earlyWarnings.knownExploited")}</Badge></div>
            {/if}
          </td>
          <td class="px-3 py-2.5 font-mono text-sm break-all">{w.packageName} {w.packageVersion}</td>
          <td class="hidden px-3 py-2.5 font-mono text-sm break-all @3xl:table-cell">
            {w.fixedIn.length ? w.fixedIn.join(", ") : "–"}
          </td>
          <td class="px-3 py-2.5"><RepositoryLink id={w.repositoryId} name={w.repositoryName} /></td>
          <td class="hidden px-3 py-2.5 text-sm text-muted-foreground @5xl:table-cell">
            {formatRelative(w.detectedAt)}
          </td>
          <td class="px-5 py-2.5 text-sm">
            {#if w.state === "confirmed"}
              {t("earlyWarnings.confirmed")}
            {:else if w.state === "cleared"}
              <span class="text-muted-foreground">{t("earlyWarnings.cleared")}</span>
            {:else if canScan && firstOfRepository.has(w.id)}
              <Button
                variant="outline"
                class="h-8 whitespace-nowrap"
                aria-label={t("earlyWarnings.scanNowFor", { repository: w.repositoryName })}
                disabled={scan.isPending}
                onclick={() => scan.mutate({ id: w.repositoryId, name: w.repositoryName })}
              >
                {t("earlyWarnings.scanNow")}
              </Button>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <div class="grid gap-2 px-5 py-6 text-muted-foreground" data-testid="early-warnings-empty">
      <p>{state === "open" ? t("earlyWarnings.emptyOpen") : t("earlyWarnings.emptyClosed")}</p>
      {#if state === "open"}
        {@const d = list.data}
        {#if d.packages === 0}
          <p>{t("earlyWarnings.noPackages")}</p>
        {:else if d.lastCheck}
          <p>
            {t("earlyWarnings.lastCheck", {
              when: formatDateTime(d.lastCheck.checkedAt),
              database: d.lastCheck.dbBuiltAt ? formatDateTime(d.lastCheck.dbBuiltAt) : "–",
              packages: d.packages,
              repositories: d.repositories,
            })}
          </p>
        {:else}
          <p>{t("earlyWarnings.notCheckedYet")}</p>
        {/if}
        {#if d.closedRecently > 0}
          <p>{t("earlyWarnings.closedRecently", { count: d.closedRecently })}</p>
        {/if}
      {/if}
    </div>
  {/if}
  {#if list.data?.truncated}
    <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("earlyWarnings.truncated")}</p>
  {/if}
</Card>
{/if}
