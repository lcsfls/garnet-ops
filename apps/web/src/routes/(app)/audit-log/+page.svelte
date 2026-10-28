<script lang="ts" module>
  interface Entry {
    id: number;
    createdAt: string;
    action: string;
    target: { type: string; id: string | null } | null;
    actor: { id: string; name: string | null; email: string | null } | null;
    ip: string | null;
    data: Record<string, unknown> | null;
  }

  /** Plain text for a stored value: lists joined, objects as `key: value` pairs. */
  function formatValue(value: unknown): string {
    if (value === null || value === undefined) return "–";
    if (Array.isArray(value)) return value.map(formatValue).join(", ") || "–";
    if (typeof value === "object") {
      return Object.entries(value as Record<string, unknown>)
        .map(([k, v]) => `${k}: ${formatValue(v)}`)
        .join(", ");
    }
    return String(value);
  }
</script>

<script lang="ts">
  import { ScrollText } from "@lucide/svelte";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import { api } from "#lib/api.ts";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { hasKey, t } from "#lib/i18n.svelte.ts";
  import { AUDIT_FILTERS, type AuditSearch, auditSearch, toQuery } from "#lib/search.ts";
  import type { Page } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";

  const search = $derived(parseSearch(auditSearch, page.url));
  const query = createQuery(() => ({
    queryKey: ["audit-log", search],
    queryFn: () =>
      api<Page<Entry>>(
        `/audit-log${toQuery({ cursor: search.cursor, pageSize: search.pageSize, action: search.group ? `${search.group}.` : undefined })}`,
      ),
    placeholderData: keepPreviousData,
  }));
  const navigate = (next: AuditSearch) =>
    goto(href(page.url.pathname, next), { reset: false });
  const setSearch = (patch: Partial<AuditSearch>) => navigate({ ...search, cursor: undefined, ...patch });

  function actionLabel(entry: Entry): string {
    const actionName = entry.action.replace(/\./g, "_");
    const actionKey = `audit.actions.${actionName}`;
    // Entries of modules removed in 0.0.4 (ADR 0025) keep their labels in a small legacy block.
    const legacyKey = `audit.legacy.actions.${actionName}`;
    // Unknown actions (e.g. from a newer version) still show, with their raw name.
    return hasKey(actionKey) ? t(actionKey as never) : hasKey(legacyKey) ? t(legacyKey as never) : entry.action;
  }

  function split(entry: Entry): { outcome: unknown; details: Record<string, unknown> } {
    const { outcome, ...details } = entry.data ?? {};
    return { outcome, details };
  }

  function detailLabel(key: string): string {
    const labelKey = hasKey(`audit.details.${key}`) ? `audit.details.${key}` : `audit.legacy.details.${key}`;
    // Keys written by a newer version still show, under their raw name.
    return hasKey(labelKey) ? t(labelKey as never) : key;
  }
</script>

{#snippet entryRow(entry: Entry)}
  {@const { outcome, details } = split(entry)}
  {@const outcomeKey = typeof outcome === "string" ? `audit.outcome.${outcome}` : null}
  <tr class="border-b align-top last:border-0">
    <td class="px-5 py-2.5 text-sm whitespace-nowrap">
      <time datetime={entry.createdAt} title={formatDateTime(entry.createdAt)}>{formatDateTime(entry.createdAt)}</time>
      <div class="text-muted-foreground">{formatRelative(entry.createdAt)}</div>
    </td>
    <td class="px-3 py-2.5">
      {#if entry.actor}
        <div class="font-medium">{entry.actor.name}</div>
        <div class="text-sm text-muted-foreground">{entry.actor.email}</div>
      {:else}
        <span class="text-muted-foreground">{t("audit.system")}</span>
      {/if}
    </td>
    <td class="px-3 py-2.5">
      <div>{actionLabel(entry)}</div>
      {#if outcomeKey && hasKey(outcomeKey)}
        <Badge
          class={outcome === "failure"
            ? "mt-1 bg-destructive/15 text-destructive-text"
            : "mt-1 bg-muted text-muted-foreground"}
        >
          {t(outcomeKey as never)}
        </Badge>
      {/if}
    </td>
    <td class="hidden px-3 py-2.5 @4xl:table-cell">
      {@render detailList(details)}
    </td>
    <td class="hidden px-5 py-2.5 font-mono text-sm text-muted-foreground @6xl:table-cell">
      {entry.ip ?? "–"}
    </td>
  </tr>
{/snippet}

<!-- Entry details as plain text key/value pairs; nested values are shown compactly. -->
{#snippet detailList(data: Record<string, unknown>)}
  {@const entries = Object.entries(data)}
  {#if entries.length === 0}
    <span class="text-muted-foreground">–</span>
  {:else}
    <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-sm">
      {#each entries as [key, value] (key)}
        <div class="contents">
          <dt class="text-muted-foreground">{detailLabel(key)}</dt>
          <dd class="font-mono break-all">{formatValue(value)}</dd>
        </div>
      {/each}
    </dl>
  {/if}
{/snippet}

<PageHeader icon={ScrollText} title={t("audit.title")} description={t("audit.description")} />
<div class="mb-4">
  <Segmented
    label={t("audit.filterLabel")}
    value={search.group ?? "all"}
    options={(["all", ...AUDIT_FILTERS] as const).map((f) => ({
      value: f,
      label: t(`audit.filter.${f}`),
    }))}
    onChange={(group) => setSearch({ group: group === "all" ? undefined : group })}
  />
</div>
<Card>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("audit.columnTime")}</th>
        <th class="px-3 py-2.5 font-medium">{t("audit.columnActor")}</th>
        <th class="px-3 py-2.5 font-medium">{t("audit.columnAction")}</th>
        <th class="hidden px-3 py-2.5 font-medium @4xl:table-cell">{t("audit.columnDetails")}</th>
        <th class="hidden px-5 py-2.5 font-medium @6xl:table-cell">{t("audit.columnIp")}</th>
      </tr>
    </thead>
    <tbody>
      {#each query.data?.items ?? [] as entry (entry.id)}
        {@render entryRow(entry)}
      {/each}
    </tbody>
  </table>
  <QueryStatus {query} />
  {#if query.data && query.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("audit.empty")}</p>
  {/if}
  {#if query.data}
    <Pagination
      page={query.data}
      onCursor={(cursor) => navigate({ ...search, cursor })}
      onPageSize={(pageSize) => setSearch({ pageSize })}
    />
  {/if}
</Card>
