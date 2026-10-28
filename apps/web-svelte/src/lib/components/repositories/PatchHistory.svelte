<script lang="ts">
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { calendarDaysBetween } from "../../dates.ts";
  import { formatDate, formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toQuery } from "../../search.ts";
  import type { Page, PatchRow } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Pagination from "../Pagination.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /** Which finding was fixed when, and which version the repository has now. */
  let {
    id,
    cursor,
    pageSize,
    onCursor,
    onPageSize,
  }: {
    id: string;
    cursor?: string | undefined;
    pageSize?: number | undefined;
    onCursor: (cursor: string | undefined) => void;
    onPageSize: (size: number) => void;
  } = $props();

  const patches = createQuery(() => ({
    queryKey: ["patches", id, cursor, pageSize],
    queryFn: () => api<Page<PatchRow>>(`/repositories/${id}/patches${toQuery({ cursor, pageSize })}`),
    placeholderData: keepPreviousData,
  }));
</script>

<Card>
  <CardHeader title={t("repository.patchHistory")} description={t("repository.patchHistoryDescription")} />
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("repository.columnFixedOn")}</th>
        <th class="px-3 py-2.5 font-medium">{t("findings.columnFinding")}</th>
        <th class="px-3 py-2.5 font-medium">{t("findings.columnPackage")}</th>
        <th class="px-3 py-2.5 font-medium">{t("repository.columnChange")}</th>
        <th class="hidden px-5 py-2.5 font-medium @3xl:table-cell">{t("repository.columnOpenFor")}</th>
      </tr>
    </thead>
    <tbody>
      {#each patches.data?.items ?? [] as p (p.id)}
        <tr class="border-b align-top last:border-0">
          <td class="px-5 py-2.5 text-sm whitespace-nowrap">
            <time datetime={p.resolvedAt} title={formatDateTime(p.resolvedAt)}>{formatDate(p.resolvedAt)}</time>
          </td>
          <td class="px-3 py-2.5">
            <div class="mb-1">
              <SeverityBadge severity={p.severity} />
            </div>
            <a
              href={href("/findings", { id: p.id, state: "all", repositoryId: id })}
              class="font-medium break-all hover:underline"
            >
              {p.vulnerabilityId}
            </a>
          </td>
          <td class="px-3 py-2.5 font-mono text-sm break-all">
            {p.packageName}
            <div class="font-sans text-muted-foreground">{p.packageType}</div>
          </td>
          <td class="px-3 py-2.5 font-mono text-sm">
            {p.version} →
            {#if p.currentVersions.length}{p.currentVersions.join(", ")}{:else}<span
                class="font-sans text-muted-foreground">{t("repository.removed")}</span
              >{/if}
          </td>
          <td class="hidden px-5 py-2.5 text-sm text-muted-foreground @3xl:table-cell">
            {t("repository.days", {
              count: Math.max(0, calendarDaysBetween(new Date(p.firstSeenAt), new Date(p.resolvedAt))),
            })}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={patches} />
  {#if patches.data && patches.data.items.length === 0}
    <p class="px-5 py-6 text-muted-foreground">{t("repository.noPatches")}</p>
  {/if}
  {#if patches.data}
    <Pagination page={patches.data} {onCursor} {onPageSize} />
  {/if}
</Card>
