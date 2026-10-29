<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import type { RunningContainer } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import OpenCounts from "./OpenCounts.svelte";

  /** "Where does this run?": the containers the host agents report that run images built from this repository (ADR 0034). */
  let { repositoryId }: { repositoryId: string } = $props();
  const query = createQuery(() => ({
    queryKey: ["hosts", "by-repository", repositoryId],
    queryFn: () => api<RunningContainer[]>(`/hosts/by-repository/${encodeURIComponent(repositoryId)}`),
  }));
</script>

<Card>
  <CardHeader title={t("hosts.runningTitle")} description={t("hosts.runningDescription")} />
  {#if query.data && query.data.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("hosts.runningEmpty")}</p>
  {:else if query.data}
    <table class="w-full text-left text-sm" data-testid="repository-running">
      <thead class="text-muted-foreground">
        <tr class="border-y">
          <th class="px-5 py-2 font-medium">{t("hosts.columnHost")}</th>
          <th class="px-3 py-2 font-medium">{t("hosts.columnContainer")}</th>
          <th class="px-3 py-2 font-medium">{t("hosts.columnFindings")}</th>
          <th class="hidden px-5 py-2 font-medium @3xl:table-cell">{t("hosts.columnLastReport")}</th>
        </tr>
      </thead>
      <tbody>
        {#each query.data as r (`${r.hostId}-${r.containerId}`)}
          <tr class="border-b align-top last:border-0">
            <td class="px-5 py-2.5">
              <a href={`/hosts/${encodeURIComponent(r.hostId)}`} class="font-medium text-primary-text hover:underline">{r.hostName}</a>
            </td>
            <td class="px-3 py-2.5">
              <a href={`/hosts/images/${encodeURIComponent(r.imageId)}`} class="text-primary-text hover:underline">{r.name}</a>
              <div class="font-mono text-xs break-all text-muted-foreground">
                {r.imageRef}{r.revision ? ` · ${r.revision.slice(0, 12)}` : ""}
              </div>
            </td>
            <td class="px-3 py-2.5"><OpenCounts open={r.open} /></td>
            <td class="hidden px-5 py-2.5 @3xl:table-cell">{formatRelative(r.lastSeenAt)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</Card>
