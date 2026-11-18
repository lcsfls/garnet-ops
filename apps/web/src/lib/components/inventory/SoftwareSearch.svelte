<script lang="ts">
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { SoftwareHit } from "../../inventory.ts";
  import { toQuery } from "../../search.ts";
  import Card from "../Card.svelte";
  import QueryStatus from "../QueryStatus.svelte";

  /**
   * Where a piece of software runs (ADR 0053): the inventory, hosts with the agent, running containers and repositories in
   * one table. Whether a row was checked against the vulnerability database is said in words: inventory rows are not.
   */
  let { q }: { q: string } = $props();
  type Answer = { items: SoftwareHit[]; limited: boolean; hostsOn: boolean };
  const enough = $derived(q.length >= 2);
  const found = createQuery(() => ({
    queryKey: ["inventory", "software", q],
    queryFn: () => api<Answer>(`/inventory/software${toQuery({ q })}`),
    enabled: enough,
    placeholderData: keepPreviousData,
  }));
  const linkOf = (hit: SoftwareHit): string =>
    hit.source === "repository"
      ? `/repositories/${hit.id}`
      : hit.source === "inventory"
        ? `/inventory${toQuery({ id: hit.id })}`
        : `/hosts/${hit.id}`;
</script>

{#if !enough}
  <p class="text-muted-foreground" data-testid="inventory-software-hint">{t("inventory.softwareSearchHint")}</p>
{:else}
  {#if found.data && !found.data.hostsOn}
    <p class="mb-4 text-sm text-muted-foreground">{t("inventory.softwareHostsOff")}</p>
  {/if}
  <Card>
    <table class="w-full text-left" data-testid="inventory-software">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("inventory.columnWhere")}</th>
          <th class="px-3 py-2.5 font-medium">{t("inventory.columnSoftwareName")}</th>
          <th class="px-3 py-2.5 font-medium">{t("inventory.columnVersion")}</th>
          <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("inventory.columnFrom")}</th>
          <th class="hidden px-5 py-2.5 font-medium @3xl:table-cell">{t("inventory.columnChecked")}</th>
        </tr>
      </thead>
      <tbody>
        {#each found.data?.items ?? [] as hit, i (i)}
          <tr class="border-b align-top last:border-0" data-testid="software-hit" data-source={hit.source}>
            <td class="px-5 py-2.5">
              <a class="font-medium underline-offset-4 hover:underline" href={linkOf(hit)}>{hit.system}</a>
              {#if hit.detail}<span class="block text-sm break-all text-muted-foreground">{hit.detail}</span>{/if}
              <span class="block text-sm text-muted-foreground @3xl:hidden">
                {t(`inventory.from.${hit.source}`)} · {hit.checked ? t("inventory.checkedYes") : t("inventory.checkedNo")}
              </span>
            </td>
            <td class="px-3 py-2.5 font-mono text-sm break-all">{hit.name}</td>
            <td class="px-3 py-2.5 font-mono text-sm break-all">{hit.version}</td>
            <td class="hidden px-3 py-2.5 text-sm @3xl:table-cell">{t(`inventory.from.${hit.source}`)}</td>
            <td class="hidden px-5 py-2.5 text-sm @3xl:table-cell">
              {#if hit.checked}{t("inventory.checkedYes")}{:else}<span class="text-muted-foreground"
                  >{t("inventory.checkedNo")}</span
                >{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={found} />
    {#if found.data && found.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">{t("inventory.softwareEmpty")}</p>
    {/if}
    {#if found.data?.limited}
      <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("inventory.softwareLimited")}</p>
    {/if}
  </Card>
  <p class="mt-3 text-sm text-muted-foreground">{t("inventory.notChecked")}</p>
{/if}
