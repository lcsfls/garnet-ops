<script lang="ts">
  import { INVENTORY_KINDS } from "@garnetops/core/inventory";
  import { Pencil, Plus, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import ExportMenu from "#lib/components/ExportMenu.svelte";
  import InventoryTokens from "#lib/components/inventory/InventoryTokens.svelte";
  import SoftwareSearch from "#lib/components/inventory/SoftwareSearch.svelte";
  import SystemDetails from "#lib/components/inventory/SystemDetails.svelte";
  import SystemDialog from "#lib/components/inventory/SystemDialog.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Pagination from "#lib/components/Pagination.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import ActionMenu from "#lib/components/ui/ActionMenu.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import ConfirmDialog from "#lib/components/ui/ConfirmDialog.svelte";
  import Select from "#lib/components/ui/Select.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import type { InventoryRow, InventorySystem } from "#lib/inventory.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { type InventorySearch, inventorySearch, toQuery } from "#lib/search.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import type { Page } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * The inventory (ADR 0053): systems and the software on them, as people and scripts tell GarnetOps. A list to keep and
   * to ask ("where does php run?"), not a scan: nothing here is connected to or checked.
   */
  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const canEdit = $derived(me.role !== "viewer");
  const queryClient = useQueryClient();

  const search: InventorySearch = $derived(parseSearch(inventorySearch, new URL(page.url.href)));
  const view = $derived(search.view ?? "systems");
  const filters = $derived({ q: search.q, kind: search.kind, source: search.source });
  const list = createQuery(() => ({
    queryKey: ["inventory", "list", filters, search.cursor, search.pageSize],
    queryFn: () =>
      api<Page<InventoryRow>>(
        `/inventory${toQuery({ ...filters, cursor: search.cursor, pageSize: search.pageSize })}`,
      ),
    enabled: view === "systems",
    placeholderData: keepPreviousData,
    // A script's report shows up without a reload.
    refetchInterval: 60_000,
  }));
  const navigate = (next: InventorySearch, replace = false) =>
    goto(href(page.url.pathname, next), { reset: false, replace });
  const setSearch = (patch: Partial<InventorySearch>, replace = false) =>
    navigate({ ...search, cursor: undefined, ...patch }, replace);
  const filtered = $derived(Boolean(search.q || search.kind || search.source));

  /** The system shown or edited, with its whole software list. */
  const openId = $derived(search.edit ?? search.id);
  const one = createQuery(() => ({
    queryKey: ["inventory", "system", openId],
    queryFn: () => api<InventorySystem>(`/inventory/${openId}`),
    enabled: Boolean(openId),
  }));
  const closeDialog = () =>
    setSearch({ add: undefined, id: undefined, edit: undefined, cursor: search.cursor }, true);

  let removing = $state<InventoryRow | null>(null);
  const remove = createMutation(() => ({
    mutationFn: (id: string) => api(`/inventory/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      removing = null;
      toast.success(t("inventory.removed"));
      await queryClient.invalidateQueries({ queryKey: ["inventory"] });
    },
  }));
</script>

<PageHeader title={t("inventory.title")} description={t("inventory.description")}>
  {#snippet actions()}
    {#if view === "systems"}
      <ExportMenu path="/inventory/export" {filters} hint={t("inventory.exportHint")} />
    {/if}
    {#if canEdit}
      <Button variant="primary" onclick={() => setSearch({ add: "1" })}>
        <Plus aria-hidden="true" class="size-4" />{t("inventory.add")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>
<div class="mb-4 flex flex-wrap items-center gap-3">
  <Segmented
    label={t("inventory.viewLabel")}
    value={view}
    options={[
      { value: "systems", label: t("inventory.viewSystems") },
      { value: "software", label: t("inventory.viewSoftware") },
    ]}
    onChange={(next) =>
      navigate({ view: next === "software" ? "software" : undefined, pageSize: search.pageSize })}
  />
  {#if view === "systems"}
    <Select
      aria-label={t("inventory.kindFilter")}
      value={search.kind ?? ""}
      onchange={(e) => setSearch({ kind: INVENTORY_KINDS.find((k) => k === e.currentTarget.value) })}
      class="max-w-52"
    >
      <option value="">{t("inventory.allKinds")}</option>
      {#each INVENTORY_KINDS as kind (kind)}
        <option value={kind}>{t(`inventory.kind.${kind}`)}</option>
      {/each}
    </Select>
    <Select
      aria-label={t("inventory.sourceFilter")}
      value={search.source ?? ""}
      onchange={(e) => {
        const source = (["manual", "script"] as const).find((s) => s === e.currentTarget.value);
        setSearch({ source });
      }}
      class="max-w-56"
    >
      <option value="">{t("inventory.allSources")}</option>
      <option value="manual">{t("inventory.source.manual")}</option>
      <option value="script">{t("inventory.source.script")}</option>
    </Select>
  {/if}
  <SearchInput
    class="ml-auto"
    label={view === "systems" ? t("inventory.search") : t("inventory.softwareSearch")}
    value={search.q ?? ""}
    onChange={(q) => setSearch({ q: q || undefined }, true)}
  />
</div>

{#if view === "software"}
  <SoftwareSearch q={search.q ?? ""} />
{:else}
  <Card>
    <table class="w-full text-left" data-testid="inventory-list">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("inventory.columnSystem")}</th>
          <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("inventory.columnKind")}</th>
          <th class="px-3 py-2.5 font-medium">{t("inventory.columnSoftware")}</th>
          <th class="hidden px-3 py-2.5 font-medium whitespace-nowrap @3xl:table-cell">{t("inventory.columnSource")}</th>
          <th class="hidden px-3 py-2.5 font-medium whitespace-nowrap @wide:table-cell">{t("inventory.columnChanged")}</th>
          {#if canEdit}<th class="px-5 py-2.5"><span class="sr-only">{t("inventory.columnActions")}</span></th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each list.data?.items ?? [] as row (row.id)}
          <tr class="border-b align-top last:border-0" data-testid="inventory-row">
            <td class="px-5 py-2.5">
              <a
                class="font-medium underline-offset-4 hover:underline"
                href={href(page.url.pathname, { ...search, id: row.id })}
                data-sveltekit-noscroll
                aria-label={t("inventory.open", { name: row.name })}>{row.name}</a
              >
              <span class="block font-mono text-sm break-all text-muted-foreground">{row.key}</span>
              {#if row.environment || row.tags.length > 0}
                <span class="mt-1 flex flex-wrap items-center gap-1 text-sm text-muted-foreground">
                  {#if row.environment}<span class="mr-1">{row.environment}</span>{/if}
                  {#each row.tags as tag (tag)}<Badge tone="outline">{tag}</Badge>{/each}
                </span>
              {/if}
              <span class="mt-0.5 block text-sm text-muted-foreground @3xl:hidden">
                {t(`inventory.kind.${row.kind}`)} · {t(`inventory.source.${row.source}`)}
              </span>
            </td>
            <td class="hidden px-3 py-2.5 whitespace-nowrap @3xl:table-cell">{t(`inventory.kind.${row.kind}`)}</td>
            <td class="px-3 py-2.5 text-sm">
              {#if row.softwareCount === 0}
                <span class="text-muted-foreground">{t("inventory.noSoftware")}</span>
              {:else}
                <!-- A line breaks between two pieces of software, inside one only when it is longer than the column. -->
                <span class="font-mono wrap-anywhere">
                  {#each row.software as item, i (i)}
                    <span class="inline-block max-w-full"
                      >{item.version ? `${item.name} ${item.version}` : item.name}{i < row.software.length - 1
                        ? ","
                        : ""}</span
                    >{" "}
                  {/each}
                </span>
                {#if row.softwareCount > row.software.length}
                  <span class="text-muted-foreground">
                    {t("inventory.moreSoftware", { count: row.softwareCount - row.software.length })}
                  </span>
                {/if}
              {/if}
            </td>
            <td class="hidden px-3 py-2.5 text-sm whitespace-nowrap @3xl:table-cell">
              {t(`inventory.source.${row.source}`)}
              {#if row.reportedAt}
                <span class="block text-muted-foreground" title={formatDateTime(row.reportedAt)}>
                  {t("inventory.reported", { when: formatRelative(row.reportedAt) })}
                </span>
              {/if}
            </td>
            <td class="hidden px-3 py-2.5 text-sm whitespace-nowrap text-muted-foreground @wide:table-cell" title={formatDateTime(row.updatedAt)}>
              {formatRelative(row.updatedAt)}
            </td>
            {#if canEdit}
              <td class="px-5 py-1.5 text-right">
                <ActionMenu
                  label={t("inventory.moreActions", { name: row.name })}
                  actions={[
                    {
                      label: t("inventory.edit", { name: row.name }),
                      icon: Pencil,
                      onSelect: () => void setSearch({ edit: row.id, cursor: search.cursor }),
                    },
                    {
                      label: t("inventory.remove", { name: row.name }),
                      icon: Trash2,
                      destructive: true,
                      onSelect: () => (removing = row),
                    },
                  ]}
                />
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={list} />
    {#if list.data && list.data.items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">
        {filtered ? t("inventory.emptyFiltered") : t("inventory.empty")}
      </p>
    {/if}
    {#if list.data}
      <Pagination
        page={list.data}
        onCursor={(cursor) => navigate({ ...search, cursor })}
        onPageSize={(pageSize) => setSearch({ pageSize })}
      />
    {/if}
  </Card>
  <p class="mt-3 text-sm text-muted-foreground" data-testid="inventory-not-checked">{t("inventory.notChecked")}</p>
{/if}

{#if isAdmin(me)}
  <InventoryTokens {me} />
{/if}

{#if canEdit && search.add === "1"}
  <SystemDialog system={null} onClose={closeDialog} />
{:else if openId && one.data && one.data.id === openId}
  {#if search.edit && canEdit}
    {#key one.data.id}
      <SystemDialog system={one.data} onClose={closeDialog} />
    {/key}
  {:else}
    <SystemDetails
      system={one.data}
      {canEdit}
      onEdit={() => void setSearch({ id: undefined, edit: one.data?.id, cursor: search.cursor }, true)}
      onClose={closeDialog}
    />
  {/if}
{/if}
<ConfirmDialog
  open={removing !== null}
  title={t("inventory.removeTitle", { name: removing?.name ?? "" })}
  description={t("inventory.removeText")}
  confirmLabel={t("inventory.removeConfirm")}
  pending={remove.isPending}
  error={remove.isError ? t("errors.actionFailed") : null}
  onConfirm={() => removing && remove.mutate(removing.id)}
  onClose={() => (removing = null)}
/>
