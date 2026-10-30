<script lang="ts">
  import { ArrowLeft, Server, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import HostPackagesCard from "#lib/components/hosts/HostPackagesCard.svelte";
  import KernelCard from "#lib/components/hosts/KernelCard.svelte";
  import OpenCounts from "#lib/components/hosts/OpenCounts.svelte";
  import SyncNote from "#lib/components/hosts/SyncNote.svelte";
  import UpdateBadge from "#lib/components/hosts/UpdateBadge.svelte";
  import ModuleOff from "#lib/components/ModuleOff.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import ConfirmDialog from "#lib/components/ui/ConfirmDialog.svelte";
  import Facts from "#lib/components/websites/Facts.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { type HostDetail, shortId } from "#lib/hosts.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /** One host (ADR 0034): what it is, and its running containers with their images, repositories, findings and updates. */
  let { data: pageData }: { data: PageData } = $props();
  const me = $derived(pageData.me);
  const on = $derived(me.organization.modules?.hosts === true);
  const canEdit = $derived(isAdmin(me));
  const id = $derived(page.params.id ?? "");
  const queryClient = useQueryClient();
  let confirmRemove = $state(false);

  const query = createQuery(() => ({
    queryKey: ["hosts", "host", id],
    queryFn: () => api<HostDetail>(`/hosts/${encodeURIComponent(id)}`),
    enabled: on,
    refetchInterval: 30_000,
  }));
  const host = $derived(query.data);
  const remove = createMutation(() => ({
    mutationFn: () => api(`/hosts/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSuccess: async () => {
      toast.success(t("hosts.removed"));
      await queryClient.invalidateQueries({ queryKey: ["hosts"] });
      await goto("/hosts");
    },
  }));
  const when = (value: string | null) =>
    value ? `${formatRelative(value)} (${formatDateTime(value)})` : null;
</script>

<a href="/hosts" class="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline">
  <ArrowLeft aria-hidden="true" class="size-4" />{t("hosts.back")}
</a>
<PageHeader icon={Server} title={host?.name ?? (on ? t("common.loading") : t("hosts.title"))} description={host?.hostname ?? ""}>
  {#snippet actions()}
    {#if host && canEdit}
      <Button
        variant="outline"
        onclick={() => {
          remove.reset();
          confirmRemove = true;
        }}
      >
        <Trash2 aria-hidden="true" class="size-4" />{t("hosts.remove")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>

{#if !on}
  <ModuleOff module="hosts" canSwitch={canEdit} />
{:else if !host}
  <Card><QueryStatus {query} /></Card>
{:else}
  <div class="grid gap-4 @wide:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
    <div class="grid content-start gap-4">
    <Card>
      <CardHeader title={host.name} />
      <Facts
        rows={[
          { label: t("hosts.hostname"), text: host.hostname, mono: true },
          { label: t("hosts.os"), text: host.os },
          { label: t("hosts.dockerVersion"), text: host.dockerVersion },
          {
            label: t("hosts.agentVersion"),
            text: host.agentVersion,
            note: host.runtime === "systemd" ? t("hosts.runtimeSystemdShort") : null,
          },
          { label: t("hosts.enrolledAt"), text: when(host.enrolledAt) },
          {
            label: t("hosts.lastReport"),
            text: when(host.lastInventoryAt) ?? t("hosts.neverReported"),
            note: host.lastInventoryAt && !host.reporting ? t("hosts.notReportingHint") : null,
          },
        ]}
      />
    </Card>
    <KernelCard kernel={host.kernel} />
    {#if host.runtime === "systemd" || host.hostPackages.count !== null}<HostPackagesCard packages={host.hostPackages} />{/if}
    </div>

    <Card>
      <CardHeader title={t("hosts.containersTitle")} />
      {#if host.containers.length === 0}
        <p class="px-5 pb-5 text-muted-foreground">{t("hosts.containersEmpty")}</p>
      {:else}
        <table class="w-full text-left" data-testid="host-containers">
          <thead class="text-sm text-muted-foreground">
            <tr class="border-y">
              <th class="px-5 py-2.5 font-medium">{t("hosts.columnContainer")}</th>
              <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("hosts.columnRepository")}</th>
              <th class="px-3 py-2.5 font-medium">{t("hosts.columnFindings")}</th>
              <th class="hidden px-5 py-2.5 font-medium @wide:table-cell">{t("hosts.columnUpdates")}</th>
            </tr>
          </thead>
          <tbody>
            {#each host.containers as c (c.containerId)}
              <tr class="border-b align-top last:border-0" data-container={c.name}>
                <td class="max-w-0 px-5 py-3 @wide:max-w-none">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="font-medium break-all">{c.name}</span>
                    {#if c.state !== "running"}<Badge tone="neutral">{c.state}</Badge>{/if}
                  </div>
                  <a
                    href={`/hosts/images/${encodeURIComponent(c.imageId)}`}
                    class="block font-mono text-sm break-all text-primary-text hover:underline"
                    title={shortId(c.imageId)}
                  >
                    {c.imageRef}
                  </a>
                  <!-- Below 3xl the repository and below wide the update move here instead of disappearing. -->
                  <div class="mt-1 flex flex-wrap gap-2 text-sm @3xl:hidden">
                    {#if c.repository}<RepositoryLink id={c.repository.id} name={c.repository.name} />{/if}
                  </div>
                  <div class="mt-1 @wide:hidden"><UpdateBadge update={c.update} /></div>
                </td>
                <td class="hidden px-3 py-3 text-sm @3xl:table-cell">
                  {#if c.repository}
                    <RepositoryLink id={c.repository.id} name={c.repository.name} />
                    {#if c.revision}<div class="font-mono text-xs text-muted-foreground">{c.revision.slice(0, 12)}</div>{/if}
                    <SyncNote sync={c.sync} />
                  {:else}
                    <span class="text-muted-foreground" title={t("hosts.noRepositoryHint")}>{t("hosts.noRepository")}</span>
                  {/if}
                </td>
                <td class="px-3 py-3">
                  {#if c.matchError}
                    <span class="text-sm text-muted-foreground">{t("hosts.matchFailed")}</span>
                  {:else if !c.matchedAt}
                    <span class="text-sm text-muted-foreground">{t("hosts.notMatched")}</span>
                  {:else}
                    <OpenCounts open={c.open} />
                  {/if}
                </td>
                <td class="hidden px-5 py-3 @wide:table-cell"><UpdateBadge update={c.update} /></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </Card>
  </div>

  <ConfirmDialog
    open={confirmRemove}
    title={t("hosts.removeTitle", { name: host.name })}
    description={t("hosts.removeDescription")}
    confirmLabel={t("hosts.remove")}
    pending={remove.isPending}
    error={remove.isError ? t("errors.actionFailed") : null}
    onConfirm={() => remove.mutate()}
    onClose={() => (confirmRemove = false)}
  />
{/if}
