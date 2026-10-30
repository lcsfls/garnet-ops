<script lang="ts">
  import { Plus, Server, TriangleAlert, X } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import AddHostDialog from "#lib/components/hosts/AddHostDialog.svelte";
  import OpenCounts from "#lib/components/hosts/OpenCounts.svelte";
  import ModuleOff from "#lib/components/ModuleOff.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { type HostRow, kernelState } from "#lib/hosts.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { rowClick } from "#lib/row-link.ts";
  import { hostsSearch } from "#lib/search.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import { parseSearch, href as urlOf } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /** Hosts and containers (ADR 0034): the hosts that run the agent, with what their containers carry. */
  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const on = $derived(me.organization.modules?.hosts === true);
  const canEdit = $derived(isAdmin(me));
  const queryClient = useQueryClient();
  const adding = $derived(canEdit && parseSearch(hostsSearch, page.url).add === "1");
  const setAdding = (open: boolean) =>
    void goto(urlOf(page.url.pathname, { add: open ? "1" : undefined }), { replace: !open, reset: false });
  const kernelAffected = (host: HostRow) => host.kernel.open.total > 0;

  const hosts = createQuery(() => ({
    queryKey: ["hosts", "list"],
    queryFn: () => api<HostRow[]>("/hosts"),
    enabled: on,
    // A new host appears with its first report.
    refetchInterval: 15_000,
  }));
  const codes = createQuery(() => ({
    queryKey: ["hosts", "enrolments"],
    queryFn: () => api<{ id: string; label: string | null; expiresAt: string }[]>("/hosts/enrolments"),
    enabled: on && canEdit,
  }));
  const revoke = createMutation(() => ({
    mutationFn: (id: string) => api(`/hosts/enrolments/${id}`, { method: "DELETE" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["hosts"] }),
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<PageHeader icon={Server} title={t("hosts.title")} description={t("hosts.description")}>
  {#snippet actions()}
    {#if on && canEdit}
      <Button onclick={() => setAdding(true)}><Plus aria-hidden="true" class="size-4" />{t("hosts.add")}</Button>
    {/if}
  {/snippet}
</PageHeader>

{#if !on}
  <ModuleOff module="hosts" canSwitch={canEdit} />
{:else}
  <details class="mb-4 rounded-xl border bg-card px-5 py-3 text-sm shadow-xs" data-testid="hosts-help">
    <summary class="cursor-pointer font-medium">{t("hosts.helpSummary")}</summary>
    <div class="mt-3 grid gap-3 text-muted-foreground @wide:grid-cols-3">
      <section>
        <h2 class="font-medium text-foreground">{t("hosts.helpReadsTitle")}</h2>
        <p>{t("hosts.helpReadsText")}</p>
      </section>
      <section>
        <h2 class="font-medium text-foreground">{t("hosts.helpSendsTitle")}</h2>
        <p>{t("hosts.helpSendsText")}</p>
      </section>
      <section>
        <h2 class="font-medium text-foreground">{t("hosts.helpKeyTitle")}</h2>
        <p>{t("hosts.helpKeyText")}</p>
      </section>
    </div>
  </details>

  {#if canEdit && codes.data && codes.data.length > 0}
    <div class="mb-4 flex flex-wrap items-center gap-2 text-sm" data-testid="host-codes">
      <span class="text-muted-foreground">{t("hosts.openCodes", { count: codes.data.length })}:</span>
      {#each codes.data as code (code.id)}
        <span class="inline-flex items-center gap-1 rounded-md border px-2 py-0.5">
          {code.label ?? t("hosts.unnamedCode")}
          <span class="text-muted-foreground">· {t("hosts.codeExpires", { when: formatRelative(code.expiresAt) })}</span>
          <button
            type="button"
            class="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            aria-label={t("hosts.revokeCodeNamed", { label: code.label ?? t("hosts.unnamedCode") })}
            disabled={revoke.isPending}
            onclick={() => revoke.mutate(code.id)}
          >
            <X aria-hidden="true" class="size-3.5" />
          </button>
        </span>
      {/each}
    </div>
  {/if}

  <Card>
    <table class="w-full text-left" data-testid="hosts-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("hosts.columnHost")}</th>
          <th class="px-3 py-2.5 text-right font-medium">{t("hosts.columnContainers")}</th>
          <th class="hidden px-3 py-2.5 text-right font-medium @3xl:table-cell">{t("hosts.columnImages")}</th>
          <th class="px-3 py-2.5 font-medium">{t("hosts.columnFindings")}</th>
          <th class="px-3 py-2.5 font-medium">{t("hosts.columnKernel")}</th>
          <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("hosts.columnUpdates")}</th>
          <th class="hidden px-3 py-2.5 font-medium @wide:table-cell">{t("hosts.columnAgent")}</th>
          <th class="hidden px-5 py-2.5 font-medium @3xl:table-cell">{t("hosts.columnLastReport")}</th>
        </tr>
      </thead>
      <tbody>
        {#each hosts.data ?? [] as host (host.id)}
          {@const href = `/hosts/${encodeURIComponent(host.id)}`}
          <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
          <tr class="row-link border-b align-top last:border-0" data-host={host.name} onclick={rowClick(() => void goto(href))}>
            <td class="px-5 py-3">
              <div class="flex flex-wrap items-center gap-2">
                <a {href} class="font-medium break-all hover:underline">{host.name}</a>
                {#if !host.lastInventoryAt}
                  <Badge tone="neutral">{t("hosts.neverReported")}</Badge>
                {:else if !host.reporting}
                  <Badge tone="high"><span title={t("hosts.notReportingHint")}>{t("hosts.notReporting")}</span></Badge>
                {/if}
              </div>
              <div class="text-sm break-all text-muted-foreground">{host.hostname}{host.os ? ` · ${host.os}` : ""}</div>
            </td>
            <td class="px-3 py-3 text-right tabular-nums">{host.containers}</td>
            <td class="hidden px-3 py-3 text-right tabular-nums @3xl:table-cell">{host.images}</td>
            <td class="px-3 py-3"><OpenCounts open={host.open} /></td>
            <td class="px-3 py-3 text-sm">
              {#if kernelAffected(host)}
                <Badge tone="high"><TriangleAlert aria-hidden="true" />{t("hosts.kernelAffectedShort")}</Badge>
              {:else if kernelState(host.kernel, 0) === "clean"}
                <span>{t("hosts.kernelClean")}</span>
              {:else}
                <span class="text-muted-foreground">{t("hosts.kernelUnchecked")}</span>
              {/if}
              {#if host.kernel.release}<div class="font-mono text-xs break-all text-muted-foreground">{host.kernel.release}</div>{/if}
            </td>
            <td class="hidden px-3 py-3 text-sm @wide:table-cell">{#if host.updatesAvailable > 0}{t("hosts.updatesCount", { count: host.updatesAvailable })}{:else}<span
                  class="text-muted-foreground">–</span
                >{/if}</td>
            <td class="hidden px-3 py-3 font-mono text-sm @wide:table-cell">{host.agentVersion ?? "–"}</td>
            <td class="hidden px-5 py-3 text-sm @3xl:table-cell">
              {#if host.lastInventoryAt}
                <time datetime={host.lastInventoryAt} title={formatDateTime(host.lastInventoryAt)}>
                  {formatRelative(host.lastInventoryAt)}
                </time>
              {:else}<span class="text-muted-foreground">–</span>{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus query={hosts} />
    {#if hosts.data && hosts.data.length === 0}
      <p class="px-5 py-6 text-muted-foreground">{t("hosts.empty")}</p>
    {/if}
  </Card>

  {#if adding}<AddHostDialog onClose={() => setAdding(false)} />{/if}
{/if}
