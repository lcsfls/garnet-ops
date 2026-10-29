<script lang="ts">
  import { ArrowLeft, Globe, Play, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, keepPreviousData, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import ConfirmDialog from "#lib/components/ui/ConfirmDialog.svelte";
  import DnsCard from "#lib/components/websites/DnsCard.svelte";
  import Facts, { type Fact } from "#lib/components/websites/Facts.svelte";
  import FindingsCard from "#lib/components/websites/FindingsCard.svelte";
  import HistoryCard from "#lib/components/websites/HistoryCard.svelte";
  import HttpCard from "#lib/components/websites/HttpCard.svelte";
  import ModuleOff from "#lib/components/websites/ModuleOff.svelte";
  import PortsCard from "#lib/components/websites/PortsCard.svelte";
  import Stage2Dialog from "#lib/components/websites/Stage2Dialog.svelte";
  import StageBadge from "#lib/components/websites/StageBadge.svelte";
  import TlsCard from "#lib/components/websites/TlsCard.svelte";
  import VerificationBadge from "#lib/components/websites/VerificationBadge.svelte";
  import VerifyDialog from "#lib/components/websites/VerifyDialog.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { layoutStep } from "#lib/layout-step.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import {
    WEBSITE_TABS,
    type WebsiteDetailSearch,
    type WebsiteTab,
    websiteDetailSearch,
  } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { type ExposureDetail, errorKey, isBusy, verificationKey } from "#lib/websites.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * One website (ADR 0023): where it stands, what stage 1 and stage 2 saw, and what is wrong. Below the wide step the sections
   * are tabs and the findings are one of them; from wide on the findings are a pane of their own beside the tab, and from xwide
   * on the DNS, TLS, HTTP and port details are shown side by side with no tabs.
   */
  let { data: pageData }: { data: PageData } = $props();
  const me = $derived(pageData.me);
  const on = $derived(me.organization.modules?.websites === true);
  const canEdit = $derived(isAdmin(me));
  const id = $derived(page.params.id ?? "");
  const search = $derived(parseSearch(websiteDetailSearch, page.url));
  const step = $derived(layoutStep());
  const queryClient = useQueryClient();
  let confirmRemove = $state(false);

  const query = createQuery(() => ({
    queryKey: ["websites", "asset", id],
    queryFn: () => api<ExposureDetail>(`/exposure/${id}`),
    enabled: on,
    placeholderData: keepPreviousData,
    refetchInterval: (q: { state: { data?: ExposureDetail } }) =>
      q.state.data && isBusy(q.state.data) ? 2500 : false,
  }));
  const data = $derived(query.data);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["websites"] });

  const run = createMutation(() => ({
    mutationFn: () => api(`/exposure/${id}/run`, { method: "POST" }),
    onSuccess: refresh,
  }));
  const patch = createMutation(() => ({
    mutationFn: (body: { includeSubdomains?: boolean; passiveEnabled?: boolean }) =>
      api(`/exposure/${id}`, { method: "PATCH", body }),
    onSuccess: refresh,
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api(`/exposure/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await refresh();
      await goto("/websites");
    },
  }));

  const setSearch = (next: Partial<WebsiteDetailSearch>) =>
    goto(href(page.url.pathname, { ...search, ...next }), { replace: true, reset: false });
  const tab: WebsiteTab = $derived(search.tab ?? "findings");
  // From the wide step the findings have a pane of their own; the tab then shows one of the others.
  const sideTab: WebsiteTab = $derived(tab === "findings" ? "dns" : tab);
  const findingsState = $derived(search.findings ?? "open");
  const tabs = $derived(WEBSITE_TABS.filter((x) => step === "base" || x !== "findings"));
  const verification = $derived(data ? verificationKey(data) : null);
  const errorText = (code: string | null) => {
    const key = errorKey(code);
    return key ? t(key) : (code ?? "");
  };
  const running = $derived(data?.stage1.run?.state === "queued" || data?.stage1.run?.state === "running");

  const verificationRows = $derived.by((): Fact[] => {
    if (!data) return [];
    const rows: Fact[] = [
      {
        label: t("websites.summaryState"),
        text: verification ? t(`websites.verification.${verification}`) : "",
      },
    ];
    if (data.verification.method) {
      rows.push({
        label: t("websites.summaryMethod"),
        text: t(`websites.method.${data.verification.method}`),
      });
    }
    if (data.verification.via === "parent" && data.verification.parent) {
      rows.push({ label: t("websites.summaryCoveredBy"), value: parentLink });
    }
    rows.push({
      label: t("websites.summaryConfirmed"),
      value: data.verification.confirmedAt ? confirmedAt : undefined,
    });
    if (data.verification.error && data.verification.state !== "verified") {
      rows.push({ label: t("websites.summaryProblem"), text: errorText(data.verification.error) });
    }
    return rows;
  });
  const stage1Rows = $derived.by((): Fact[] =>
    data
      ? [
          { label: t("websites.summaryLastCheck"), value: data.stage1.lastAt ? stage1At : undefined },
          {
            label: t("websites.summaryDaily"),
            text: data.stage1.enabled ? t("websites.yes") : t("websites.no"),
          },
        ]
      : [],
  );
  const stage2Rows = $derived.by((): Fact[] => {
    if (!data) return [];
    const rows: Fact[] = [
      {
        label: t("websites.summaryState"),
        text: data.stage2.enabled
          ? t(`websites.schedule.${data.stage2.schedule}`)
          : t("websites.stage2State.off"),
      },
      { label: t("websites.summaryLastCheck"), value: data.stage2.lastAt ? stage2At : undefined },
    ];
    if (data.stage2.error)
      rows.push({ label: t("websites.summaryProblem"), text: errorText(data.stage2.error) });
    return rows;
  });
</script>

{#snippet when(value: string)}
  <time datetime={value} title={formatDateTime(value)}>{formatRelative(value)}</time>
{/snippet}
{#snippet confirmedAt()}{#if data?.verification.confirmedAt}{@render when(data.verification.confirmedAt)}{/if}{/snippet}
{#snippet stage1At()}{#if data?.stage1.lastAt}{@render when(data.stage1.lastAt)}{/if}{/snippet}
{#snippet stage2At()}{#if data?.stage2.lastAt}{@render when(data.stage2.lastAt)}{/if}{/snippet}
{#snippet parentLink()}
  {#if data?.verification.parent}
    <a href={`/websites/${encodeURIComponent(data.verification.parent.id)}`} class="text-primary-text hover:underline">
      {data.verification.parent.value}
    </a>
  {/if}
{/snippet}

{#snippet meta()}
  {#if data}
    <div class="mt-2 flex flex-wrap items-center gap-2">
      <VerificationBadge asset={data} />
      <StageBadge asset={data} stage={1} />
      <StageBadge asset={data} stage={2} />
    </div>
  {/if}
{/snippet}

{#snippet actions()}
  {#if data && canEdit}
    <Button disabled={run.isPending || running} onclick={() => run.mutate()}>
      <Play aria-hidden="true" class="size-4" />
      {t("websites.checkNow")}
    </Button>
    <Button
      variant="outline"
      onclick={() => {
        remove.reset();
        confirmRemove = true;
      }}
    >
      <Trash2 aria-hidden="true" class="size-4" />
      {t("websites.remove")}
    </Button>
  {/if}
{/snippet}

{#snippet tabBody(which: WebsiteTab)}
  {#if data}
    {#if which === "tls"}<TlsCard detail={data} />
    {:else if which === "http"}<HttpCard detail={data} />
    {:else if which === "ports"}<PortsCard detail={data} {canEdit} onStage2={() => setSearch({ stage2: "1" })} />
    {:else if which === "history"}<HistoryCard detail={data} />
    {:else}<DnsCard detail={data} {canEdit} />{/if}
  {/if}
{/snippet}

<a
  href="/websites"
  class="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
>
  <ArrowLeft aria-hidden="true" class="size-4" />
  {t("websites.back")}
</a>
<PageHeader
  icon={Globe}
  title={data?.value ?? (on ? t("common.loading") : t("websites.title"))}
  description={data ? t(`websites.kind.${data.kind}`) : ""}
  meta={data ? meta : undefined}
  actions={data ? actions : undefined}
/>
{#if !on}
  <ModuleOff canSwitch={canEdit} />
{:else if !data}
  <Card><QueryStatus {query} /></Card>
{:else}
  <div class="grid gap-4">
    {#if run.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
    {#if patch.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
    {#if data.stage1.error}
      <Alert tone="error">{t("websites.stage1Failed", { reason: errorText(data.stage1.error) })}</Alert>
    {/if}

    <div class="grid gap-4 @2xl:grid-cols-2 @wide:grid-cols-3" data-testid="websites-summary">
      <Card>
        <CardHeader title={t("websites.summaryVerification")}>
          {#snippet actions()}
            {#if canEdit}
              <Button variant="outline" class="h-9 px-3 text-sm" onclick={() => setSearch({ verify: "1" })}>
                {t("websites.verifyOpen")}
              </Button>
            {/if}
          {/snippet}
        </CardHeader>
        <Facts rows={verificationRows} />
        {#if canEdit && data.kind === "domain"}
          <label class="flex items-start gap-2.5 px-5 pb-5 text-sm">
            <Checkbox
              class="mt-0.5"
              checked={data.includeSubdomains}
              disabled={patch.isPending}
              onchange={(e) => patch.mutate({ includeSubdomains: e.currentTarget.checked })}
            />
            <span>
              {t("websites.includeSubdomains")}
              <span class="block text-muted-foreground">{t("websites.includeSubdomainsHint")}</span>
            </span>
          </label>
        {/if}
      </Card>

      <Card>
        <CardHeader title={t("websites.summaryStage1")} description={t("websites.summaryStage1Text")} />
        <Facts rows={stage1Rows} />
        {#if canEdit}
          <label class="flex items-center gap-2.5 px-5 pb-5 text-sm">
            <Checkbox
              checked={data.stage1.enabled}
              disabled={patch.isPending}
              onchange={(e) => patch.mutate({ passiveEnabled: e.currentTarget.checked })}
            />
            {t("websites.stage1Daily")}
          </label>
        {/if}
      </Card>

      <Card>
        <CardHeader title={t("websites.summaryStage2")} description={t("websites.summaryStage2Text")}>
          {#snippet actions()}
            {#if canEdit}
              <Button variant="outline" class="h-9 px-3 text-sm" onclick={() => setSearch({ stage2: "1" })}>
                {data?.stage2.enabled ? t("websites.stage2Manage") : t("websites.stage2Open")}
              </Button>
            {/if}
          {/snippet}
        </CardHeader>
        <Facts rows={stage2Rows} />
      </Card>
    </div>

    {#if step !== "xwide"}
      <Segmented
        label={t("websites.tabsLabel")}
        value={step === "base" ? tab : sideTab}
        options={tabs.map((x) => ({ value: x, label: t(`websites.tab.${x}`) }))}
        onChange={(next) => setSearch({ tab: next === "findings" ? undefined : next })}
      />
    {/if}

    {#if step === "xwide"}
      <div class="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)] items-start gap-4">
        <FindingsCard detail={data} state={findingsState} onState={(findings) => setSearch({ findings })} />
        <div class="grid gap-4">
          <DnsCard detail={data} {canEdit} />
          <TlsCard detail={data} />
        </div>
        <div class="grid gap-4">
          <HttpCard detail={data} />
          <PortsCard detail={data} {canEdit} onStage2={() => setSearch({ stage2: "1" })} />
          <HistoryCard detail={data} />
        </div>
      </div>
    {:else if step === "wide"}
      <div class="grid grid-cols-[minmax(0,26rem)_minmax(0,1fr)] items-start gap-4">
        <FindingsCard detail={data} state={findingsState} onState={(findings) => setSearch({ findings })} />
        {@render tabBody(sideTab)}
      </div>
    {:else if tab === "findings"}
      <FindingsCard detail={data} state={findingsState} onState={(findings) => setSearch({ findings })} />
    {:else}
      {@render tabBody(tab)}
    {/if}
  </div>

  {#if canEdit}
    {#if search.verify === "1"}
      <VerifyDialog assetId={id} email={me.user.email} onClose={() => setSearch({ verify: undefined })} />
    {/if}
    {#if search.stage2 === "1"}
      <Stage2Dialog asset={data} email={me.user.email} onClose={() => setSearch({ stage2: undefined })} />
    {/if}
    <ConfirmDialog
      open={confirmRemove}
      title={t("websites.removeTitle", { asset: data.value })}
      description={t("websites.removeDescription")}
      confirmLabel={t("websites.remove")}
      pending={remove.isPending}
      error={remove.isError ? t("errors.actionFailed") : null}
      onConfirm={() => remove.mutate()}
      onClose={() => (confirmRemove = false)}
    />
  {/if}
{/if}
