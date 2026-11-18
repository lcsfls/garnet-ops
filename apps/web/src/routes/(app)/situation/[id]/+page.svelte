<script lang="ts">
  import {
    FIX_SIDE,
    type FixPath,
    type SituationKind,
    type SituationStatus,
  } from "@garnetops/core/situation";
  import type { SsholeSafeReason } from "@garnetops/core/sshd";
  import { ArrowLeft } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import { cn } from "#lib/cn.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import Segmented from "#lib/components/Segmented.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import StateIcon from "#lib/components/ui/StateIcon.svelte";
  import CopyRow from "#lib/components/websites/CopyRow.svelte";
  import { formatDate, formatNumber } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { type SituationDetailSearch, situationDetailSearch } from "#lib/search.ts";
  import { TONE_CLASSES } from "#lib/severity-meta.ts";
  import type { Severity } from "#lib/types.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  /**
   * One vulnerability (ADR 0052): every system that has it, its state, and what fixes it: an action on the server, a commit in
   * a repository, or nobody's yet. What GarnetOps could not check is listed on its own and never counted as fine. Names of
   * packages, images and hosts are scanned or reported content and are shown as text.
   */
  type PatchState =
    | "patchable-now"
    | "waiting-for-mirror"
    | "lists-stale"
    | "pro-only"
    | "no-fix-yet"
    | "unknown";
  type Reason =
    | "never-scanned"
    | "scan-failed"
    | "not-reporting"
    | "packages-not-matched"
    | "host-packages-not-reported"
    | "image-not-checked";
  interface System {
    kind: SituationKind;
    id: string;
    name: string;
    status: SituationStatus;
    severity: Severity;
    packages: { name: string; version: string; type: string; fixedIn: string[] }[];
    fixPath: FixPath;
    reasons: SsholeSafeReason[];
    repository: { id: string; name: string; findingId: string | null } | null;
    container: { name: string; imageRef: string; update: { state: string; tag: string | null } } | null;
    host: { id: string; name: string; reporting: boolean } | null;
    patch: { state: PatchState; fixedIn: string | null; command: string | null } | null;
    kernel: boolean;
  }
  interface Answer {
    vulnerability: {
      id: string;
      severity: Severity;
      cvssScore: number | null;
      knownExploited: boolean;
      publishedAt: string | null;
      description: string | null;
      urls: string[];
      aliases: string[];
    };
    systems: System[];
    truncated: number;
    counts: {
      affected: number;
      notReachable: number;
      notChecked: number;
      checked: number;
      byPath: Record<FixPath, number>;
    };
    notChecked: { kind: SituationKind; id: string; name: string; reason: Reason }[];
    hostsOn: boolean;
  }

  const id = $derived(page.params.id ?? "");
  const search: SituationDetailSearch = $derived(parseSearch(situationDetailSearch, new URL(page.url.href)));
  const query = createQuery(() => ({
    queryKey: ["situation", "vulnerability", id],
    queryFn: () => api<Answer>(`/situation/${encodeURIComponent(id)}`),
    refetchInterval: 60_000,
  }));
  const data = $derived(query.data);
  const SIDES = ["all", "server", "repository", "none"] as const;
  const sideCount = (side: (typeof SIDES)[number]) =>
    (data?.systems ?? []).filter((s) => side === "all" || FIX_SIDE[s.fixPath] === side).length;
  const shown = $derived(
    (data?.systems ?? []).filter((s) => !search.side || FIX_SIDE[s.fixPath] === search.side),
  );
  const setSide = (side: (typeof SIDES)[number]) =>
    goto(href(page.url.pathname, { side: side === "all" ? undefined : side }), {
      reset: false,
      replace: true,
    });
  const systemHref = (kind: SituationKind, systemId: string) =>
    kind === "repository"
      ? `/repositories/${encodeURIComponent(systemId)}`
      : `/hosts/${encodeURIComponent(systemId)}`;
  const FIGURES = ["affected", "notReachable", "notChecked", "checked"] as const;
</script>

<a
  href="/situation"
  class="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline"
>
  <ArrowLeft aria-hidden="true" class="size-4" />{t("situation.back")}
</a>
<PageHeader title={id} description={t("situation.detailDescription")}>
  {#snippet meta()}
    {#if data}
      <div class="mt-2 flex flex-wrap items-center gap-2 text-sm" data-testid="situation-meta">
        <SeverityBadge severity={data.vulnerability.severity} />
        {#if data.vulnerability.knownExploited}
          <span class={cn("inline-flex items-center gap-1", TONE_CLASSES.critical.text)}>
            <StateIcon name="flame" class="size-3.5" />{t("situation.exploited")}
          </span>
        {/if}
        {#if data.vulnerability.cvssScore !== null}
          <span class="text-muted-foreground">{t("situation.cvss", { score: data.vulnerability.cvssScore.toFixed(1) })}</span>
        {/if}
        {#if data.vulnerability.publishedAt}
          <span class="text-muted-foreground">{formatDate(data.vulnerability.publishedAt)}</span>
        {/if}
      </div>
    {/if}
  {/snippet}
</PageHeader>

{#if !data}
  <Card><QueryStatus {query} /></Card>
{:else}
  <div class="grid gap-4">
    <dl
      class="grid grid-cols-2 gap-3 @3xl:grid-cols-4"
      aria-label={t("situation.summaryLabel")}
      data-testid="situation-counts"
    >
      {#each FIGURES as figure (figure)}
        <div class="rounded-xl border bg-card px-5 py-4">
          <dt class="text-sm text-muted-foreground">{t(`situation.summary.${figure}`)}</dt>
          <dd class="text-2xl font-semibold tabular-nums" data-testid={`situation-count-${figure}`}>
            {formatNumber(data.counts[figure])}
          </dd>
          {#if figure === "checked"}
            <dd class="mt-1 text-sm text-muted-foreground">{t("situation.checkedHint")}</dd>
          {/if}
        </div>
      {/each}
    </dl>

    <Card>
      <CardHeader title={t("situation.systemsTitle")} />
      <div class="px-5 pb-4">
        <Segmented
          label={t("situation.sideFilter")}
          value={search.side ?? "all"}
          options={SIDES.map((s) => ({ value: s, label: t(`situation.side.${s}`), count: sideCount(s) }))}
          onChange={setSide}
        />
      </div>
      <table class="w-full text-left" data-testid="situation-systems">
        <thead class="text-sm text-muted-foreground">
          <tr class="border-y">
            <th class="px-5 py-2.5 font-medium">{t("situation.columnSystem")}</th>
            <th class="px-3 py-2.5 font-medium">{t("situation.columnStatus")}</th>
            <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("situation.columnPackage")}</th>
            <th class="px-5 py-2.5 font-medium">{t("situation.columnFixedBy")}</th>
          </tr>
        </thead>
        <tbody>
          {#each shown as system, index (`${system.kind}:${system.id}:${system.name}`)}
            <tr class="border-b align-top last:border-0" data-testid="situation-system" data-path={system.fixPath}>
              <td class="px-5 py-3">
                <span class="block text-sm text-muted-foreground">{t(`situation.kind.${system.kind}`)}</span>
                {#if system.kind === "repository"}
                  <RepositoryLink id={system.id} name={system.name} class="font-medium" />
                {:else if system.kind === "host"}
                  <a class="font-medium underline-offset-4 hover:underline" href={systemHref("host", system.id)}
                    >{system.name}</a
                  >
                {:else}
                  <span class="font-medium break-all">{system.name}</span>
                  {#if system.host}
                    <span class="block text-sm">
                      <a class="underline underline-offset-4" href={systemHref("host", system.host.id)}
                        >{t("situation.onHost", { host: system.host.name })}</a
                      >
                    </span>
                  {/if}
                  {#if system.container}
                    <span class="block font-mono text-sm break-all text-muted-foreground">{system.container.imageRef}</span>
                  {/if}
                {/if}
                {#if system.host && !system.host.reporting}
                  <span class="mt-1 block text-sm text-muted-foreground">{t("situation.notReporting")}</span>
                {/if}
              </td>
              <td class="px-3 py-3">
                {#if system.status === "affected"}
                  <span class="block font-medium">{t("situation.status.affected")}</span>
                  <span class="mt-1 block"><SeverityBadge severity={system.severity} /></span>
                {:else}
                  <Badge tone="neutral">{t(`situation.status.${system.status}`)}</Badge>
                  <div class="mt-1.5 text-sm" data-testid="situation-not-reachable">
                    <span class="font-medium">{t("situation.notReachableTitle")}</span>
                    {#each system.reasons as reason (reason)}
                      <span class="block text-muted-foreground">{t(`hosts.sshNoteReasons.${reason}`)}</span>
                    {/each}
                    <span class="block text-muted-foreground">{t("situation.notReachableKeep")}</span>
                  </div>
                {/if}
              </td>
              <td class="hidden px-3 py-3 text-sm @3xl:table-cell">
                {#each system.packages as p (`${p.type}:${p.name}:${p.version}`)}
                  <span class="block">
                    <span class="font-mono break-all">{p.name} {p.version}</span>
                    <span class="text-muted-foreground">
                      {p.fixedIn.length
                        ? t("situation.fixedIn", { versions: p.fixedIn.join(", ") })
                        : t("situation.noFix")}
                    </span>
                  </span>
                {/each}
              </td>
              <td class="px-5 py-3 text-sm">
                <span class="block font-medium" data-testid="situation-path">{t(`situation.path.${system.fixPath}`)}</span>
                <span class="block text-muted-foreground">{t(`situation.pathHint.${system.fixPath}`)}</span>
                {#if system.patch && system.patch.state !== "unknown" && system.fixPath !== "vendor"}
                  <span class="mt-1 block">{t(`situation.patch.${system.patch.state}`)}</span>
                {/if}
                {#if system.patch?.command}
                  <div class="mt-2">
                    <CopyRow id={`situation-command-${index}`} label={t("situation.command")} value={system.patch.command} />
                  </div>
                {/if}
                {#if system.kernel}
                  <span class="mt-1 block text-muted-foreground">{t("situation.kernel")}</span>
                {/if}
                {#if system.container && system.fixPath === "server-image"}
                  {#if system.container.update.state === "newer-version" && system.container.update.tag}
                    <span class="mt-1 block"
                      >{t("situation.imageUpdate.newer-version", { tag: system.container.update.tag })}</span
                    >
                  {:else if system.container.update.state === "newer-build"}
                    <span class="mt-1 block">{t("situation.imageUpdate.newer-build")}</span>
                  {/if}
                {/if}
                {#if system.repository}
                  <span class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
                    {#if system.kind === "container"}
                      <span
                        >{t("situation.builtBy")}
                        <RepositoryLink id={system.repository.id} name={system.repository.name} /></span
                      >
                    {/if}
                    {#if system.fixPath === "repository-dependency" && system.packages[0]}
                      <a
                        class="underline underline-offset-4"
                        href={href("/fixes", { repositoryId: system.repository.id, q: system.packages[0].name })}
                        >{t("situation.fixProposal")}</a
                      >
                    {/if}
                    {#if system.repository.findingId}
                      <a
                        class="underline underline-offset-4"
                        href={href("/findings", { id: system.repository.findingId })}>{t("situation.openFinding")}</a
                      >
                    {/if}
                  </span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if shown.length === 0}
        <p class="px-5 py-6 text-muted-foreground">{t("situation.noSystems")}</p>
      {/if}
      {#if data.truncated > 0}
        <p class="border-t px-5 py-3 text-sm text-muted-foreground">
          {t("situation.truncated", { count: data.truncated })}
        </p>
      {/if}
    </Card>

    {#if data.notChecked.length > 0}
      <Card>
        <CardHeader title={t("situation.notCheckedTitle")} description={t("situation.notCheckedText")} />
        <table class="w-full text-left text-sm" data-testid="situation-not-checked">
          <tbody>
            {#each data.notChecked as row (`${row.kind}:${row.id}:${row.name}`)}
              <tr class="border-t align-top">
                <td class="w-40 px-5 py-2.5 text-muted-foreground">{t(`situation.kind.${row.kind}`)}</td>
                <td class="px-3 py-2.5">
                  <a class="font-medium break-all underline-offset-4 hover:underline" href={systemHref(row.kind, row.id)}
                    >{row.name}</a
                  >
                </td>
                <td class="px-5 py-2.5">{t(`situation.reason.${row.reason}`)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </Card>
    {/if}

    {#if data.vulnerability.description || data.vulnerability.urls.length > 0}
      <Card>
        <CardHeader title={t("situation.about")} />
        <div class="grid gap-3 px-5 pb-5 text-sm" data-testid="situation-about">
          {#if data.vulnerability.description}
            <p class="max-w-prose whitespace-pre-line">{data.vulnerability.description}</p>
          {/if}
          {#if data.vulnerability.urls.length > 0}
            <div>
              <span class="font-medium">{t("situation.sources")}</span>
              <ul class="mt-1 grid gap-1">
                {#each data.vulnerability.urls as url (url)}
                  <li>
                    <a class="break-all underline underline-offset-4" href={url} rel="noopener noreferrer" target="_blank"
                      >{url}</a
                    >
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
        </div>
      </Card>
    {/if}
  </div>
{/if}
