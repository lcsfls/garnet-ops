<script lang="ts">
  import type { DistributionJudgement } from "@garnetops/core/software";
  import { createQuery, keepPreviousData } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDate, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Severity } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Badge from "../ui/Badge.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /**
   * What runs (ADR 0041): advisories a newer vulnerability database brought for running images and hosts (they are findings at once),
   * and distributions whose regular security support ended or ends within 90 days.
   */
  let { state }: { state: "open" | "closed" } = $props();

  interface Warning {
    id: string;
    state: "open" | "cleared";
    kind: "image" | "kernel" | "packages";
    subjectId: string;
    subjectName: string;
    vulnerabilityId: string;
    packageName: string;
    packageVersion: string;
    fixedIn: string[];
    severity: Severity;
    knownExploited: boolean;
    detectedAt: string;
    closedAt: string | null;
  }
  interface Distribution {
    kind: "host" | "image";
    id: string;
    name: string;
    distribution: DistributionJudgement;
  }

  const list = createQuery(() => ({
    queryKey: ["early-warnings", "hosts", state],
    queryFn: () =>
      api<{
        enabled: boolean;
        items: Warning[];
        truncated: boolean;
        distributions: Distribution[];
        closedRecently: number;
      }>(href("/early-warnings/hosts", { state: state === "open" ? undefined : state })),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  }));
  const linkOf = (kind: Warning["kind"] | Distribution["kind"], id: string) =>
    kind === "image" ? `/hosts/images/${encodeURIComponent(id)}` : `/hosts/${encodeURIComponent(id)}`;
</script>

{#if state === "open" && (list.data?.distributions.length ?? 0) > 0}
  <Card class="mb-4">
    <CardHeader title={t("earlyWarnings.distributionsTitle")} description={t("earlyWarnings.distributionsText")} />
    <ul class="border-t" data-testid="early-warnings-distributions">
      {#each list.data?.distributions ?? [] as d (`${d.kind}:${d.id}`)}
        <li class="flex flex-wrap items-center gap-x-3 gap-y-1 border-b px-5 py-2.5 last:border-0">
          <a href={linkOf(d.kind, d.id)} class="font-medium break-all hover:underline">{d.name}</a>
          <span class="text-sm text-muted-foreground">{t(`earlyWarnings.subjectKind.${d.kind}`)}</span>
          <span>{d.distribution.name} {d.distribution.cycle}</span>
          {#if d.distribution.status === "endOfLife"}
            <Badge tone="high">{t("earlyWarnings.distributionEnded")}</Badge>
            {#if d.distribution.eol}
              <span class="text-sm text-muted-foreground">
                {t("earlyWarnings.distributionEndedOn", { date: formatDate(d.distribution.eol) })}
              </span>
            {/if}
          {:else}
            <Badge tone="medium">
              {t("earlyWarnings.distributionEndsIn", { days: d.distribution.daysLeft ?? 0 })}
            </Badge>
            {#if d.distribution.eol}
              <span class="text-sm text-muted-foreground">{formatDate(d.distribution.eol)}</span>
            {/if}
          {/if}
        </li>
      {/each}
    </ul>
  </Card>
{/if}

<Card>
  <p class="border-b px-5 py-3 text-sm text-muted-foreground">{t("earlyWarnings.hostsHint")}</p>
  <table class="w-full text-left">
    <thead class="text-sm text-muted-foreground">
      <tr class="border-b">
        <th class="px-5 py-2.5 font-medium">{t("earlyWarnings.columnSeverity")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnAdvisory")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnPackage")}</th>
        <th class="hidden px-3 py-2.5 font-medium @3xl:table-cell">{t("earlyWarnings.columnFixedIn")}</th>
        <th class="px-3 py-2.5 font-medium">{t("earlyWarnings.columnRunsOn")}</th>
        <th class="hidden px-5 py-2.5 font-medium @5xl:table-cell">
          {state === "open" ? t("earlyWarnings.columnDetected") : t("earlyWarnings.columnOutcome")}
        </th>
      </tr>
    </thead>
    <tbody>
      {#each list.data?.items ?? [] as w (w.id)}
        <tr class="border-b align-top last:border-0" data-testid="early-warning-host">
          <td class="px-5 py-2.5"><SeverityBadge severity={w.severity} /></td>
          <td class="px-3 py-2.5">
            <span class="font-mono text-sm break-all">{w.vulnerabilityId}</span>
            {#if w.knownExploited}
              <div class="mt-1"><Badge tone="critical">{t("earlyWarnings.knownExploited")}</Badge></div>
            {/if}
          </td>
          <td class="px-3 py-2.5 font-mono text-sm break-all">{w.packageName} {w.packageVersion}</td>
          <td class="hidden px-3 py-2.5 font-mono text-sm break-all @3xl:table-cell">
            {w.fixedIn.length ? w.fixedIn.join(", ") : "–"}
          </td>
          <td class="px-3 py-2.5">
            <a href={linkOf(w.kind, w.subjectId)} class="break-all hover:underline">{w.subjectName}</a>
            <div class="text-sm text-muted-foreground">{t(`earlyWarnings.subjectKind.${w.kind}`)}</div>
          </td>
          <td class="hidden px-5 py-2.5 text-sm text-muted-foreground @5xl:table-cell">
            {#if w.state === "cleared"}
              {t("earlyWarnings.hostCleared")}
            {:else}
              {formatRelative(w.detectedAt)}
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <QueryStatus query={list} />
  {#if list.data && list.data.items.length === 0}
    <div class="grid gap-2 px-5 py-6 text-muted-foreground" data-testid="early-warnings-empty">
      <p>{state === "open" ? t("earlyWarnings.hostsEmptyOpen") : t("earlyWarnings.hostsEmptyClosed")}</p>
      {#if state === "open" && list.data.closedRecently > 0}
        <p>{t("earlyWarnings.hostsClosedRecently", { count: list.data.closedRecently })}</p>
      {/if}
    </div>
  {/if}
  {#if list.data?.truncated}
    <p class="border-t px-5 py-3 text-sm text-muted-foreground">{t("earlyWarnings.truncated")}</p>
  {/if}
</Card>
