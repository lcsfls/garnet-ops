<script lang="ts">
  import { ArrowRight, ExternalLink, GitPullRequest, TriangleAlert, X } from "@lucide/svelte";
  import { type CreateVia, camelCode, PR_TONE, safeHttpsUrl } from "../../fixes.ts";
  import { formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { FixProposalRow } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /** The full story of one proposal: the change, what it fixes, why it is by hand, the AI suggestion, the pull request. */
  let {
    proposal: p,
    canCreate,
    onCreate,
    onClose,
  }: {
    proposal: FixProposalRow;
    canCreate: boolean;
    onCreate: (via: CreateVia) => void;
    onClose?: () => void;
  } = $props();

  const prUrl = $derived(safeHttpsUrl(p.pr?.url ?? null));
</script>

{#snippet close()}
  <button
    type="button"
    onclick={onClose}
    aria-label={t("fixes.detailClose")}
    class="grid size-8 place-items-center rounded-md hover:bg-accent"
  >
    <X aria-hidden="true" class="size-4" />
  </button>
{/snippet}

<Card class="self-start">
  <CardHeader
    title={p.packageName}
    description={`${p.repositoryName} · ${p.packageType}`}
    actions={onClose ? close : undefined}
  />
  <div class="grid gap-4 px-5 pb-5">
    <section aria-label={t("fixes.detailChange")} class="grid gap-1.5">
      <h3 class="text-sm font-medium text-muted-foreground">{t("fixes.detailChange")}</h3>
      <div class="flex flex-wrap items-center gap-2 font-mono">
        {p.installedVersion}
        <ArrowRight aria-hidden="true" class="size-4 text-muted-foreground" />
        {#if p.targetVersion !== null}
          {p.targetVersion}
        {:else}
          <span class="font-sans text-muted-foreground">{t("fixes.noVersion")}</span>
        {/if}
        {#if p.majorUpgrade}
          <Badge tone="outline" class="font-sans">
            <TriangleAlert aria-hidden="true" />
            {t("fixes.majorUpgrade")}
          </Badge>
        {/if}
      </div>
      {#if p.majorUpgrade}<p class="text-sm text-muted-foreground">{t("fixes.majorHint")}</p>{/if}
      {#if p.manifestPath}
        <dl class="mt-1 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted-foreground">{t("fixes.detailFile")}</dt>
          <dd class="font-mono break-all">{p.manifestPath}</dd>
          {#if p.currentSpec}
            <dt class="text-muted-foreground">{t("fixes.detailRequirement")}</dt>
            <dd class="font-mono break-all">{p.currentSpec}{p.newSpec ? ` → ${p.newSpec}` : ""}</dd>
          {/if}
          <dt class="text-muted-foreground">{t("fixes.detailDependency")}</dt>
          <dd>
            {p.dependency === "direct"
              ? t("fixes.direct")
              : p.dependency === "transitive"
                ? t("fixes.transitive")
                : t("fixes.unknownDependency")}{p.dev ? ` · ${t("fixes.dev")}` : ""}
          </dd>
        </dl>
      {/if}
    </section>

    <section aria-label={t("fixes.detailVulnerabilities")} class="grid gap-1.5">
      <h3 class="text-sm font-medium text-muted-foreground">{t("fixes.detailVulnerabilities")}</h3>
      <div>
        <SeverityBadge severity={p.severity} />
      </div>
      <ul class="flex flex-wrap gap-x-3 gap-y-1">
        {#each p.vulnerabilityIds as id (id)}
          <li>
            <a
              href={href("/findings", { repositoryId: p.repositoryId, q: id })}
              class="font-mono text-sm break-all hover:underline"
            >
              {id}
            </a>
          </li>
        {/each}
      </ul>
      {#if p.unresolvedIds.length > 0}
        <p class="text-sm text-muted-foreground">
          {t("fixes.detailUnresolved")} <span class="font-mono">{p.unresolvedIds.join(", ")}</span>
        </p>
      {/if}
      <a
        href={href("/findings", { repositoryId: p.repositoryId, q: p.packageName })}
        class="text-sm font-medium text-primary-text hover:underline"
      >
        {t("fixes.showFindings")}
      </a>
    </section>

    {#if p.action === "manual" && p.reason}
      <section aria-label={t("fixes.detailManual")} class="grid gap-1">
        <h3 class="text-sm font-medium text-muted-foreground">{t("fixes.detailManual")}</h3>
        <p>{t(`fixes.reason.${camelCode(p.reason)}` as MessageKey)}</p>
      </section>
    {/if}

    {#if p.aiSuggestion}
      <section aria-label={t("fixes.aiLabel")} class="grid gap-1.5 rounded-md border bg-muted/40 p-3">
        <h3 class="flex flex-wrap items-center gap-2 text-sm font-medium">
          <Badge tone="outline">{t("fixes.aiLabel")}</Badge>
          <span class="font-normal text-muted-foreground">
            {t("fixes.aiConfidence", { confidence: t(`fixes.confidence.${p.aiSuggestion.confidence}`) })}
          </span>
        </h3>
        <!-- Plain text only: it is written by a model and never rendered as markup. -->
        <p class="whitespace-pre-wrap">{p.aiSuggestion.summary}</p>
        {#if p.aiSuggestion.recommendation}
          <p class="whitespace-pre-wrap">{p.aiSuggestion.recommendation}</p>
        {/if}
        {#if p.aiSuggestion.upgradeTo && p.aiSuggestion.upgradeTo !== p.targetVersion}
          <p class="text-sm text-muted-foreground">
            {t("fixes.aiDifferentVersion", {
              version: p.aiSuggestion.upgradeTo,
              target: p.targetVersion ?? "–",
            })}
          </p>
        {/if}
        <p class="text-sm text-muted-foreground">{t("fixes.aiReadOnly")}</p>
      </section>
    {/if}

    {#if p.pr}
      <section aria-label={t("fixes.detailPr")} class="grid gap-1.5">
        <h3 class="text-sm font-medium text-muted-foreground">{t("fixes.detailPr")}</h3>
        <div class="flex flex-wrap items-center gap-2">
          <Badge tone={PR_TONE[p.pr.state]}>{t(`fixes.prState.${p.pr.state}`)}</Badge>
          {#if prUrl && p.pr.number !== null}
            <a
              href={prUrl}
              target="_blank"
              rel="noopener noreferrer"
              class="inline-flex items-center gap-1 font-medium text-primary-text hover:underline"
            >
              {t("fixes.prNumber", { number: p.pr.number })}
              <ExternalLink aria-hidden="true" class="size-3.5" />
              <span class="sr-only">{t("fixes.openOnForge")}</span>
            </a>
          {/if}
        </div>
        {#if p.pr.state === "failed" && p.pr.reason}
          <p class="text-sm text-destructive-text">
            {t(`fixes.failure.${camelCode(p.pr.reason)}` as MessageKey)}
          </p>
        {/if}
        <p class="text-sm text-muted-foreground">
          {p.pr.requestedBy ? `${p.pr.requestedBy} · ` : ""}{p.pr.lastCheckedAt
            ? t("fixes.prChecked", { when: formatRelative(p.pr.lastCheckedAt) })
            : t("fixes.prNotChecked")}
        </p>
      </section>
    {/if}

    {#if canCreate && p.pr?.state !== "merged" && (p.creatableViaConnection || p.creatable)}
      <div class="flex flex-wrap gap-2">
        {#if p.creatableViaConnection && p.connection}
          <Button onclick={() => onCreate("connection")}>
            <GitPullRequest aria-hidden="true" class="size-4" />
            {p.connection.accountLogin
              ? t("fixes.createPrAs", { login: p.connection.accountLogin })
              : t("fixes.createPrAsAccount")}
          </Button>
        {/if}
        {#if p.creatable}
          <Button
            variant={p.creatableViaConnection ? "outline" : "primary"}
            onclick={() => onCreate("repository")}
          >
            <GitPullRequest aria-hidden="true" class="size-4" />
            {p.creatableViaConnection ? t("fixes.createPrWithToken") : t("fixes.createPr")}
          </Button>
        {/if}
      </div>
    {/if}
  </div>
</Card>
