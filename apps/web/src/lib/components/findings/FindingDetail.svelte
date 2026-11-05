<script lang="ts" module>
  import type { FindingDetail as Detail } from "../../types.ts";

  /**
   * A short title from the advisory text: its first sentence, as plain text. The full text follows in the body. Without
   * a description the vulnerability id is the title.
   */
  function titleOf(data: Detail): string {
    const text = data.vulnerability.description?.trim();
    if (!text) return data.vulnerability.id;
    const first = /^(.{20,160}?[.!?])(\s|$)/s.exec(text)?.[1] ?? text;
    return first.length > 160 ? `${first.slice(0, 157).trimEnd()}…` : first;
  }

  function isHttpUrl(value: string): boolean {
    try {
      const { protocol } = new URL(value);
      return protocol === "https:" || protocol === "http:";
    } catch {
      return false;
    }
  }
</script>

<script lang="ts">
  import { ExternalLink, ShieldAlert, Sparkles, X } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import type { Snippet } from "svelte";
  import { api } from "../../api.ts";
  import { formatDate, formatDateTime, formatPercent, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import Alert from "../ui/Alert.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ButtonLink from "../ui/ButtonLink.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import FindingNotes from "./FindingNotes.svelte";
  import FindingStateActions from "./FindingStateActions.svelte";

  /**
   * Details of one finding. All text comes from scanned data (CVE descriptions, paths) and is treated as untrusted:
   * rendered as plain text only, and links only for http(s) URLs, opened without a referrer or window access.
   */
  let {
    id,
    canEdit,
    onClose,
    onAskAi,
  }: {
    id: string;
    canEdit: boolean;
    /** Absent when the pane shows the first finding by itself (xwide); then there is nothing to close. */
    onClose?: (() => void) | undefined;
    /** Opens the AI panel. Absent when the panel is already a pane of its own (xwide). */
    onAskAi?: (() => void) | undefined;
  } = $props();

  const query = createQuery(() => ({
    queryKey: ["finding", id],
    queryFn: () => api<Detail>(`/findings/${id}`),
  }));

  // Bring the pane into view when a finding is picked from further down the list.
  let pane: HTMLDivElement | undefined = $state();
  $effect(() => {
    pane?.scrollIntoView({ block: "nearest" });
  });
</script>

{#snippet fact(label: string, value: Snippet, note?: string)}
  <div class="bg-card px-5 py-3">
    <dt class="text-[13px] text-muted-foreground">{label}</dt>
    <dd class="mt-0.5 text-lg font-semibold">{@render value()}</dd>
    {#if note}<dd class="text-[13px] text-muted-foreground">{note}</dd>{/if}
  </div>
{/snippet}

{#snippet body(data: Detail)}
  {@const v = data.vulnerability}
  <!-- Mockup .facts: the three numbers that decide what to do, side by side; EPSS says what it means right there. -->
  <dl class="grid grid-cols-[repeat(auto-fit,minmax(9rem,1fr))] gap-px border-y bg-border" data-testid="finding-facts">
    {#snippet cvss()}
      {#if v.cvssScore !== null}{v.cvssScore.toFixed(1)}{:else}<span class="text-muted-foreground">–</span>{/if}
    {/snippet}
    {#snippet epss()}
      {#if v.epss !== null}{formatPercent(v.epss)}{:else}<span class="text-muted-foreground">–</span>{/if}
    {/snippet}
    {#snippet fixedIn()}
      {#if data.fixedIn?.length}
        <span class="font-mono break-all">{data.fixedIn.join(", ")}</span>
      {:else}
        <span class="text-muted-foreground">{t("findings.noFix")}</span>
      {/if}
    {/snippet}
    {@render fact(t("findings.cvss"), cvss)}
    {@render fact(t("findings.epss"), epss, t("findings.epssExplained"))}
    {@render fact(t("findings.columnFixedIn"), fixedIn)}
  </dl>
  <div class="grid gap-5 px-5 py-4">
    {#if data.state === "open" && data.fixProposal}
      <ButtonLink
        class="justify-self-start"
        data-testid="finding-fix-proposal"
        href={href("/fixes", {
          repositoryId: data.fixProposal.repositoryId,
          q: data.packageName,
          id: data.fixProposal.key,
        })}
      >
        {t("findings.fixProposal")}
      </ButtonLink>
    {/if}

    {#if v.description}<p class="whitespace-pre-line">{v.description}</p>{/if}

    {#if v.knownExploited}<Alert tone="error">{t("findings.kevHint")}</Alert>{/if}

    <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm" data-testid="finding-facts-list">
      <dt class="text-muted-foreground">{t("findings.package")}</dt>
      <dd class="font-mono break-all">
        {data.packageName}
        {data.packageVersion} <span class="font-sans text-muted-foreground">· {data.packageType}</span>
      </dd>
      <dt class="text-muted-foreground">{t("findings.locations")}</dt>
      <dd>
        <RepositoryLink id={data.repository.id} name={data.repository.name} class="font-medium" />
        {#if data.locations?.length}
          <ul class="mt-0.5 grid gap-0.5 font-mono break-all text-muted-foreground">
            <!-- Unkeyed: scanner data may list a path twice, and a duplicate key would stop the page. -->
            {#each data.locations as path}<li>{path}</li>{/each}
          </ul>
        {/if}
      </dd>
      {#if v.aliases?.length}
        <dt class="text-muted-foreground">{t("findings.aliases")}</dt>
        <dd class="font-mono break-all">{v.aliases.join(", ")}</dd>
      {/if}
      {#if data.alsoIn.length}
        <dt class="text-muted-foreground">{t("findings.alsoIn")}</dt>
        <dd>
          <ul class="grid gap-0.5" data-testid="finding-also-in">
            {#each data.alsoIn as other (other.id)}
              <li>
                <a href={href("/findings", { id: other.id, state: "all" })} class="link">{other.repositoryName}</a>
                <span class="text-muted-foreground">
                  · <span class="font-mono">{other.packageVersion}</span>{#if other.state !== "open"}
                    · {t(`findingState.${other.state}`)}{/if}
                </span>
              </li>
            {/each}
          </ul>
        </dd>
      {/if}
      <dt class="text-muted-foreground">{t("findings.advisory")}</dt>
      <dd>
        <span class="font-mono break-all">{v.id}</span>
        {#if v.publishedAt}
          <span class="text-muted-foreground"
            >· <time datetime={v.publishedAt} title={formatDateTime(v.publishedAt)}
              >{t("findings.published", { date: formatDate(v.publishedAt) })}</time
            ></span
          >
        {/if}
      </dd>
      {#if v.modifiedAt}
        <dt class="text-muted-foreground">{t("findings.modified")}</dt>
        <dd>{formatDateTime(v.modifiedAt)}</dd>
      {/if}
      {#if v.cvssVector}
        <dt class="text-muted-foreground">{t("findings.cvssVector")}</dt>
        <dd class="font-mono break-all">{v.cvssVector}</dd>
      {/if}
      <dt class="text-muted-foreground">{t("findings.columnFirstSeen")}</dt>
      <dd>{formatDateTime(data.firstSeenAt)}</dd>
    </dl>

    {#if v.urls?.length}
      <div>
        <h3 class="mb-1 text-sm font-medium">{t("findings.references")}</h3>
        <ul class="grid gap-1 text-sm">
          <!-- Unkeyed: an advisory may list an address twice, and a duplicate key would stop the page. -->
          {#each v.urls.filter(isHttpUrl) as url}
            <li>
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                class="link inline-flex items-center gap-1 break-all"
                aria-label={t("findings.externalLink", { host: new URL(url).host })}
              >
                {url}
                <ExternalLink aria-hidden="true" class="size-3.5 flex-none" />
              </a>
            </li>
          {/each}
        </ul>
      </div>
    {/if}

    <FindingNotes findingId={data.id} />

    <!-- The decisions about this finding, as real buttons: accept the risk (or reopen it), ask the AI. -->
    {#if canEdit || onAskAi}
      <div class="flex flex-wrap items-start gap-2 border-t pt-4" data-testid="finding-actions">
        {#if canEdit}<FindingStateActions {data} />{/if}
        {#if onAskAi}
          <Button onclick={onAskAi}>
            <Sparkles aria-hidden="true" class="size-4" />
            {t("ai.askAi")}
          </Button>
        {/if}
      </div>
    {/if}
  </div>
{/snippet}

<!-- Below the wide step the pane sits above the list; from wide on it sits beside it and stays in view. -->
<div
  bind:this={pane}
  class="order-first scroll-mt-6 self-start @wide:sticky @wide:top-0 @wide:order-none @wide:max-h-[calc(100dvh-8.5rem)] @wide:overflow-y-auto @wide:rounded-lg"
>
  <Card>
    <div class="flex items-start gap-3 px-5 pt-[18px] pb-3">
      <div class="min-w-0 flex-1">
        {#if query.data}
          {@const data = query.data}
          <div class="mb-2 flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={data.severity} />
            {#if data.vulnerability.knownExploited}
              <Badge tone="critical">
                <ShieldAlert aria-hidden="true" />
                {t("findings.kev")}
              </Badge>
            {/if}
            {#if data.state !== "open"}<Badge tone="neutral">{t(`findingState.${data.state}`)}</Badge>{/if}
          </div>
          <h2 class="text-[19px] leading-snug font-semibold tracking-[-0.01em] break-words">{titleOf(data)}</h2>
          <p class="mt-1 text-sm text-muted-foreground">
            <!-- The id is the title when the advisory has no text; then it is not repeated here. -->
            {#if data.vulnerability.description?.trim()}<span class="font-mono break-all">{data.vulnerability.id}</span>
              ·{/if}
            {data.repository.name} ·
            {t("findings.detected", { when: formatRelative(data.firstSeenAt) })}
          </p>
        {:else}
          <p class="text-muted-foreground">{query.isError ? t("errors.generic") : t("common.loading")}</p>
        {/if}
      </div>
      {#if onClose}
        <button
          type="button"
          onclick={onClose}
          aria-label={t("findings.close")}
          class="grid size-8 flex-none place-items-center rounded-md hover:bg-accent"
        >
          <X aria-hidden="true" class="size-4" />
        </button>
      {/if}
    </div>
    {#if query.data}{@render body(query.data)}{/if}
  </Card>
</div>
