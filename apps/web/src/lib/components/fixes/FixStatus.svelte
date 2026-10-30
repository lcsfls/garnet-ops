<script lang="ts">
  import { ExternalLink, GitPullRequest } from "@lucide/svelte";
  import { type CreateVia, camelCode, PR_TONE, safeHttpsUrl } from "../../fixes.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { FixProposalRow } from "../../types.ts";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";

  /** What can be done with a proposal, in one cell: its pull request, the button, or why not. */
  let {
    row: p,
    canCreate,
    admin,
    onCreate,
  }: {
    row: FixProposalRow;
    canCreate: boolean;
    admin: boolean;
    onCreate: (via: CreateVia) => void;
  } = $props();

  const url = $derived(safeHttpsUrl(p.pr?.url ?? null));
  // The viewer's own connected account can open it in their name (ADR 0039).
  const viaConnection = $derived(p.creatableViaConnection && p.connection !== null && canCreate);
</script>

{#if p.pr && p.pr.state !== "failed" && p.pr.state !== "closed"}
  <div class="grid gap-1">
    <Badge tone={PR_TONE[p.pr.state]}>{t(`fixes.prState.${p.pr.state}`)}</Badge>
    {#if url && p.pr.number !== null}
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        class="inline-flex items-center gap-1 text-sm font-medium text-primary-text hover:underline"
      >
        {t("fixes.prNumber", { number: p.pr.number })}
        <ExternalLink aria-hidden="true" class="size-3.5" />
        <span class="sr-only">{t("fixes.openOnForge")}</span>
      </a>
    {/if}
  </div>
{:else if p.action === "manual"}
  <div class="grid gap-1">
    <Badge tone="neutral">{t("fixes.manualBadge")}</Badge>
    {#if p.reason}
      <span class="text-sm text-muted-foreground">
        {t(`fixes.reason.${camelCode(p.reason)}` as MessageKey)}
      </span>
    {/if}
  </div>
{:else}
  <div class="grid justify-items-start gap-1.5">
    {#if p.pr?.state === "failed"}
      <span class="text-sm text-destructive-text"
        >{t(`fixes.prState.failed`)}{p.pr.reason
          ? `: ${t(`fixes.failure.${camelCode(p.pr.reason)}` as MessageKey)}`
          : ""}</span
      >
    {/if}
    {#if viaConnection}
      <Button variant="outline" class="h-8 px-3 text-sm" onclick={() => onCreate("connection")}>
        <GitPullRequest aria-hidden="true" class="size-4" />
        {p.connection?.accountLogin
          ? t("fixes.createPrAs", { login: p.connection.accountLogin })
          : t("fixes.createPrAsAccount")}
      </Button>
    {/if}
    {#if p.writeAccess === "on" && canCreate}
      <Button variant="outline" class="h-8 px-3 text-sm" onclick={() => onCreate("repository")}>
        <GitPullRequest aria-hidden="true" class="size-4" />
        {viaConnection ? t("fixes.createPrWithToken") : t("fixes.createPr")}
      </Button>
    {:else if viaConnection}
      <!-- The viewer's own account opens it: the repository's write token is not needed here. -->
    {:else if p.writeAccess === "failed"}
      <span class="text-sm text-muted-foreground">{t("fixes.writeFailed")}</span>
    {:else if p.writeAccess === "off"}
      <span class="text-sm text-muted-foreground"
        >{t("fixes.writeOff")}{#if admin}{" · "}<a
            href="/repositories/{encodeURIComponent(p.repositoryId)}"
            class="font-medium text-primary-text hover:underline">{t("fixes.turnOnWriteAccess")}</a
          >{/if}</span
      >
    {/if}
  </div>
{/if}
