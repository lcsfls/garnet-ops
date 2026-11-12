<script lang="ts">
  import type { CodeExcerpt, CodeView } from "@garnetops/core/code-view";
  import { Code } from "@lucide/svelte";
  import { ApiError, api } from "../../api.ts";
  import { highlightLine } from "../../highlight.ts";
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";

  /**
   * The code of a finding (ADR 0048): where the package is declared and where the code imports it, read by the worker from a
   * fresh clone when asked, handed over once and kept in this page's memory only. Every line is shown as text; highlight.js
   * classes are the only markup taken from it.
   */
  let { findingId }: { findingId: string } = $props();

  type Phase =
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "done"; view: CodeView }
    | { kind: "failed"; message: string };
  let phase = $state<Phase>({ kind: "idle" });
  /** Two minutes and a bit: a clone of a large repository and a search of its sources. */
  const POLL_MS = 1000;
  const MAX_POLLS = 180;

  async function load() {
    phase = { kind: "loading" };
    try {
      const { id } = await api<{ id: string }>(`/code/findings/${findingId}`, { method: "POST" });
      for (let i = 0; i < MAX_POLLS; i++) {
        await new Promise((resolve) => setTimeout(resolve, POLL_MS));
        const answer = await api<{ state: string; result?: CodeView; error?: string | null }>(
          `/code/requests/${id}`,
        );
        if (answer.state === "done" && answer.result) {
          phase = { kind: "done", view: answer.result };
          return;
        }
        if (answer.state === "failed") {
          phase = { kind: "failed", message: answer.error ?? t("codeView.failed") };
          return;
        }
      }
      phase = { kind: "failed", message: t("codeView.timeout") };
    } catch (e) {
      phase = {
        kind: "failed",
        message:
          e instanceof ApiError && e.code === "busy"
            ? t("codeView.busy")
            : e instanceof ApiError && e.status === 429
              ? t("codeView.rateLimited")
              : t("codeView.failed"),
      };
    }
  }

  const short = (sha: string | null) => (sha ? sha.slice(0, 12) : "–");
  const roleLabel = (role: CodeExcerpt["role"]) => t(`codeView.role.${role}`);
</script>

{#snippet excerpt(e: CodeExcerpt)}
  <figure class="grid gap-1" data-testid="code-excerpt">
    <figcaption class="flex flex-wrap items-baseline gap-x-2 text-sm">
      <span class="font-mono break-all">{e.path}</span>
      <span class="text-muted-foreground">{roleLabel(e.role)}</span>
    </figcaption>
    <div class="code-view overflow-x-auto rounded-md border bg-[var(--surface-2)]">
      <table class="w-full border-collapse font-mono text-[13px] leading-5">
        <tbody>
          {#each e.lines as line, i (line.n)}
            {@const marked = e.marks.includes(line.n)}
            {#if i > 0 && line.n !== (e.lines[i - 1]?.n ?? 0) + 1}
              <tr><td colspan="2" class="px-3 text-muted-foreground" aria-label={t("codeView.gap")}>…</td></tr>
            {/if}
            <tr class={marked ? "bg-[var(--neutral-bg)]" : ""} data-marked={marked ? "true" : undefined}>
              <td
                class="w-px px-3 text-right align-top whitespace-nowrap select-none {marked
                  ? 'font-semibold text-foreground'
                  : 'text-muted-foreground'}"
              >
                {line.n}
              </td>
              <td class="pr-3 whitespace-pre">{#each highlightLine(line.text, e.language) as token, k (k)}{#if token.classes}<span
                      class={token.classes}>{token.text}</span
                    >{:else}{token.text}{/if}{/each}{#if line.cut}<span class="text-muted-foreground"> {t("codeView.cut")}</span>{/if}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </figure>
{/snippet}

<section class="grid gap-3 border-t pt-4" aria-labelledby="code-view-title" data-testid="code-viewer">
  <div class="flex flex-wrap items-center gap-2">
    <h3 id="code-view-title" class="text-sm font-medium">{t("codeView.title")}</h3>
    {#if phase.kind === "idle" || phase.kind === "failed"}
      <Button class="ml-auto h-8 px-3 text-sm" onclick={load}>
        <Code aria-hidden="true" class="size-4" />
        {t("codeView.show")}
      </Button>
    {/if}
  </div>
  {#if phase.kind === "idle"}
    <p class="text-sm text-muted-foreground">{t("codeView.hint")}</p>
  {:else if phase.kind === "loading"}
    <p class="text-sm text-muted-foreground" aria-live="polite">{t("codeView.loading")}</p>
  {:else if phase.kind === "failed"}
    <p class="text-sm" role="status">{phase.message}</p>
  {:else}
    {@const v = phase.view}
    <p class="text-sm text-muted-foreground" data-testid="code-commit">
      {t("codeView.commit", { commit: short(v.commit), branch: v.branch })}
      {#if v.scanCommit && v.commit !== v.scanCommit}
        {t("codeView.notScanCommit", { commit: short(v.scanCommit) })}
      {/if}
    </p>
    <div class="grid gap-3">
      <h4 class="text-sm font-medium">{t("codeView.declared")}</h4>
      {#if v.declarations.length === 0}
        <p class="text-sm text-muted-foreground">{t("codeView.noDeclarations")}</p>
      {/if}
      {#each v.declarations as e (e.path)}{@render excerpt(e)}{/each}
    </div>
    <div class="grid gap-3">
      <h4 class="text-sm font-medium">{t("codeView.used")}</h4>
      {#if !v.search.ran}
        <p class="text-sm text-muted-foreground">{t("codeView.noSearch")}</p>
      {:else}
        <p class="text-sm text-muted-foreground">
          {t("codeView.usageSummary", { count: v.usageCount, files: v.usageFileCount, searched: v.search.files })}
          {t("codeView.byName")}
          {#if v.search.stopped}{t(`codeView.stopped.${v.search.stopped}`)}{/if}
        </p>
        {#each v.usages as e (e.path)}{@render excerpt(e)}{/each}
        {#if v.usageCount > v.usages.reduce((sum, u) => sum + u.marks.length, 0)}
          <p class="text-sm text-muted-foreground">{t("codeView.moreUsages")}</p>
        {/if}
      {/if}
    </div>
  {/if}
</section>
