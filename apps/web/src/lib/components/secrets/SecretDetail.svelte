<script lang="ts">
  import { isSensitiveFileRule } from "@garnetops/core/secrets";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatDate, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { folderPattern, placeText, type SecretDetail, secretRuleName } from "../../secrets.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import Facts from "../websites/Facts.svelte";
  import type { IgnoreDraft } from "./IgnoreRules.svelte";

  /**
   * One secret (ADR 0049): what was found and where, what to do, and closing it as revoked or dismissed with a reason. The value
   * is never part of it: GarnetOps does not have it.
   */
  let {
    id,
    canEdit,
    canIgnore = false,
    onIgnoreSimilar,
  }: {
    id: string;
    canEdit: boolean;
    /** Admins can make an ignore rule from it (ADR 0049 addendum). */
    canIgnore?: boolean;
    onIgnoreSimilar?: (draft: IgnoreDraft) => void;
  } = $props();
  const queryClient = useQueryClient();
  const detail = createQuery(() => ({
    queryKey: ["secret", id],
    queryFn: () => api<SecretDetail>(`/secrets/${id}`),
  }));
  let closing = $state<"revoke" | "dismiss" | null>(null);
  let reasonError = $state<string | null>(null);

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["secrets"] }),
      queryClient.invalidateQueries({ queryKey: ["secret", id] }),
      queryClient.invalidateQueries({ queryKey: ["secret-counts"] }),
    ]);
  const close = createMutation(() => ({
    mutationFn: (body: { action: "revoke" | "dismiss"; reason: string }) =>
      api(`/secrets/${id}/${body.action}`, { method: "POST", body: { reason: body.reason } }),
    onSuccess: async () => {
      closing = null;
      toast.success(t("secrets.closed"));
      await refresh();
    },
    onError: (e: Error) => {
      if (e instanceof ApiError && e.status === 422) reasonError = e.problem?.errors?.[0]?.message ?? null;
      else toast.error(t("errors.actionFailed"));
    },
  }));
  const reopen = createMutation(() => ({
    mutationFn: () => api(`/secrets/${id}/reopen`, { method: "POST" }),
    onSuccess: refresh,
    onError: () => toast.error(t("errors.actionFailed")),
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!closing) return;
    reasonError = null;
    const form = new FormData(event.currentTarget as HTMLFormElement);
    close.mutate({ action: closing, reason: String(form.get("reason")).trim() });
  }

  const commitText = (commit: string | undefined, when: string | null | undefined) =>
    commit ? t("secrets.commit", { commit: commit.slice(0, 12), when: when ? formatDate(when) : "–" }) : "";
</script>

<Card>
  <div data-testid="secret-detail">
    <CardHeader title={t("secrets.detailTitle")} description={t("secrets.noValue")} />
    <QueryStatus query={detail} />
    {#if detail.data}
      {@const d = detail.data}
      <div class="flex flex-wrap items-center gap-2 px-5 pb-3">
        <SeverityBadge severity={d.severity} />
        <span class="font-medium {isSensitiveFileRule(d.ruleId) ? '' : 'font-mono'}">{secretRuleName(d.ruleId)}</span>
      </div>
      <Facts
        rows={[
          { label: t("secrets.rule"), text: d.ruleId, mono: true, note: t("secrets.severityRuleHint") },
          { label: t("secrets.repository"), value: repository },
          { label: t("secrets.firstSeen"), text: formatRelative(d.firstSeenAt) },
          { label: t("secrets.lastSeen"), text: formatRelative(d.lastSeenAt) },
        ]}
      />
      {#snippet repository()}<RepositoryLink id={d.repositoryId} name={d.repositoryName} />{/snippet}

      <section class="grid gap-2 border-t px-5 py-4 text-sm" aria-labelledby="secret-files">
        <h3 id="secret-files" class="font-medium">{t("secrets.inFiles")}</h3>
        {#if d.treeLocations.length === 0}
          <p class="text-muted-foreground">{t("secrets.noPlaces")}</p>
        {:else}
          <ul class="grid gap-1" data-testid="secret-places">
            {#each d.treeLocations as p, i (i)}<li class="font-mono break-all">{placeText(p)}</li>{/each}
          </ul>
          {#if d.treeLocationCount > d.treeLocations.length}
            <p class="text-muted-foreground">
              {t("secrets.morePlaces", { count: d.treeLocationCount - d.treeLocations.length })}
            </p>
          {/if}
        {/if}
        <h3 class="mt-2 font-medium">{t("secrets.inHistory")}</h3>
        {#if d.historyLocations.length === 0}
          <p class="text-muted-foreground">{t("secrets.historyNotChecked")}</p>
        {:else}
          <ul class="grid gap-1.5" data-testid="secret-history">
            {#each d.historyLocations as p, i (i)}
              <li>
                <span class="font-mono break-all">{placeText(p)}</span>
                <span class="block text-muted-foreground">{commitText(p.commit, p.committedAt)}</span>
              </li>
            {/each}
          </ul>
          {#if d.historyLocationCount > d.historyLocations.length}
            <p class="text-muted-foreground">
              {t("secrets.morePlaces", { count: d.historyLocationCount - d.historyLocations.length })}
            </p>
          {/if}
        {/if}
      </section>

      <section class="grid gap-2 border-t px-5 py-4 text-sm" aria-labelledby="secret-steps">
        <h3 id="secret-steps" class="font-medium">{t("secrets.stepsTitle")}</h3>
        <ol class="grid list-decimal gap-1.5 pl-5">
          {#if isSensitiveFileRule(d.ruleId)}<li>{t("secrets.steps.file")}</li>{/if}
          <li>{t("secrets.steps.rotate")}</li>
          <li>{t("secrets.steps.remove")}</li>
          <li>{t("secrets.steps.history")}</li>
        </ol>
      </section>

      {#if d.ignoredBy}
        <section class="grid gap-1 border-t px-5 py-4 text-sm" data-testid="secret-ignored">
          <h3 class="font-medium">{t("secrets.ignore.setAside")}</h3>
          <p class="font-mono break-all">
            {[d.ignoredBy.pathPattern, d.ignoredBy.ruleId].filter(Boolean).join(" · ")}
          </p>
          <p class="whitespace-pre-line text-muted-foreground">{d.ignoredBy.reason}</p>
        </section>
      {/if}

      <div class="flex flex-wrap items-center gap-2 border-t px-5 py-4">
        {#if canIgnore && !d.ignoredBy && onIgnoreSimilar}
          {@const first = d.treeLocations[0] ?? d.historyLocations[0]}
          <Button
            onclick={() =>
              onIgnoreSimilar?.({
                repositoryId: d.repositoryId,
                pathPattern: first ? folderPattern(first.path) : "",
                ruleId: d.ruleId,
              })}
          >
            {t("secrets.ignore.similar")}
          </Button>
        {/if}
        {#if d.state !== "open"}
          <p class="basis-full text-sm">
            <span class="font-medium">
              {t("secrets.closedBy", {
                state: t(`secrets.state.${d.state}`),
                name: d.stateByName ?? "–",
                date: d.stateAt ? formatDate(d.stateAt) : "–",
              })}
            </span>
            {#if d.stateReason}<span class="mt-1 block whitespace-pre-line">{d.stateReason}</span>{/if}
          </p>
          {#if canEdit}
            <Button disabled={reopen.isPending} onclick={() => reopen.mutate()}>{t("secrets.reopen")}</Button>
          {/if}
        {:else if canEdit}
          <Button onclick={() => ((closing = "revoke"), (reasonError = null))}>{t("secrets.revoke")}</Button>
          <Button onclick={() => ((closing = "dismiss"), (reasonError = null))}>{t("secrets.dismiss")}</Button>
        {/if}
      </div>
    {/if}
  </div>
</Card>

<Dialog
  open={closing !== null}
  onClose={() => (closing = null)}
  title={closing === "dismiss" ? t("secrets.dismissTitle") : t("secrets.revokeTitle")}
  description={closing === "dismiss" ? t("secrets.dismissDescription") : t("secrets.revokeDescription")}
>
  <form class="grid gap-4" onsubmit={submit}>
    <div class="grid gap-1.5">
      <label for="secret-reason" class="text-sm font-medium">{t("secrets.reason")}</label>
      <textarea
        id="secret-reason"
        name="reason"
        required
        minlength={10}
        maxlength={1000}
        rows={3}
        aria-describedby="secret-reason-hint"
        class="rounded-md border border-control bg-card px-3 py-2 text-base shadow-xs"
      ></textarea>
      <p id="secret-reason-hint" class="text-sm text-muted-foreground">{reasonError ?? t("secrets.reasonHint")}</p>
    </div>
    <DialogFooter>
      <Button variant="secondary" onclick={() => (closing = null)}>{t("common.cancel")}</Button>
      <Button variant="primary" type="submit" disabled={close.isPending}>
        {closing === "dismiss" ? t("secrets.dismiss") : t("secrets.revoke")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
