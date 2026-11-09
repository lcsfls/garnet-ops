<script lang="ts">
  import { SECRET_SEVERITIES } from "@garnetops/core/secrets";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { RepositorySecrets } from "../../secrets.ts";
  import type { Me } from "../../session.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Button from "../ui/Button.svelte";
  import ButtonLink from "../ui/ButtonLink.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";

  /**
   * A repository's secrets (ADR 0049): what is open, whether the last scan checked, and the history: on every scan (admins, or
   * the owner of a private repository) or once now (members and above).
   */
  let { repo, me }: { repo: RepositoryDetail; me: Me } = $props();
  const queryClient = useQueryClient();
  const key = $derived(["repository-secrets", repo.id]);
  const secrets = createQuery(() => ({
    queryKey: key,
    queryFn: () => api<RepositorySecrets>(`/repositories/${repo.id}/secrets`),
  }));
  const canSetHistory = $derived(isAdmin(me) || (repo.mine && repo.visibility === "private"));
  const canCheck = $derived(me.role !== "viewer");
  const total = $derived(Object.values(secrets.data?.open ?? {}).reduce((sum, n) => sum + (n ?? 0), 0));

  const history = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api<RepositorySecrets>(`/repositories/${repo.id}/secrets/history`, {
        method: "PUT",
        body: { enabled },
      }),
    onSuccess: (next: RepositorySecrets) => queryClient.setQueryData(key, next),
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const check = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}/secrets/history-check`, { method: "POST" }),
    onSuccess: async () => {
      toast.success(t("secrets.card.checkQueued"));
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
    },
    onError: (e: Error) => {
      const code = e instanceof ApiError ? e.code : null;
      toast.error(
        code === "rate-limited"
          ? t("secrets.card.checkRecent")
          : code === "scan-running"
            ? t("secrets.card.checkRunning")
            : t("errors.actionFailed"),
      );
    },
  }));
</script>

<Card>
  <div data-testid="repository-secrets">
    <CardHeader title={t("secrets.card.title")} description={t("secrets.card.description")} />
    <QueryStatus query={secrets} />
    {#if secrets.data}
      {@const s = secrets.data}
      <div class="grid gap-3 px-5 pb-5 text-sm">
        {#if s.lastCheck === "skipped" || s.lastCheck === "failed"}
          <p class="text-muted-foreground">
            {t("secrets.card.notChecked", { reason: t(`secrets.card.reason.${s.lastCheck}`) })}
          </p>
        {/if}
        {#if total === 0}
          <p>{t("secrets.card.none")}</p>
        {:else}
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{t("secrets.card.open", { count: total })}</span>
            {#each SECRET_SEVERITIES as severity (severity)}
              {#if s.open[severity]}
                <span class="inline-flex items-center gap-1">
                  <SeverityBadge {severity} /><span class="tabular-nums">{s.open[severity]}</span>
                </span>
              {/if}
            {/each}
            <ButtonLink class="ml-auto h-9 text-sm" href={href("/secrets", { repositoryId: repo.id })}>
              {t("secrets.card.show")}
            </ButtonLink>
          </div>
        {/if}
        <div class="grid gap-1 border-t pt-3">
          <label class="flex items-center gap-2 font-medium">
            <Checkbox
              checked={s.history.enabled}
              disabled={!canSetHistory || history.isPending}
              onchange={(e) => history.mutate(e.currentTarget.checked)}
              aria-describedby="secret-history-hint"
            />
            {t("secrets.card.history")}
          </label>
          <p id="secret-history-hint" class="text-muted-foreground">{t("secrets.card.historyHint")}</p>
          <p class="text-muted-foreground">
            {s.history.checkedAt
              ? t("secrets.card.historyChecked", { when: formatRelative(s.history.checkedAt) })
              : t("secrets.card.historyNever")}
          </p>
          {#if canCheck && !s.history.enabled}
            <div>
              <Button disabled={check.isPending} onclick={() => check.mutate()}>{t("secrets.card.checkNow")}</Button>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</Card>
