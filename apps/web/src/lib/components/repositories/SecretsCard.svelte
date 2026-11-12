<script lang="ts">
  import { SECRET_SEVERITIES } from "@garnetops/core/secrets";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { RepositorySecrets } from "../../secrets.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
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
  const stepUp = new StepUp();
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
  /** The repository's own gitleaks configuration (ADR 0049 addendum 2026-11-12): admins, with a recent sign-in. */
  const repoConfig = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api<RepositorySecrets>(`/repositories/${repo.id}/secrets/repo-config`, {
        method: "PUT",
        body: { enabled },
      }),
    onSuccess: async (next: RepositorySecrets) => {
      queryClient.setQueryData(key, next);
      toast.success(t(next.repoConfig.enabled ? "secrets.card.repoConfigOn" : "secrets.card.repoConfigOff"));
      await queryClient.invalidateQueries({ queryKey: ["secret-counts"] });
    },
    onError: (e: Error, enabled: boolean) => {
      if (!stepUp.handled(e, () => repoConfig.mutate(enabled))) toast.error(t("errors.actionFailed"));
    },
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

<StepUpPrompt {stepUp} email={me.user.email} />
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
        <div class="grid gap-1 border-t pt-3" data-testid="secret-repo-config">
          <label class="flex items-center gap-2 font-medium">
            <Checkbox
              checked={s.repoConfig.enabled}
              disabled={!isAdmin(me) || repoConfig.isPending}
              onchange={(e) => repoConfig.mutate(e.currentTarget.checked)}
              aria-describedby="secret-repo-config-hint"
            />
            {t("secrets.card.repoConfig")}
          </label>
          <p id="secret-repo-config-hint" class="text-muted-foreground">{t("secrets.card.repoConfigHint")}</p>
          {#if s.repoConfig.enabled}
            {@const last = s.repoConfig.last}
            {#if !last}
              <p class="text-muted-foreground">{t("secrets.card.repoConfigNextScan")}</p>
            {:else if last.problem}
              <p>
                {t("secrets.card.repoConfigProblem", {
                  reason: t(`secrets.card.repoConfigReason.${last.problem}` as MessageKey),
                })}
              </p>
            {:else}
              <p class="text-muted-foreground">
                {t("secrets.card.repoConfigLast", {
                  files: [last.file, last.ignoreFile ? ".gitleaksignore" : null].filter(Boolean).join(", ") || "–",
                  setAside: last.setAside,
                  added: last.added,
                })}
              </p>
            {/if}
          {/if}
        </div>
      </div>
    {/if}
  </div>
</Card>
