<script lang="ts">
  import { GitPullRequest, RefreshCw, TriangleAlert } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { camelCode } from "../../fixes.ts";
  import { formatDate, formatRelative } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import RenovateDialog from "./RenovateDialog.svelte";
  import WriteAccessDialog from "./WriteAccessDialog.svelte";

  /**
   * "Fix PRs: off / on, by whom, since" on the repository page (ADR 0014): the separate write
   * token that lets GarnetOps open pull requests for this repository, and nothing else. Owners
   * and admins turn it on or off, with a recent sign-in; the token is never shown again.
   */
  let { repo, me }: { repo: RepositoryDetail; me: Me } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const admin = $derived(isAdmin(me));
  const wa = $derived(repo.writeAccess);
  const access = $derived(wa.access);
  let dialog = $state<"enable" | "replace" | null>(null);
  let turningOff = $state(false);
  let renovate = $state(false);

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["repository", repo.id] });
  const check = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}/write-access/check`, { method: "POST" }),
    onSuccess: refresh,
    onError: (e: Error) => void stepUp.handled(e, () => check.mutate()),
  }));
  const turnOff = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}/write-access`, { method: "DELETE" }),
    onSuccess: async () => {
      turningOff = false;
      await refresh();
      await queryClient.invalidateQueries({ queryKey: ["fixes"] });
    },
    onError: (e: Error) => void stepUp.handled(e, () => turnOff.mutate()),
  }));
</script>

<Card>
  <CardHeader title={t("repository.writeAccess.title")} description={t("repository.writeAccess.description")}>
    {#snippet actions()}
      <Button variant="outline" onclick={() => (renovate = true)}>{t("repository.renovate.button")}</Button>
    {/snippet}
  </CardHeader>
  <div class="grid gap-3 px-5 pb-5">
    <div class="flex flex-wrap items-center gap-2">
      <Badge tone={wa.enabled ? "info" : "neutral"}>
        <GitPullRequest aria-hidden="true" />
        {wa.enabled ? t("repository.writeAccess.on") : t("repository.writeAccess.off")}
      </Badge>
      {#if access}
        <Badge tone={access.status === "failed" ? "critical" : "neutral"}>
          {t(`repository.writeAccess.status.${access.status}`)}
        </Badge>
      {/if}
      {#if access?.checkedAt}
        <span class="text-sm text-muted-foreground">
          {t("repository.writeAccess.checkedAt", { when: formatRelative(access.checkedAt) })}
        </span>
      {/if}
    </div>

    {#if access}
      <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1.5">
        <dt class="text-muted-foreground">{t("repository.writeAccess.forge")}</dt>
        <dd>{t(`repository.writeAccess.forgeNames.${access.forgeKind}`)}</dd>
        <dt class="text-muted-foreground">{t("repository.writeAccess.apiAddress")}</dt>
        <dd class="font-mono text-sm break-all">{access.apiBaseUrl}</dd>
        <dt class="sr-only">{t("repository.writeAccess.title")}</dt>
        <dd class="col-span-2 text-sm text-muted-foreground">
          {access.enabledBy
            ? t("repository.writeAccess.enabledBy", { name: access.enabledBy, date: formatDate(access.enabledAt) })
            : t("repository.writeAccess.enabledAt", { date: formatDate(access.enabledAt) })}
        </dd>
      </dl>
    {:else}
      <p class="text-sm text-muted-foreground">
        {wa.supported ? t("repository.writeAccess.offHint") : t("repository.writeAccess.unsupported")}
      </p>
    {/if}

    {#if access?.status === "failed" && access.statusReason}
      <Alert tone="error">
        {t(`fixes.failure.${camelCode(access.statusReason)}` as MessageKey, {
          defaultValue: t("fixes.failure.unexpected"),
        })}
      </Alert>
    {/if}
    {#if access?.warning === "broad-token"}
      <div class="flex gap-2.5 rounded-md border border-warning/45 px-3 py-2.5 text-sm">
        <TriangleAlert aria-hidden="true" class="mt-0.5 size-4 flex-none text-warning-text" />
        <span>{t("repository.writeAccess.broadToken")}</span>
      </div>
    {/if}

    {#if admin}
      <div class="flex flex-wrap gap-2">
        {#if wa.enabled}
          <Button variant="outline" onclick={() => (dialog = "replace")}>{t("repository.writeAccess.replace")}</Button>
          <Button variant="outline" disabled={check.isPending} onclick={() => check.mutate()}>
            <RefreshCw aria-hidden="true" class="size-4" />
            {check.isPending ? t("repository.writeAccess.checking") : t("repository.writeAccess.check")}
          </Button>
          <Button variant="destructive" onclick={() => (turningOff = true)}>
            {t("repository.writeAccess.turnOff")}
          </Button>
        {:else if wa.supported}
          <Button onclick={() => (dialog = "enable")}>{t("repository.writeAccess.turnOn")}</Button>
        {/if}
      </div>
    {:else}
      <p class="text-sm text-muted-foreground">{t("repository.writeAccess.adminOnly")}</p>
    {/if}
  </div>

  {#if dialog}
    <WriteAccessDialog
      {repo}
      replacing={dialog === "replace"}
      {me}
      onClose={() => (dialog = null)}
      onDone={async () => {
        dialog = null;
        await refresh();
        await queryClient.invalidateQueries({ queryKey: ["fixes"] });
      }}
    />
  {/if}
  <ConfirmDialog
    open={turningOff}
    title={t("repository.writeAccess.turnOffTitle")}
    description={t("repository.writeAccess.turnOffText")}
    confirmLabel={t("repository.writeAccess.turnOffConfirm")}
    pending={turnOff.isPending}
    error={turnOff.isError && !(turnOff.error instanceof ApiError && turnOff.error.code === "step-up-required")
      ? t("errors.actionFailed")
      : null}
    onConfirm={() => turnOff.mutate()}
    onClose={() => (turningOff = false)}
  />
  <RenovateDialog repositoryId={repo.id} open={renovate} onClose={() => (renovate = false)} />
  <StepUpPrompt {stepUp} email={me.user.email} />
</Card>
