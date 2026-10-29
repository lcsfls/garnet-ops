<script lang="ts">
  import { KeyRound, ListChecks, Plus, RefreshCw, Trash2, TriangleAlert } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatRelative } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { isAdmin } from "../../../nav.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { AvailableForgeApp, ForgeConnection } from "../../../types.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import QueryStatus from "../../QueryStatus.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import ConfirmDialog from "../../ui/ConfirmDialog.svelte";
  import AddConnectionDialog from "./AddConnectionDialog.svelte";
  import RepositoryPicker from "./RepositoryPicker.svelte";
  import SignInAppsCard from "./SignInAppsCard.svelte";
  import SignInDialog from "./SignInDialog.svelte";

  const KNOWN_PROBLEMS = [
    "token-rejected",
    "sign-in-expired",
    "forbidden",
    "rate-limited",
    "timeout",
    "tls",
    "unresolvable",
    "address-refused",
    "connection-failed",
  ] as const;

  /**
   * Settings → Connected accounts (ADR 0030): the signed-in person's own accounts on GitHub, Gitea or Forgejo. Each
   * lists the repositories it can see; picking them adds them private to the person. Nobody else sees this list.
   */
  let { me }: { me: Me } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const canEdit = $derived(me.role !== "viewer");
  const connections = createQuery(() => ({
    queryKey: ["forge-connections"],
    queryFn: () => api<ForgeConnection[]>("/forge-connections"),
    // A new token is checked by the worker a moment later.
    refetchInterval: (query: { state: { data?: ForgeConnection[] } }) =>
      query.state.data?.some((c) => c.state === "unchecked") ? 2000 : false,
  }));
  // Forges an admin set up for signing in (ADR 0031); without any, connecting means pasting a token.
  const apps = createQuery(() => ({
    queryKey: ["forge-apps-available"],
    queryFn: () => api<AvailableForgeApp[]>("/forge-apps/available"),
  }));
  let choosing = $state(false);
  let adding = $state(false);
  let replacing = $state<ForgeConnection | null>(null);
  let picking = $state<ForgeConnection | null>(null);
  let removing = $state<ForgeConnection | null>(null);
  let removeRepositories = $state(false);

  const refresh = createMutation(() => ({
    mutationFn: (id: string) => api(`/forge-connections/${id}/refresh`, { method: "POST" }),
    onSuccess: async () => {
      toast.success(t("connections.refreshQueued"));
      await queryClient.invalidateQueries({ queryKey: ["forge-connections"] });
    },
    onError: (e: Error) =>
      toast.error(
        e instanceof ApiError && e.status === 429 ? t("errors.tooManyAttempts") : t("errors.actionFailed"),
      ),
  }));
  const remove = createMutation(() => ({
    mutationFn: (input: { id: string; repositories: boolean }) =>
      api(`/forge-connections/${input.id}?removeRepositories=${input.repositories ? "1" : "0"}`, {
        method: "DELETE",
      }),
    onSuccess: async () => {
      removing = null;
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["forge-connections"] }),
        queryClient.invalidateQueries({ queryKey: ["repositories"] }),
      ]);
    },
    onError: (e: Error, input: { id: string; repositories: boolean }) => {
      stepUp.handled(e, () => remove.mutate(input));
    },
  }));

  function problemText(code: string | null): string {
    const known = KNOWN_PROBLEMS.find((p) => p === code);
    return known ? t(`connections.problems.${known}`) : t("connections.problemOther", { code: code ?? "" });
  }
</script>

<Card>
  <CardHeader title={t("connections.title")} description={t("connections.description")}>
    {#snippet actions()}
      {#if canEdit}
        <Button
          variant="outline"
          onclick={() => {
            if ((apps.data ?? []).length > 0) choosing = true;
            else adding = true;
          }}
        >
          <Plus aria-hidden="true" class="size-4" />
          {t("connections.add")}
        </Button>
      {/if}
    {/snippet}
  </CardHeader>
  {#if !canEdit}<p class="px-5 pb-3 text-sm text-muted-foreground">{t("connections.viewerHint")}</p>{/if}
  <QueryStatus query={connections} />
  {#if connections.data && connections.data.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("connections.empty")}</p>
  {/if}
  <ul>
    {#each connections.data ?? [] as c (c.id)}
      <li class="grid gap-2 border-t px-5 py-3" data-testid="forge-connection">
        <div class="flex flex-wrap items-start gap-3">
          <div class="min-w-0 flex-[1_1_18rem]">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium">{t(`repository.writeAccess.forgeNames.${c.forgeKind}`)}</span>
              <span class="font-mono text-sm break-all text-muted-foreground">{c.webBaseUrl}</span>
              <Badge tone="neutral">
                {c.authMethod === "sign-in" ? t("connections.authSignIn") : t("connections.authToken")}
              </Badge>
            </div>
            <div class="mt-0.5 text-sm" aria-live="polite">
              {#if c.state === "unchecked"}
                <span class="text-muted-foreground">{t("connections.stateUnchecked")}</span>
              {:else if c.state === "ok"}
                <span>{t("connections.stateOk", { login: c.accountLogin ?? "" })}</span>
                <span class="text-muted-foreground">
                  · {t("connections.repositoryCount", { count: c.repositories })}
                  {#if c.lastCheckedAt}· {t("connections.lastChecked", { when: formatRelative(c.lastCheckedAt) })}{/if}
                </span>
              {:else}
                <span class="text-destructive-text">{t("connections.stateFailed")}: {problemText(c.problem)}</span>
              {/if}
            </div>
            {#if c.broadToken}
              <div class="mt-1 flex items-start gap-1.5 text-[13px] text-warning-text">
                <TriangleAlert aria-hidden="true" class="mt-0.5 size-3.5 flex-none" />{t("connections.broadToken")}
              </div>
            {/if}
          </div>
          {#if canEdit}
            <Button disabled={c.state !== "ok"} onclick={() => (picking = c)}>
              <ListChecks aria-hidden="true" class="size-4" />
              {t("connections.choose")}
            </Button>
            <Button
              variant="outline"
              class="h-9"
              disabled={refresh.isPending || c.state === "unchecked"}
              onclick={() => refresh.mutate(c.id)}
            >
              <RefreshCw aria-hidden="true" class="size-4" />
              {t("connections.refresh")}
            </Button>
            {#if c.authMethod === "sign-in" && c.state === "failed" && (apps.data ?? []).length > 0}
              <Button variant="outline" class="h-9" onclick={() => (choosing = true)}>
                {t("connections.signIn.again")}
              </Button>
            {/if}
            <Button
              variant="ghost"
              class="h-9 px-2.5"
              aria-label={`${t("connections.replaceToken")}: ${c.webBaseUrl}`}
              title={t("connections.replaceToken")}
              onclick={() => (replacing = c)}
            >
              <KeyRound aria-hidden="true" class="size-4" />
            </Button>
          {/if}
          <Button
            variant="ghost"
            class="h-9 px-2.5"
            aria-label={`${t("connections.remove")}: ${c.webBaseUrl}`}
            title={t("connections.remove")}
            onclick={() => {
              removeRepositories = false;
              removing = c;
            }}
          >
            <Trash2 aria-hidden="true" class="size-4" />
          </Button>
        </div>
      </li>
    {/each}
  </ul>
</Card>

{#if isAdmin(me)}<SignInAppsCard {me} />{/if}

{#if choosing}
  <SignInDialog
    apps={apps.data ?? []}
    onClose={() => (choosing = false)}
    onUseToken={() => {
      choosing = false;
      adding = true;
    }}
  />
{/if}
{#if adding}
  <AddConnectionDialog
    {me}
    onClose={() => (adding = false)}
    onDone={() => {
      adding = false;
    }}
  />
{/if}
{#if replacing}
  {#key replacing.id}
    <AddConnectionDialog {me} replacing={replacing} onClose={() => (replacing = null)} onDone={() => (replacing = null)} />
  {/key}
{/if}
{#if picking}
  {#key picking.id}
    <RepositoryPicker connection={picking} onClose={() => (picking = null)} />
  {/key}
{/if}
<ConfirmDialog
  open={removing !== null}
  title={t("connections.removeTitle", { forge: removing?.webBaseUrl ?? "" })}
  description={t("connections.removeDescription")}
  confirmLabel={t("connections.remove")}
  pending={remove.isPending}
  error={remove.isError && !stepUp.open ? t("errors.actionFailed") : null}
  onConfirm={() => {
    if (removing) remove.mutate({ id: removing.id, repositories: removeRepositories });
  }}
  onClose={() => (removing = null)}
>
  <label class="flex items-start gap-2 text-sm">
    <Checkbox class="mt-0.5" bind:checked={removeRepositories} />
    {t("connections.removeRepositories")}
  </label>
</ConfirmDialog>
<StepUpPrompt {stepUp} email={me.user.email} />
