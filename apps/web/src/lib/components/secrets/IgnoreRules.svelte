<script module lang="ts">
  /** What the dialog starts with: empty, or taken from a secret ("ignore similar"). */
  export interface IgnoreDraft {
    repositoryId: string | null;
    pathPattern: string;
    ruleId: string;
  }
</script>

<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatDate } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { isAdmin } from "../../nav.ts";
  import type { SecretIgnoreRule } from "../../secrets.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { Page, RepositoryRow } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import Select from "../ui/Select.svelte";

  /**
   * Ignore rules for secrets (ADR 0049 addendum): kept in GarnetOps, made by admins with a reason and a recent sign-in, audited.
   * What a rule sets aside stays listed under "Ignored" and counted here; removing the rule brings it back at once.
   */
  let { me, draft = $bindable(null) }: { me: Me; draft?: IgnoreDraft | null } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const canEdit = $derived(isAdmin(me));
  const rules = createQuery(() => ({
    queryKey: ["secret-ignore-rules"],
    queryFn: () => api<{ items: SecretIgnoreRule[] }>("/secrets/ignore-rules"),
  }));
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
    enabled: draft !== null,
  }));
  let errors = $state<Record<string, string>>({});
  let removing = $state<SecretIgnoreRule | null>(null);
  let reason = $state("");

  const refresh = () =>
    Promise.all(
      [["secret-ignore-rules"], ["secrets"], ["secret"], ["secret-counts"], ["repository-secrets"]].map((queryKey) =>
        queryClient.invalidateQueries({ queryKey }),
      ),
    );
  type Body = { repositoryId: string | null; pathPattern: string; ruleId: string; reason: string };
  const create = createMutation(() => ({
    mutationFn: (body: Body) =>
      api<{ id: string; ignored: number }>("/secrets/ignore-rules", { method: "POST", body }),
    onSuccess: async (result: { ignored: number }) => {
      draft = null;
      reason = "";
      toast.success(t("secrets.ignore.created", { count: result.ignored }));
      await refresh();
    },
    onError: (e: Error, body: Body) => {
      if (stepUp.handled(e, () => create.mutate(body))) return;
      if (e instanceof ApiError && e.status === 422) {
        errors = Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path, x.message]));
      } else toast.error(t("errors.actionFailed"));
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) => api(`/secrets/ignore-rules/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      removing = null;
      toast.success(t("secrets.ignore.removed"));
      await refresh();
    },
    onError: (e: Error, id: string) => {
      if (stepUp.handled(e, () => remove.mutate(id))) return;
      toast.error(t("errors.actionFailed"));
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!draft) return;
    errors = {};
    create.mutate({
      repositoryId: draft.repositoryId,
      pathPattern: draft.pathPattern.trim(),
      ruleId: draft.ruleId.trim(),
      reason: reason.trim(),
    });
  }
</script>

<StepUpPrompt {stepUp} email={me.user.email} />
<Card>
  <div data-testid="secret-ignore-rules">
    <CardHeader title={t("secrets.ignore.title")} description={t("secrets.ignore.description")}>
      {#snippet actions()}
        {#if canEdit}
          <Button onclick={() => (draft = { repositoryId: null, pathPattern: "", ruleId: "" })}>
            {t("secrets.ignore.add")}
          </Button>
        {/if}
      {/snippet}
    </CardHeader>
    <QueryStatus query={rules} />
    {#if rules.data && rules.data.items.length === 0}
      <p class="px-5 pb-5 text-sm text-muted-foreground">{t("secrets.ignore.none")}</p>
    {:else if rules.data}
      <ul class="grid gap-3 px-5 pb-5 text-sm">
        {#each rules.data.items as rule (rule.id)}
          <li class="grid gap-1 rounded-md border px-4 py-3" data-testid="secret-ignore-rule">
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
              {#if rule.pathPattern}<span class="font-mono break-all">{rule.pathPattern}</span>{/if}
              {#if rule.ruleId}<span class="font-mono text-muted-foreground">{rule.ruleId}</span>{/if}
              <span class="text-muted-foreground">
                {rule.repositoryName ?? t("secrets.ignore.allRepositories")}
              </span>
              <span class="ml-auto">{t("secrets.ignore.ignoredCount", { count: rule.ignored })}</span>
              {#if canEdit}
                <Button class="h-8 text-sm" onclick={() => (removing = rule)}>{t("secrets.ignore.remove")}</Button>
              {/if}
            </div>
            <p class="whitespace-pre-line">{rule.reason}</p>
            <p class="text-muted-foreground">
              {t("secrets.ignore.madeBy", { name: rule.createdByName ?? "–", date: formatDate(rule.createdAt) })}
            </p>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</Card>

<Dialog
  open={draft !== null}
  onClose={() => (draft = null)}
  title={t("secrets.ignore.addTitle")}
  description={t("secrets.ignore.addDescription")}
>
  {#if draft}
    <form class="grid gap-4" onsubmit={submit}>
      <Field
        label={t("secrets.ignore.pathPattern")}
        hint={t("secrets.ignore.pathPatternHint")}
        error={errors.pathPattern}
        bind:value={draft.pathPattern}
        maxlength={200}
        class="font-mono"
      />
      <Field
        label={t("secrets.ignore.ruleId")}
        hint={t("secrets.ignore.ruleIdHint")}
        error={errors.ruleId}
        bind:value={draft.ruleId}
        maxlength={80}
        class="font-mono"
      />
      <div class="grid gap-1.5">
        <label for="ignore-repository" class="text-sm font-medium">{t("secrets.repository")}</label>
        <Select
          id="ignore-repository"
          value={draft.repositoryId ?? ""}
          onchange={(e) => draft && (draft.repositoryId = e.currentTarget.value || null)}
        >
          <option value="">{t("secrets.ignore.allRepositories")}</option>
          {#each repositories.data?.items ?? [] as r (r.id)}
            <option value={r.id}>{r.name}</option>
          {/each}
        </Select>
      </div>
      <div class="grid gap-1.5">
        <label for="ignore-reason" class="text-sm font-medium">{t("secrets.reason")}</label>
        <textarea
          id="ignore-reason"
          bind:value={reason}
          required
          minlength={10}
          maxlength={1000}
          rows={3}
          aria-describedby="ignore-reason-hint"
          class="rounded-md border border-control bg-card px-3 py-2 text-base shadow-xs"
        ></textarea>
        <p id="ignore-reason-hint" class="text-sm text-muted-foreground">{errors.reason ?? t("secrets.reasonHint")}</p>
      </div>
      <DialogFooter>
        <Button variant="secondary" onclick={() => (draft = null)}>{t("common.cancel")}</Button>
        <Button variant="primary" type="submit" disabled={create.isPending}>{t("secrets.ignore.save")}</Button>
      </DialogFooter>
    </form>
  {/if}
</Dialog>

<ConfirmDialog
  open={removing !== null}
  title={t("secrets.ignore.removeTitle")}
  description={t("secrets.ignore.removeDescription", { count: removing?.ignored ?? 0 })}
  confirmLabel={t("secrets.ignore.remove")}
  pending={remove.isPending}
  onConfirm={() => removing && remove.mutate(removing.id)}
  onClose={() => (removing = null)}
/>
