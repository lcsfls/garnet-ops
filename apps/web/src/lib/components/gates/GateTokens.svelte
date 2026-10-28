<script lang="ts">
  import { Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { GateTokenRow } from "../../types.ts";
  import QueryStatus from "../QueryStatus.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Field from "../ui/Field.svelte";

  /** The pipeline tokens of one repository: created, shown once, revoked. Mounted fresh for each repository. */
  let { repositoryId }: { repositoryId: string } = $props();

  const queryClient = useQueryClient();
  const key = $derived(["gate-tokens", repositoryId]);
  const tokens = createQuery(() => ({
    queryKey: key,
    queryFn: () => api<GateTokenRow[]>(`/gates/repositories/${repositoryId}/tokens`),
  }));
  let created = $state<string | null>(null);
  let revoking = $state<GateTokenRow | null>(null);
  const create = createMutation(() => ({
    mutationFn: (label: string) =>
      api<{ token: string }>(`/gates/repositories/${repositoryId}/tokens`, {
        method: "POST",
        body: { label },
      }),
    onSuccess: async (result: { token: string }) => {
      created = result.token;
      await queryClient.invalidateQueries({ queryKey: key });
    },
  }));
  const revoke = createMutation(() => ({
    mutationFn: (id: string) => api(`/gates/repositories/${repositoryId}/tokens/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      revoking = null;
      await queryClient.invalidateQueries({ queryKey: key });
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    const label = String(new FormData(form).get("label") ?? "").trim();
    if (label) create.mutate(label, { onSuccess: () => form.reset() });
  }
</script>

<div class="grid gap-3">
  <p class="text-sm text-muted-foreground">{t("gates.tokensHint")}</p>
  {#if created}
    <div class="grid gap-2">
      <Alert tone="info">{t("gates.tokenCreated")}</Alert>
      <code class="rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">{created}</code>
      <div>
        <CopyButton text={created} />
      </div>
    </div>
  {/if}
  <QueryStatus query={tokens} />
  {#if tokens.data && tokens.data.length === 0}
    <p class="text-sm text-muted-foreground">{t("gates.tokensEmpty")}</p>
  {/if}
  <ul class="grid gap-2">
    {#each tokens.data ?? [] as token (token.id)}
      <li class="flex flex-wrap items-center gap-3 rounded-md border px-3 py-2">
        <div class="min-w-0 flex-1">
          <div class="font-medium">{token.label}</div>
          <div class="text-[13px] text-muted-foreground">
            <span class="font-mono">{token.prefix}…</span> ·
            {token.lastUsedAt ? t("gates.lastUsed", { when: formatRelative(token.lastUsedAt) }) : t("gates.neverUsed")}
          </div>
        </div>
        <Button variant="ghost" onclick={() => (revoking = token)} aria-label={`${t("gates.revoke")}: ${token.label}`}>
          <Trash2 aria-hidden="true" class="size-4" />
          {t("gates.revoke")}
        </Button>
      </li>
    {/each}
  </ul>
  <form class="grid gap-2" onsubmit={submit}>
    <Field label={t("gates.tokenLabel")} hint={t("gates.tokenLabelHint")} name="label" required maxlength={80} />
    <div>
      <Button type="submit" variant="outline" disabled={create.isPending}>{t("gates.createToken")}</Button>
    </div>
    {#if create.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
  </form>
  <ConfirmDialog
    open={revoking !== null}
    title={t("gates.revokeTitle", { label: revoking?.label ?? "" })}
    description={t("gates.revokeDescription")}
    confirmLabel={t("gates.revoke")}
    pending={revoke.isPending}
    error={revoke.isError ? t("errors.actionFailed") : null}
    onConfirm={() => revoking && revoke.mutate(revoking.id)}
    onClose={() => (revoking = null)}
  />
</div>
