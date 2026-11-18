<script lang="ts">
  import { INVENTORY_TOKEN_SCOPES, type InventoryTokenScope } from "@garnetops/core/inventory";
  import { Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { InventoryTokenRow } from "../../inventory.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Field from "../ui/Field.svelte";
  import FormField from "../ui/FormField.svelte";
  import FormRow from "../ui/FormRow.svelte";
  import Select from "../ui/Select.svelte";

  /**
   * The tokens scripts fill and read the inventory with (ADR 0053), for owners and admins: created with a recent sign-in,
   * shown once, revoked here. With the two requests a script needs, ready to copy.
   */
  let { me }: { me: Me } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const key = ["inventory", "tokens"];
  const tokens = createQuery(() => ({
    queryKey: key,
    queryFn: () => api<InventoryTokenRow[]>("/inventory/tokens"),
  }));

  type Created = { token: string; scope: InventoryTokenScope };
  let created = $state<Created | null>(null);
  let revoking = $state<InventoryTokenRow | null>(null);
  let label = $state("");
  let scope = $state<InventoryTokenScope>("write");
  type Input = { label: string; scope: InventoryTokenScope };
  const create = createMutation(() => ({
    mutationFn: (input: Input) => api<Created>("/inventory/tokens", { method: "POST", body: input }),
    onSuccess: async (result: Created) => {
      created = result;
      label = "";
      await queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (e: Error, input: Input): void => {
      if (!stepUp.handled(e, () => create.mutate(input))) toast.error(t("errors.actionFailed"));
    },
  }));
  const revoke = createMutation(() => ({
    mutationFn: (id: string) => api(`/inventory/tokens/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      revoking = null;
      toast.success(t("inventory.automation.revoked"));
      await queryClient.invalidateQueries({ queryKey: key });
    },
    onError: (e: Error, id: string): void => {
      if (stepUp.handled(e, () => revoke.mutate(id))) revoking = null;
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (label.trim()) create.mutate({ label: label.trim(), scope });
  }

  /** The requests as a script sends them. The token comes from the script's environment, never from this page. */
  const base = `${window.location.origin}/api/v1/inventory-feed`;
  const reportExample = [
    `curl -fsS -X PUT "${base}/systems/$(hostname -f)" \\`,
    `  -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"kind":"server","software":[{"name":"nginx","version":"1.26.0"}]}'`,
  ].join("\n");
  const readExample = [
    `curl -fsS "${base}/systems" \\`,
    `  -H "Authorization: Bearer $GARNETOPS_INVENTORY_TOKEN"`,
  ].join("\n");
</script>

<Card class="mt-5">
  <CardHeader title={t("inventory.automation.title")} description={t("inventory.automation.text")} />
  <div class="grid gap-5 px-5 pb-5 @wide:grid-cols-2" data-testid="inventory-tokens">
    <div class="grid content-start gap-3">
      {#if created}
        <div class="grid gap-2" data-testid="inventory-token-created">
          <Alert tone="info">{t("inventory.automation.created")}</Alert>
          <code class="rounded-md bg-muted px-3 py-2 font-mono text-sm break-all">{created.token}</code>
          <div><CopyButton text={created.token} /></div>
        </div>
      {/if}
      <QueryStatus query={tokens} />
      {#if tokens.data && tokens.data.length === 0}
        <p class="text-sm text-muted-foreground">{t("inventory.automation.noTokens")}</p>
      {/if}
      <ul class="grid gap-2">
        {#each tokens.data ?? [] as token (token.id)}
          <li class="flex flex-wrap items-center gap-3 rounded-md border px-3 py-2">
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2 font-medium">
                {token.label}
                <Badge tone="outline">{t(`inventory.automation.scopeShort.${token.scope}`)}</Badge>
              </div>
              <div class="text-[13px] text-muted-foreground">
                <span class="font-mono">{token.prefix}…</span> ·
                {token.lastUsedAt
                  ? t("inventory.automation.lastUsed", { when: formatRelative(token.lastUsedAt) })
                  : t("inventory.automation.neverUsed")}
              </div>
            </div>
            <Button
              variant="destructive"
              onclick={() => (revoking = token)}
              aria-label={t("inventory.automation.revoke", { label: token.label })}
            >
              <Trash2 aria-hidden="true" class="size-4" />
              {t("inventory.automation.revokeConfirm")}
            </Button>
          </li>
        {/each}
      </ul>
      <form class="grid gap-3" onsubmit={submit}>
        <FormRow>
          <Field label={t("inventory.automation.tokenLabel")} bind:value={label} required maxlength={100} autocomplete="off" />
          <FormField label={t("inventory.automation.tokenScope")}>
            {#snippet children(c)}
              <Select {...c} bind:value={scope} class="w-full">
                {#each INVENTORY_TOKEN_SCOPES as s (s)}
                  <option value={s}>{t(`inventory.automation.scope.${s}`)}</option>
                {/each}
              </Select>
            {/snippet}
          </FormField>
        </FormRow>
        <div>
          <Button type="submit" variant="secondary" disabled={create.isPending}>{t("inventory.automation.create")}</Button>
        </div>
      </form>
    </div>
    <div class="grid content-start gap-4">
      {#each [{ title: t("inventory.automation.exampleReport"), text: reportExample }, { title: t("inventory.automation.exampleRead"), text: readExample }] as example (example.title)}
        <div class="grid gap-2">
          <h3 class="text-sm font-medium">{example.title}</h3>
          <pre class="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm">{example.text}</pre>
          <div><CopyButton text={example.text} /></div>
        </div>
      {/each}
    </div>
  </div>
  <ConfirmDialog
    open={revoking !== null}
    title={t("inventory.automation.revokeTitle", { label: revoking?.label ?? "" })}
    description={t("inventory.automation.revokeText")}
    confirmLabel={t("inventory.automation.revokeConfirm")}
    pending={revoke.isPending}
    error={revoke.isError ? t("errors.actionFailed") : null}
    onConfirm={() => revoking && revoke.mutate(revoking.id)}
    onClose={() => (revoking = null)}
  />
</Card>
<StepUpPrompt {stepUp} email={me.user.email} />
