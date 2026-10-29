<script lang="ts">
  import { Plus, Trash2 } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { ForgeApp, ForgeKind } from "../../../types.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import QueryStatus from "../../QueryStatus.svelte";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import ConfirmDialog from "../../ui/ConfirmDialog.svelte";
  import CopyButton from "../../ui/CopyButton.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Field from "../../ui/Field.svelte";
  import Select from "../../ui/Select.svelte";

  const FORGES: ForgeKind[] = ["github", "gitea", "forgejo"];

  /**
   * Settings → Connected accounts → Sign-in with a forge (owners and admins, ADR 0031): the GitHub App or OAuth2
   * application GarnetOps signs people in with, one per forge address. The client secret is write-only.
   */
  let { me }: { me: Me } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const list = createQuery(() => ({
    queryKey: ["forge-apps"],
    queryFn: () => api<{ redirectUri: string; apps: ForgeApp[] }>("/forge-apps"),
  }));
  let adding = $state(false);
  let removing = $state<ForgeApp | null>(null);
  let forge = $state<ForgeKind>("github");
  let webBaseUrl = $state("https://github.com");
  let clientId = $state("");
  let clientSecret = $state("");
  let error = $state<string | null>(null);

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["forge-apps"] }),
      queryClient.invalidateQueries({ queryKey: ["forge-apps-available"] }),
    ]);

  const add = createMutation(() => ({
    mutationFn: () =>
      api<ForgeApp>("/forge-apps", {
        method: "POST",
        body: { forgeKind: forge, webBaseUrl, clientId, clientSecret: clientSecret.trim() || undefined },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      clientSecret = "";
      adding = false;
      toast.success(t("connections.apps.added"));
      await refresh();
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => add.mutate())) return;
      const code = e instanceof ApiError ? e.code : null;
      if (code === "invalid-web-address") error = t("connections.invalidWeb");
      else if (code === "invalid-api-address") error = t("connections.invalidApi");
      else if (code === "duplicate") error = t("connections.duplicate");
      else error = t("errors.actionFailed");
    },
  }));
  const remove = createMutation(() => ({
    mutationFn: (id: string) => api(`/forge-apps/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      removing = null;
      await refresh();
    },
    onError: (e: Error, id: string) => {
      stepUp.handled(e, () => remove.mutate(id));
    },
  }));

  function open() {
    forge = "github";
    webBaseUrl = "https://github.com";
    clientId = "";
    clientSecret = "";
    error = null;
    adding = true;
  }
  function chooseForge(value: ForgeKind) {
    if (value === "github" && webBaseUrl === "") webBaseUrl = "https://github.com";
    if (value !== "github" && webBaseUrl === "https://github.com") webBaseUrl = "";
    forge = value;
  }
</script>

<Card>
  <CardHeader title={t("connections.apps.title")} description={t("connections.apps.description")}>
    {#snippet actions()}
      <Button variant="outline" onclick={open}>
        <Plus aria-hidden="true" class="size-4" />
        {t("connections.apps.add")}
      </Button>
    {/snippet}
  </CardHeader>
  <QueryStatus query={list} />
  {#if list.data && list.data.apps.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">{t("connections.apps.empty")}</p>
  {/if}
  <ul>
    {#each list.data?.apps ?? [] as a (a.id)}
      <li class="flex flex-wrap items-center gap-3 border-t px-5 py-3" data-testid="forge-app">
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{t(`repository.writeAccess.forgeNames.${a.forgeKind}`)}</span>
            <span class="font-mono text-sm break-all text-muted-foreground">{a.webBaseUrl}</span>
          </div>
          <div class="text-[13px] text-muted-foreground">
            {t("connections.apps.clientId")}: <span class="font-mono">{a.clientId}</span> ·
            {a.hasSecret ? t("connections.apps.secretStored") : t("connections.apps.noSecret")}
          </div>
        </div>
        <Button
          variant="ghost"
          class="h-9 px-2.5"
          aria-label={`${t("connections.apps.remove")}: ${a.webBaseUrl}`}
          onclick={() => (removing = a)}
        >
          <Trash2 aria-hidden="true" class="size-4" />
        </Button>
      </li>
    {/each}
  </ul>
</Card>

{#if adding}
  <Dialog open onClose={() => (adding = false)} title={t("connections.apps.add")}>
    <form
      class="grid gap-4"
      onsubmit={(e) => {
        e.preventDefault();
        add.mutate();
      }}
    >
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <div class="grid gap-1.5">
        <label for="fa-forge" class="text-sm font-medium">{t("connections.forge")}</label>
        <Select
          id="fa-forge"
          value={forge}
          onchange={(e) => chooseForge(e.currentTarget.value as ForgeKind)}
          class="max-w-64"
        >
          {#each FORGES as k (k)}
            <option value={k}>{t(`repository.writeAccess.forgeNames.${k}`)}</option>
          {/each}
        </Select>
      </div>
      <p class="rounded-md border bg-muted/40 px-3 py-2.5 text-sm">
        {forge === "github" ? t("connections.apps.githubSteps") : t("connections.apps.giteaSteps")}
      </p>
      {#if forge !== "github" && list.data}
        <div class="grid gap-1.5">
          <span class="text-sm font-medium">{t("connections.apps.redirectUri")}</span>
          <div class="flex items-center gap-2">
            <code class="min-w-0 flex-1 truncate rounded-md border bg-muted/40 px-3 py-2 text-sm">{list.data.redirectUri}</code>
            <CopyButton text={list.data.redirectUri} />
          </div>
        </div>
      {/if}
      <Field
        label={t("connections.webAddress")}
        hint={t("connections.webAddressHint")}
        bind:value={webBaseUrl}
        type="url"
        spellcheck={false}
        autocomplete="off"
        required
        class="font-mono text-sm"
      />
      <Field
        label={t("connections.apps.clientId")}
        bind:value={clientId}
        spellcheck={false}
        autocomplete="off"
        required
        class="font-mono text-sm"
      />
      <Field
        label={t("connections.apps.clientSecret")}
        hint={t("connections.apps.clientSecretHint")}
        type="password"
        name="forge-client-secret"
        bind:value={clientSecret}
        autocomplete="off"
        spellcheck={false}
        class="font-mono"
      />
      <DialogFooter>
        <Button variant="outline" onclick={() => (adding = false)}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={add.isPending || clientId.trim().length < 4 || !webBaseUrl.trim()}>
          {add.isPending ? t("common.loading") : t("connections.apps.save")}
        </Button>
      </DialogFooter>
    </form>
  </Dialog>
{/if}
<ConfirmDialog
  open={removing !== null}
  title={t("connections.apps.removeTitle", { forge: removing?.webBaseUrl ?? "" })}
  description={t("connections.apps.removeDescription")}
  confirmLabel={t("connections.apps.remove")}
  pending={remove.isPending}
  error={remove.isError && !stepUp.open ? t("errors.actionFailed") : null}
  onConfirm={() => {
    if (removing) remove.mutate(removing.id);
  }}
  onClose={() => (removing = null)}
/>
<StepUpPrompt {stepUp} email={me.user.email} />
