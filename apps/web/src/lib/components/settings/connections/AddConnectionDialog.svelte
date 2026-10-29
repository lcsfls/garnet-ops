<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import type { ForgeConnection, ForgeKind } from "../../../types.ts";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Field from "../../ui/Field.svelte";
  import Select from "../../ui/Select.svelte";

  const FORGES: ForgeKind[] = ["github", "gitea", "forgejo"];

  /**
   * Connects the signed-in person's account on a forge (ADR 0030), or replaces the token of one of their connections.
   * Mounted fresh each time it opens; the token never stays in the page after saving.
   */
  let {
    me,
    replacing,
    onClose,
    onDone,
  }: {
    me: Me;
    /** The connection whose token is replaced; without it a new account is connected. */
    replacing?: ForgeConnection;
    onClose: () => void;
    onDone: (connection: ForgeConnection | null) => void;
  } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let forge = $state<ForgeKind>("github");
  let webBaseUrl = $state("https://github.com");
  let apiBaseUrl = $state("");
  let token = $state("");
  let error = $state<string | null>(null);
  let fieldErrors = $state<{ web?: string; api?: string; token?: string }>({});

  function chooseForge(value: ForgeKind) {
    // The address follows the forge until somebody types their own.
    if (value === "github" && webBaseUrl === "") webBaseUrl = "https://github.com";
    if (value !== "github" && webBaseUrl === "https://github.com") webBaseUrl = "";
    forge = value;
  }

  const save = createMutation(() => ({
    mutationFn: () =>
      replacing
        ? api<null>(`/forge-connections/${replacing.id}/token`, { method: "PUT", body: { token } })
        : api<ForgeConnection>("/forge-connections", {
            method: "POST",
            body: { forgeKind: forge, webBaseUrl, apiBaseUrl: apiBaseUrl.trim() || undefined, token },
          }),
    onMutate: () => {
      error = null;
      fieldErrors = {};
    },
    onSuccess: async (connection: ForgeConnection | null) => {
      token = "";
      await queryClient.invalidateQueries({ queryKey: ["forge-connections"] });
      onDone(connection);
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      error = null;
      fieldErrors = {};
      const code = e instanceof ApiError ? e.code : null;
      if (code === "invalid-web-address") fieldErrors = { web: t("connections.invalidWeb") };
      else if (code === "invalid-api-address") fieldErrors = { api: t("connections.invalidApi") };
      else if (code === "duplicate") error = t("connections.duplicate");
      else if (
        e instanceof ApiError &&
        e.status === 422 &&
        (e.problem?.errors ?? []).some((x) => x.path.startsWith("token"))
      ) {
        fieldErrors = { token: t("connections.invalidToken") };
      } else error = t("connections.failed");
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (token.trim().length >= 8 && (replacing || webBaseUrl.trim())) save.mutate();
  }
</script>

<Dialog
  open
  {onClose}
  title={replacing ? t("connections.replaceTitle", { forge: replacing.webBaseUrl }) : t("connections.add")}
  description={replacing ? undefined : t("connections.description")}
>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {#if !replacing}
      <div class="grid gap-1.5">
        <label for="fc-forge" class="text-sm font-medium">{t("connections.forge")}</label>
        <Select
          id="fc-forge"
          value={forge}
          onchange={(e) => chooseForge(e.currentTarget.value as ForgeKind)}
          class="max-w-64"
        >
          {#each FORGES as k (k)}
            <option value={k}>{t(`repository.writeAccess.forgeNames.${k}`)}</option>
          {/each}
        </Select>
      </div>
      <Field
        label={t("connections.webAddress")}
        hint={t("connections.webAddressHint")}
        error={fieldErrors.web}
        bind:value={webBaseUrl}
        type="url"
        inputmode="url"
        spellcheck={false}
        autocomplete="off"
        required
        class="font-mono text-sm"
      />
      <details class="text-sm">
        <summary class="cursor-pointer text-muted-foreground hover:text-foreground">{t("connections.advanced")}</summary>
        <div class="mt-3">
          <Field
            label={t("connections.apiAddress")}
            hint={t("connections.apiAddressHint")}
            error={fieldErrors.api}
            bind:value={apiBaseUrl}
            spellcheck={false}
            autocomplete="off"
            class="font-mono text-sm"
          />
        </div>
      </details>
    {/if}
    <Field
      label={t("connections.token")}
      hint={t("connections.tokenHint")}
      error={fieldErrors.token}
      type="password"
      name="connection-token"
      bind:value={token}
      autocomplete="off"
      spellcheck={false}
      required
      minlength={8}
      maxlength={500}
      class="font-mono"
    />
    <div class="grid gap-1.5 rounded-md border bg-muted/40 px-3 py-2.5 text-sm">
      <b>{t("connections.scopesTitle")}</b>
      {#if (replacing?.forgeKind ?? forge) === "github"}
        <p>{t("connections.scopesGithub")}</p>
      {:else}
        <p>{t("connections.scopesGitea")}</p>
      {/if}
    </div>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
      <Button type="submit" disabled={save.isPending || token.trim().length < 8}>
        {save.isPending ? t("connections.connecting") : replacing ? t("connections.saveToken") : t("connections.connect")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
<StepUpPrompt {stepUp} email={me.user.email} />
