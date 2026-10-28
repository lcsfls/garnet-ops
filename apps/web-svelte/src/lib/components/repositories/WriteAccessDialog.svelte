<script lang="ts">
  import { createMutation } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { defaultApiBase, repoHost } from "../../fixes.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import type { ForgeKind, RepositoryDetail } from "../../types.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import Select from "../ui/Select.svelte";

  const FORGES: ForgeKind[] = ["github", "gitea", "forgejo"];

  /** Turns fix pull requests on, or replaces the write token (ADR 0014). Mounted fresh each time it opens. */
  let {
    repo,
    replacing,
    me,
    onClose,
    onDone,
  }: {
    repo: RepositoryDetail;
    replacing: boolean;
    me: Me;
    onClose: () => void;
    onDone: () => Promise<void>;
  } = $props();

  const stepUp = new StepUp();
  const host = $derived(repoHost(repo.url));
  // The form starts from what is stored (or suggested) when the dialog opens.
  // svelte-ignore state_referenced_locally
  const stored = repo.writeAccess.access;
  // svelte-ignore state_referenced_locally
  const suggested = repo.writeAccess.suggested;
  let forge = $state<ForgeKind | "">(stored?.forgeKind ?? suggested?.forgeKind ?? "");
  let apiUrl = $state(stored?.apiBaseUrl ?? suggested?.apiBaseUrl ?? "");
  let token = $state("");
  let error = $state<string | null>(null);
  let fieldErrors = $state<{ api?: string; token?: string }>({});

  const save = createMutation(() => ({
    mutationFn: () =>
      api(`/repositories/${repo.id}/write-access`, {
        method: "PUT",
        body: { token, forgeKind: forge, apiBaseUrl: apiUrl.trim() || undefined },
      }),
    onMutate: () => {
      error = null;
      fieldErrors = {};
    },
    onSuccess: async () => {
      token = "";
      await onDone();
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => save.mutate())) return;
      if (e instanceof ApiError && e.status === 422) {
        if (e.code === "invalid-api-address") {
          fieldErrors = { api: t("repository.writeAccess.invalidApi") };
          return;
        }
        if (e.code === "unsupported-repository") {
          error = t("repository.writeAccess.unsupportedSave");
          return;
        }
        const paths = (e.problem?.errors ?? []).map((x) => x.path.split(".")[0]);
        if (paths.includes("token")) {
          fieldErrors = { token: t("repository.writeAccess.invalidToken") };
          return;
        }
        if (paths.includes("apiBaseUrl")) {
          fieldErrors = { api: t("repository.writeAccess.invalidApi") };
          return;
        }
      }
      error = t("repository.writeAccess.failed");
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (forge && token.length >= 8) save.mutate();
  }

  function chooseForge(value: ForgeKind | "") {
    forge = value;
    // The address follows the forge until somebody edits it by hand.
    if (value && host && (apiUrl === "" || FORGES.some((k) => apiUrl === defaultApiBase(k, host)))) {
      apiUrl = defaultApiBase(value, host);
    }
  }
</script>

<Dialog
  open
  {onClose}
  title={replacing ? t("repository.writeAccess.dialogTitleReplace") : t("repository.writeAccess.dialogTitle")}
  description={t("repository.writeAccess.dialogText")}
>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <div class="grid gap-1.5">
      <label for="wa-forge" class="text-sm font-medium">{t("repository.writeAccess.forgeLabel")}</label>
      <Select
        id="wa-forge"
        value={forge}
        onchange={(e) => chooseForge(e.currentTarget.value as ForgeKind | "")}
        class="max-w-64"
      >
        <option value="">{t("repository.writeAccess.forgeUnknown")}</option>
        {#each FORGES as k (k)}
          <option value={k}>{t(`repository.writeAccess.forgeNames.${k}`)}</option>
        {/each}
      </Select>
    </div>
    <Field
      label={t("repository.writeAccess.apiLabel")}
      hint={t("repository.writeAccess.apiHint")}
      error={fieldErrors.api}
      bind:value={apiUrl}
      spellcheck={false}
      autocomplete="off"
      class="font-mono text-sm"
    />
    <Field
      label={t("repository.writeAccess.tokenLabel")}
      hint={t("repository.writeAccess.tokenHint")}
      error={fieldErrors.token}
      type="password"
      name="write-token"
      bind:value={token}
      autocomplete="off"
      spellcheck={false}
      required
      minlength={8}
      maxlength={500}
      class="font-mono"
    />
    <div class="grid gap-1.5 rounded-md border bg-muted/40 px-3 py-2.5 text-sm">
      <b>{t("repository.writeAccess.scopesTitle")}</b>
      <p>{forge === "github" ? t("repository.writeAccess.scopesGithub") : null}</p>
      {#if forge === "gitea" || forge === "forgejo"}
        <p>{t("repository.writeAccess.scopesGitea")}</p>
      {/if}
      {#if forge === ""}
        <p>{t("repository.writeAccess.scopesGithub")}</p>
        <p>{t("repository.writeAccess.scopesGitea")}</p>
      {/if}
      <p class="text-muted-foreground">{t("repository.writeAccess.scopesPlain")}</p>
    </div>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
      <Button type="submit" disabled={save.isPending || !forge || token.length < 8}>
        {save.isPending ? t("repository.writeAccess.saving") : t("repository.writeAccess.save")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
<!-- Next to the dialog, not inside it: closing the confirmation must not close this one. -->
<StepUpPrompt {stepUp} email={me.user.email} />
