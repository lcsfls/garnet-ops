<script lang="ts">
  import { ExternalLink } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { forgeRepo, newFileUrl, secretsUrl } from "../../forge-links.ts";
  import { WORKFLOW_PATH, workflowFile } from "../../gate-pipeline.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Page, RepositoryRow } from "../../types.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Select from "../ui/Select.svelte";
  import Stepper from "../ui/Stepper.svelte";

  /**
   * Quality gate in CI, step by step (ADR 0008): pick the repository, create its token (shown once, with a link to the forge's
   * secrets page), then the whole workflow file to commit, with a link that fills it in on GitHub. Nothing is sent to the forge.
   */
  let { repositoryId: initial, onClose }: { repositoryId: string | undefined; onClose: () => void } =
    $props();

  const queryClient = useQueryClient();
  const repositories = createQuery(() => ({
    queryKey: ["repositories", { pageSize: 100 }],
    queryFn: () => api<Page<RepositoryRow>>("/repositories?pageSize=100"),
  }));
  let step = $state(0);
  // svelte-ignore state_referenced_locally
  let repositoryId = $state(initial ?? "");
  let token = $state<string | null>(null);
  const repo = $derived(repositories.data?.items.find((r) => r.id === repositoryId) ?? null);
  const location = $derived(repo ? forgeRepo(repo.url) : null);
  const file = workflowFile(window.location.origin);
  const fileLink = $derived(
    location && repo?.branch ? newFileUrl(location, repo.branch, WORKFLOW_PATH, file) : null,
  );

  const create = createMutation(() => ({
    mutationFn: () =>
      api<{ token: string }>(`/gates/repositories/${repositoryId}/tokens`, {
        method: "POST",
        body: { label: t("gates.wizard.tokenLabel") },
      }),
    onSuccess: async (result: { token: string }) => {
      token = result.token;
      await queryClient.invalidateQueries({ queryKey: ["gate-tokens", repositoryId] });
    },
  }));
  const steps = $derived([
    t("gates.wizard.stepRepository"),
    t("gates.wizard.stepToken"),
    t("gates.wizard.stepWorkflow"),
  ]);
</script>

<Dialog open {onClose} title={t("gates.wizard.title")} description={t("gates.wizard.description")}>
  <div class="grid gap-5" data-testid="gate-wizard">
    <Stepper {steps} current={step} label={t("gates.wizard.steps")} doneLabel={t("gates.wizard.stepDone")} />

    {#if step === 0}
      <label class="grid gap-1.5">
        <span class="text-sm font-medium">{t("gates.repository")}</span>
        <Select value={repositoryId} onchange={(e) => (repositoryId = e.currentTarget.value)}>
          <option value="">{t("gates.chooseRepository")}</option>
          {#each repositories.data?.items ?? [] as r (r.id)}
            <option value={r.id}>{r.name}</option>
          {/each}
        </Select>
      </label>
      <p class="text-sm text-muted-foreground">{t("gates.wizard.repositoryHint")}</p>
    {:else if step === 1}
      {#if token}
        <Alert tone="info">{t("gates.tokenCreated")}</Alert>
        <code class="rounded-md bg-muted px-3 py-2 font-mono text-sm break-all" data-testid="gate-wizard-token"
          >{token}</code
        >
        <div><CopyButton text={token} /></div>
        <p class="text-sm">{t("gates.wizard.storeSecret")}</p>
        {#if location}
          <a
            href={secretsUrl(location)}
            target="_blank"
            rel="noopener noreferrer"
            class="link inline-flex items-center gap-1.5 text-sm font-medium"
          >
            {t("gates.wizard.openSecrets")}
            <ExternalLink aria-hidden="true" class="size-3.5" />
          </a>
        {/if}
      {:else}
        <p class="text-sm">{t("gates.wizard.tokenText", { name: repo?.name ?? "" })}</p>
        {#if create.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
        <div>
          <Button disabled={create.isPending} onclick={() => create.mutate()}>{t("gates.wizard.createToken")}</Button>
        </div>
      {/if}
    {:else}
      <p class="text-sm">{t("gates.wizard.workflowText", { path: WORKFLOW_PATH })}</p>
      <pre
        class="max-h-72 overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-[13px] leading-relaxed"
        data-testid="gate-wizard-workflow"><code>{file}</code></pre>
      <div class="flex flex-wrap items-center gap-3">
        <CopyButton text={file} />
        {#if fileLink}
          <a
            href={fileLink}
            target="_blank"
            rel="noopener noreferrer"
            class="link inline-flex items-center gap-1.5 text-sm font-medium"
          >
            {t("gates.wizard.createOnGithub")}
            <ExternalLink aria-hidden="true" class="size-3.5" />
          </a>
        {/if}
      </div>
      <p class="text-sm text-muted-foreground">{t("gates.wizard.after")}</p>
    {/if}

    <DialogFooter>
      {#if step > 0}
        <Button variant="outline" onclick={() => (step -= 1)}>{t("gates.wizard.back")}</Button>
      {/if}
      {#if step < 2}
        <Button disabled={(step === 0 && !repositoryId) || (step === 1 && !token)} onclick={() => (step += 1)}>
          {t("gates.wizard.next")}
        </Button>
      {:else}
        <Button onclick={onClose}>{t("gates.wizard.done")}</Button>
      {/if}
    </DialogFooter>
    {#if step === 1 && !token}
      <button type="button" class="justify-self-end text-sm text-muted-foreground hover:underline" onclick={() => (step = 2)}>
        {t("gates.wizard.haveToken")}
      </button>
    {/if}
  </div>
</Dialog>
