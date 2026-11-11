<script lang="ts">
  import { EXPOSED_FILE_PROBES } from "@garnetops/core/exposed-files";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";

  /**
   * Files that must not be public (ADR 0050). Off until an admin switches it on for a proved name; then the daily look asks for a
   * fixed list of paths and reports the ones whose content proves the file. Nothing of a file is kept.
   */
  let { detail, canEdit, email }: { detail: ExposureDetail; canEdit: boolean; email: string } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  const files = $derived(detail.exposedFiles);
  const isName = $derived(detail.kind === "domain");
  const verified = $derived(detail.verification.effective);
  let showPaths = $state(false);

  const change = createMutation(() => ({
    mutationFn: (enabled: boolean) =>
      api(`/exposure/${detail.id}/exposed-files`, { method: "PUT", body: { enabled } }),
    onSuccess: async (_: unknown, enabled: boolean) => {
      toast.success(t(enabled ? "websites.exposedFiles.switchedOn" : "websites.exposedFiles.switchedOff"));
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
    },
    onError: (e: Error, enabled: boolean) => {
      if (stepUp.handled(e, () => change.mutate(enabled))) return;
      toast.error(
        e instanceof ApiError && e.code === "not-verified"
          ? t("websites.exposedFiles.notVerified")
          : t("errors.actionFailed"),
      );
    },
  }));
</script>

<StepUpPrompt {stepUp} {email} />
<Card>
  <div data-testid="exposed-files">
    <CardHeader title={t("websites.exposedFiles.title")} description={t("websites.exposedFiles.description")} />
    <div class="grid gap-3 px-5 pb-5 text-sm">
      {#if !isName}
        <p class="text-muted-foreground">{t("websites.exposedFiles.namesOnly")}</p>
      {:else if files.enabled}
        <p>
          {t("websites.exposedFiles.on", { date: files.enabledAt ? formatDateTime(files.enabledAt) : "–" })}
        </p>
        {#if files.last}
          {#if files.last.error === "notVerified"}
            <Alert tone="error">{t("websites.exposedFiles.lostProof")}</Alert>
          {:else if files.last.error === "noHttps"}
            <p class="text-muted-foreground">{t("websites.exposedFiles.noHttps")}</p>
          {:else}
            <p class="text-muted-foreground">
              {t("websites.exposedFiles.last", {
                checked: files.last.checked,
                found: files.last.found,
                failed: files.last.failed,
              })}
            </p>
          {/if}
        {:else}
          <p class="text-muted-foreground">{t("websites.exposedFiles.noRunYet")}</p>
        {/if}
        {#if canEdit}
          <div>
            <Button disabled={change.isPending} onclick={() => change.mutate(false)}>
              {t("websites.exposedFiles.switchOff")}
            </Button>
          </div>
        {/if}
      {:else}
        <p>{t("websites.exposedFiles.off", { count: EXPOSED_FILE_PROBES.length })}</p>
        {#if !verified}
          <p class="text-muted-foreground">{t("websites.exposedFiles.needsProof")}</p>
        {:else if canEdit}
          <div>
            <Button disabled={change.isPending} onclick={() => change.mutate(true)}>
              {t("websites.exposedFiles.switchOn")}
            </Button>
          </div>
        {/if}
      {/if}
      {#if isName}
        <button
          type="button"
          class="link w-fit text-sm"
          aria-expanded={showPaths}
          onclick={() => (showPaths = !showPaths)}
        >
          {showPaths ? t("websites.exposedFiles.hidePaths") : t("websites.exposedFiles.showPaths")}
        </button>
        {#if showPaths}
          <ul class="grid gap-0.5 font-mono text-sm" data-testid="exposed-files-paths">
            {#each EXPOSED_FILE_PROBES as probe (probe.path)}<li>{probe.path}</li>{/each}
          </ul>
        {/if}
      {/if}
    </div>
  </div>
</Card>
