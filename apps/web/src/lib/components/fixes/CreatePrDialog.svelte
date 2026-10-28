<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import type { FixProposalRow } from "../../types.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";

  /**
   * Asks before GarnetOps opens a pull request (ADR 0014): what will change, on which branch, and
   * what it will not do. The request names only the repository and the proposal; the API works out
   * the version and the file again. A recent sign-in is needed.
   */
  let {
    proposal,
    me,
    onClose,
    onCreated,
  }: {
    proposal: FixProposalRow;
    me: Me;
    onClose: () => void;
    onCreated: () => void;
  } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let error = $state<string | null>(null);

  const create = createMutation(() => ({
    mutationFn: () =>
      api("/fixes/prs", { method: "POST", body: { repositoryId: proposal.repositoryId, key: proposal.key } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["fixes"] });
      onCreated();
    },
    onError: async (e: Error) => {
      if (stepUp.handled(e, () => create.mutate())) return;
      const code = e instanceof ApiError ? e.code : null;
      if (code === "already-open") error = t("fixes.create.alreadyOpen");
      else if (code === "write-access-off") error = t("fixes.create.writeOff");
      else if (code === "write-access-failed") error = t("fixes.create.writeFailed");
      else if (code === "not-editable") error = t("fixes.create.notEditable");
      else if (e instanceof ApiError && e.status === 404) error = t("fixes.create.gone");
      else if (e instanceof ApiError && e.status === 429) error = t("fixes.create.rateLimited");
      else error = t("fixes.create.failed");
      if (code === "not-editable" || (e instanceof ApiError && e.status === 404)) {
        await queryClient.invalidateQueries({ queryKey: ["fixes"] });
      }
    },
  }));
</script>

<Dialog
  open
  {onClose}
  title={t("fixes.create.title")}
  description={t("fixes.create.description", { repository: proposal.repositoryName })}
>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <ul class="grid gap-2 text-sm">
      <li>
        {t("fixes.create.change", {
          file: proposal.manifestPath ?? "",
          from: proposal.currentSpec ?? proposal.installedVersion,
          to: proposal.newSpec ?? proposal.targetVersion ?? "",
        })}
      </li>
      <li>
        {t("fixes.create.branch", {
          branch: proposal.branch ?? "",
          base: t("fixes.create.defaultBranch"),
        })}
      </li>
      {#if proposal.majorUpgrade}<li class="font-medium">{t("fixes.majorHint")}</li>{/if}
      <li class="text-muted-foreground">{t("fixes.create.lockfile")}</li>
      <li class="text-muted-foreground">{t("fixes.create.never")}</li>
    </ul>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>
        {t("common.cancel")}
      </Button>
      <Button disabled={create.isPending || create.isSuccess} onclick={() => create.mutate()}>
        {create.isPending ? t("fixes.create.working") : t("fixes.create.confirm")}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
<!-- Next to the dialog, not inside it: closing the confirmation must not close this one. -->
<StepUpPrompt {stepUp} email={me.user.email} />
