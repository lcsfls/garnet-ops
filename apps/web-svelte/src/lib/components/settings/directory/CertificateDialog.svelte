<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import type { DirectoryServerView, DirectoryView } from "../../../directory.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import Facts from "./Facts.svelte";

  /**
   * Confirming a certificate (ADR 0020): the owner compares the fingerprint GarnetOps read with the one the directory
   * server shows, and the API pins exactly the fingerprint that was shown. A change is a security event, so the dialog
   * says so and shows both.
   */
  let { me, server, onClose }: { me: Me; server: DirectoryServerView; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let error = $state<string | null>(null);
  const candidate = $derived(server.certificate?.candidate ?? null);
  const pin = $derived(server.certificate?.pin ?? null);
  const changed = $derived(server.certificate?.status === "changed");

  const confirm = createMutation(() => ({
    mutationFn: (fingerprint: string) =>
      api<DirectoryView>("/directory/certificates/confirm", {
        method: "POST",
        body: { url: server.url, fingerprint },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["directory"] });
      onClose();
    },
    onError: async (e: Error, fingerprint: string) => {
      if (stepUp.handled(e, () => confirm.mutate(fingerprint))) return;
      if (e instanceof ApiError && e.code === "fingerprint-mismatch") {
        await queryClient.invalidateQueries({ queryKey: ["directory"] });
        error = t("directory.certMismatch");
        return;
      }
      error = t("errors.actionFailed");
    },
  }));
</script>

<Dialog
  open
  {onClose}
  title={changed ? t("directory.certChangedTitle") : t("directory.certConfirmTitle")}
  description={server.url}
>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {#if changed}<Alert tone="error">{t("directory.certChangedWarning")}</Alert>{/if}
    {#if candidate}
      <Facts label={changed ? t("directory.certNew") : t("directory.certPresented")} facts={candidate} />
    {/if}
    {#if changed && pin}<Facts label={t("directory.certPinned")} facts={pin} />{/if}
    <p class="text-sm text-muted-foreground">{t("directory.certCompare")}</p>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>
        {t("common.cancel")}
      </Button>
      <Button
        disabled={!candidate || confirm.isPending}
        onclick={() => {
          if (candidate) confirm.mutate(candidate.fingerprint);
        }}
      >
        {confirm.isPending ? t("common.loading") : t("directory.certConfirm")}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
<StepUpPrompt {stepUp} email={me.user.email} />
