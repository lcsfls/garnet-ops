<script lang="ts">
  import { Check, Loader } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { type ExposureDetail, errorKey, verificationKey } from "../../websites.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import CopyRow from "./CopyRow.svelte";

  /**
   * The proof of control (ADR 0023): the DNS TXT record or the file an owner or admin publishes, with copy buttons, and
   * "Check now", which asks the worker and waits for its answer. The code is public by design (it is published in DNS or
   * on the website). Mounted fresh each time it opens.
   */
  let { assetId, email, onClose }: { assetId: string; email: string; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  /** From when on a check counts as the answer to "Check now", until it arrives. */
  let since = $state<number | null>(null);
  let confirmRotate = $state(false);
  let failed = $state(false);

  const detail = createQuery(() => ({
    queryKey: ["websites", "asset", assetId],
    queryFn: () => api<ExposureDetail>(`/exposure/${assetId}`),
    refetchInterval: since !== null ? 1500 : false,
  }));
  const asset = $derived(detail.data);
  const checkedAt = $derived(
    asset?.verification.checkedAt ? new Date(asset.verification.checkedAt).getTime() : 0,
  );
  const waiting = $derived(since !== null && checkedAt < since);

  // The answer arrived: the list and the page behind the dialog show it too.
  $effect(() => {
    if (since !== null && !waiting) {
      untrack(() => {
        since = null;
        void queryClient.invalidateQueries({ queryKey: ["websites"] });
      });
    }
  });

  const check = createMutation(() => ({
    mutationFn: () => api(`/exposure/${assetId}/verify`, { method: "POST" }),
    onMutate: () => {
      failed = false;
      // Wait for a check newer than the last one; a little before now, as the worker's clock may differ.
      since = Math.max(Date.now() - 5000, checkedAt + 1);
    },
    onError: () => {
      since = null;
      failed = true;
    },
  }));
  const rotate = createMutation(() => ({
    mutationFn: () => api(`/exposure/${assetId}/verify/rotate`, { method: "POST" }),
    onSuccess: async () => {
      confirmRotate = false;
      since = null;
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => rotate.mutate())) {
        confirmRotate = false;
        return;
      }
      failed = true;
    },
  }));

  const key = $derived(asset ? verificationKey(asset) : null);
  const instructions = $derived(asset?.instructions ?? null);
  const problem = $derived.by(() => {
    const code = asset?.verification.error;
    if (!code) return null;
    const k = errorKey(code);
    return k ? t(k) : code;
  });
</script>

<Dialog
  open
  {onClose}
  title={t("websites.verifyTitle", { asset: asset?.value ?? "" })}
  description={t("websites.verifyDescription")}
>
  {#if !asset || !instructions}
    <p class="text-muted-foreground">{detail.isError ? t("errors.loadFailed") : t("common.loading")}</p>
  {:else}
    <div class="grid gap-4">
      {#if failed}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
      {#if key === "verified"}
        <Alert tone="info">
          <span data-testid="verify-state">
            {t("websites.verifyVerified", {
              when: asset.verification.confirmedAt ? formatDateTime(asset.verification.confirmedAt) : "",
            })}
          </span>
        </Alert>
      {:else if key === "covered"}
        <Alert tone="info">
          <span data-testid="verify-state">
            {t("websites.verifyCovered", { parent: asset.verification.parent?.value ?? "" })}
          </span>
        </Alert>
      {:else if key === "lost"}
        <Alert tone="error"><span data-testid="verify-state">{t("websites.verifyLost")}</span></Alert>
      {/if}
      {#if !waiting && problem && key !== "verified"}
        <Alert tone="error"><span data-testid="verify-error">{problem}</span></Alert>
      {/if}

      {#if instructions.dns}
        <section class="grid gap-3 rounded-lg border p-4" aria-labelledby="verify-dns">
          <h3 id="verify-dns" class="font-medium">{t("websites.verifyDnsTitle")}</h3>
          <p class="text-sm text-muted-foreground">{t("websites.verifyDnsText")}</p>
          <CopyRow id="verify-dns-name" label={t("websites.verifyDnsName")} value={instructions.dns.name} />
          <CopyRow id="verify-dns-value" label={t("websites.verifyDnsValue")} value={instructions.value} />
        </section>
      {/if}
      <section class="grid gap-3 rounded-lg border p-4" aria-labelledby="verify-file">
        <h3 id="verify-file" class="font-medium">{t("websites.verifyFileTitle")}</h3>
        <p class="text-sm text-muted-foreground">
          {asset.kind === "ip" ? t("websites.verifyFileTextIp") : t("websites.verifyFileText")}
        </p>
        <CopyRow id="verify-file-url" label={t("websites.verifyFileUrl")} value={instructions.file.url} />
        <CopyRow id="verify-file-content" label={t("websites.verifyFileContent")} value={instructions.value} />
      </section>
      <p class="text-sm text-muted-foreground">{t("websites.verifyNote")}</p>
      <DialogFooter>
        <Button variant="outline" onclick={() => (confirmRotate = true)}>{t("websites.verifyNewCode")}</Button>
        <Button variant="outline" onclick={onClose}>{t("common.close")}</Button>
        <Button disabled={check.isPending || waiting} onclick={() => check.mutate()}>
          {#if waiting}
            <Loader aria-hidden="true" class="size-4 animate-spin motion-reduce:animate-none" />
            {t("websites.verifyChecking")}
          {:else}
            <Check aria-hidden="true" class="size-4" />
            {t("websites.verifyCheckNow")}
          {/if}
        </Button>
      </DialogFooter>
    </div>
  {/if}
</Dialog>
<ConfirmDialog
  open={confirmRotate}
  title={t("websites.verifyNewCodeTitle")}
  description={t("websites.verifyNewCodeText")}
  confirmLabel={t("websites.verifyNewCode")}
  pending={rotate.isPending}
  error={failed ? t("errors.actionFailed") : null}
  onConfirm={() => rotate.mutate()}
  onClose={() => (confirmRotate = false)}
/>
<StepUpPrompt {stepUp} {email} />
