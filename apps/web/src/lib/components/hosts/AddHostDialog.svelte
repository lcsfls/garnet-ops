<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { composeFile, type Enrolment } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  /**
   * Adding a host (ADR 0034): an optional name, then a one-time code inside a Compose file to run on the host. The code is shown here
   * only. Mounted fresh each time it opens.
   */
  let { onClose }: { onClose: () => void } = $props();

  const queryClient = useQueryClient();
  let label = $state("");
  let enrolment = $state<Enrolment | null>(null);

  const create = createMutation(() => ({
    mutationFn: () =>
      api<Enrolment>("/hosts/enrolments", { method: "POST", body: { label: label.trim() || undefined } }),
    onSuccess: async (result: Enrolment) => {
      enrolment = result;
      await queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  }));
  const file = $derived(
    enrolment
      ? composeFile({
          image: enrolment.image,
          serverUrl: enrolment.serverUrl,
          code: enrolment.code,
          ...(label.trim() ? { hostName: label.trim() } : {}),
        })
      : "",
  );

  function submit(event: SubmitEvent) {
    event.preventDefault();
    create.mutate();
  }
</script>

<Dialog
  open
  {onClose}
  title={enrolment ? t("hosts.snippetTitle") : t("hosts.addTitle")}
  description={enrolment ? t("hosts.snippetSteps") : t("hosts.addDescription")}
>
  {#if !enrolment}
    <form class="grid gap-4" onsubmit={submit}>
      {#if create.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
      <Field label={t("hosts.addLabel")} hint={t("hosts.addLabelHint")} bind:value={label} maxlength={100} autocomplete="off" />
      <DialogFooter>
        <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? t("common.loading") : t("hosts.addSubmit")}
        </Button>
      </DialogFooter>
    </form>
  {:else}
    <div class="grid gap-4">
      <Alert tone="info">{t("hosts.snippetCodeNote", { when: formatDateTime(enrolment.expiresAt) })}</Alert>
      <pre
        data-testid="host-compose"
        class="max-h-[50vh] overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs leading-relaxed whitespace-pre select-all">{file}</pre>
      <p class="text-sm text-muted-foreground">{t("hosts.snippetHttpsNote", { url: enrolment.serverUrl })}</p>
      <DialogFooter>
        <CopyButton text={file} />
        <Button onclick={onClose}>{t("hosts.snippetDone")}</Button>
      </DialogFooter>
    </div>
  {/if}
</Dialog>
