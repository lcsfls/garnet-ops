<script lang="ts">
  import { createMutation } from "@tanstack/svelte-query";
  import type { PasskeyRow } from "../../account.ts";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import { NAME_MAX } from "./AddPasskeyDialog.svelte";

  /** Renames a passkey; the name is only a label for this list. */
  let {
    passkey,
    onClose,
    onRenamed,
  }: {
    passkey: PasskeyRow | null;
    onClose: () => void;
    onRenamed: () => void;
  } = $props();
  let error = $state<string | null>(null);
  const rename = createMutation(() => ({
    mutationFn: (input: { id: string; name: string }) =>
      api(`/account/passkeys/${input.id}`, { method: "PATCH", body: { name: input.name } }),
    onSuccess: () => onRenamed(),
    onError: (e: Error) => {
      error =
        e instanceof ApiError && e.status === 422 ? t("account.passkeys.errorName") : t("errors.generic");
    },
  }));
  function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    if (passkey) {
      rename.mutate({
        id: passkey.id,
        name: String(new FormData(event.currentTarget as HTMLFormElement).get("name")).trim(),
      });
    }
  }
</script>

<Dialog open={passkey !== null} {onClose} title={t("account.passkeys.renameTitle")}>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <!-- The dialog's content mounts when it opens, so the field starts from the current name (React: defaultValue). -->
    <Field
      label={t("account.passkeys.name")}
      name="name"
      required
      maxlength={NAME_MAX}
      autocomplete="off"
      value={passkey?.name ?? ""}
    />
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>
        {t("common.cancel")}
      </Button>
      <Button type="submit" disabled={rename.isPending}>
        {rename.isPending ? t("common.loading") : t("account.passkeys.renameSave")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
