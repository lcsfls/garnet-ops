<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";

  /** New backup codes, shown once; "Done" waits for the confirmation that they are saved. */
  let { codes, onClose }: { codes: string[] | null; onClose: () => void } = $props();
  let saved = $state(false);
  const close = () => {
    saved = false;
    onClose();
  };
</script>

<Dialog
  open={codes !== null}
  onClose={close}
  title={t("account.authenticator.codesShownTitle")}
  description={t("account.authenticator.codesShownText")}
>
  <div class="grid gap-4">
    <ul
      aria-label={t("account.authenticator.codesTitle")}
      class="grid grid-cols-2 gap-2 rounded-md bg-muted p-4 font-mono text-sm"
    >
      {#each codes ?? [] as code, index (index)}
        <li>{code}</li>
      {/each}
    </ul>
    <div class="flex justify-end">
      <CopyButton text={(codes ?? []).join("\n")} />
    </div>
    <label class="flex items-start gap-2.5 text-sm">
      <Checkbox class="mt-0.5" bind:checked={saved} />
      {t("account.authenticator.codesSaved")}
    </label>
    <DialogFooter>
      <Button disabled={!saved} onclick={close}>
        {t("account.authenticator.codesDone")}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
