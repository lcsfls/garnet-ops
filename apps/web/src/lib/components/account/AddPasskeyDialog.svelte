<script lang="ts" module>
  import { ApiError } from "../../api.ts";

  export const NAME_MAX = 60;
  /** What the step-up check recognises, for the ceremony that is not an API call of ours. */
  const STEP_UP = new ApiError(403, {
    type: "https://garnetops.com/problems/step-up-required",
    title: "Sign in again to confirm it is you",
    status: 403,
  });
</script>

<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { PASSKEY_FAILURE_KEYS, registerPasskey } from "../../passkeys.ts";
  import type { StepUp } from "../../step-up.svelte.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  /** Adds a passkey: a name, then the browser's ceremony (recent sign-in required). */
  let {
    open,
    stepUp,
    onClose,
    onAdded,
  }: {
    open: boolean;
    stepUp: StepUp;
    onClose: () => void;
    onAdded: () => void;
  } = $props();
  let busy = $state(false);
  let error = $state<string | null>(null);

  async function add(name: string) {
    busy = true;
    error = null;
    const result = await registerPasskey(name);
    busy = false;
    if (result.ok) return onAdded();
    if (result.reason === "step-up" && stepUp.handled(STEP_UP, () => void add(name))) return;
    error = t(PASSKEY_FAILURE_KEYS[result.reason]);
  }
  function submit(event: SubmitEvent) {
    event.preventDefault();
    void add(String(new FormData(event.currentTarget as HTMLFormElement).get("name")).trim());
  }
</script>

<Dialog
  {open}
  onClose={() => {
    error = null;
    onClose();
  }}
  title={t("account.passkeys.addTitle")}
  description={t("account.passkeys.addDescription")}
>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <Field
      label={t("account.passkeys.name")}
      hint={t("account.passkeys.nameHint")}
      name="name"
      required
      maxlength={NAME_MAX}
      autocomplete="off"
    />
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>
        {t("common.cancel")}
      </Button>
      <Button type="submit" disabled={busy}>
        {busy ? t("common.loading") : t("account.passkeys.create")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
