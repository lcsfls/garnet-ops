<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import CopyButton from "../ui/CopyButton.svelte";

  /** The public deploy key to copy, and where it goes on the forge. */
  let { publicKey }: { publicKey: string } = $props();
</script>

<div class="grid gap-2">
  <label for="deploy-public-key" class="text-sm font-medium">{t("repositories.deployKeyLabel")}</label>
  <textarea
    id="deploy-public-key"
    readonly
    rows={3}
    value={publicKey}
    onfocus={(e) => e.currentTarget.select()}
    class="w-full resize-none break-all rounded-md border border-input bg-muted px-3 py-2 font-mono text-sm"
  ></textarea>
  <div>
    <CopyButton text={publicKey} />
  </div>
  <p class="text-sm text-muted-foreground">{t("repositories.deployKeyHowTo")}</p>
</div>
