<script lang="ts">
  import { ExternalLink } from "@lucide/svelte";
  import type { AdminMessages } from "@restow-backup/cicd-updater/messages";
  import { t } from "../../../i18n.svelte.ts";
  import Alert from "../../ui/Alert.svelte";
  import { SOURCE_UPDATE, UPDATING_DOCS } from "./explain.ts";

  let { texts }: { texts: AdminMessages } = $props();
</script>

<div class="grid gap-3">
  <Alert tone="info">{texts.noSidecar}</Alert>
  <p class="text-muted-foreground">{t("settings.updatesManual")}</p>
  <pre class="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm"><code>{SOURCE_UPDATE}</code></pre>
  <a
    href={UPDATING_DOCS}
    target="_blank"
    rel="noopener noreferrer"
    class="inline-flex items-center gap-1.5 text-primary-text underline-offset-4 hover:underline"
  >
    {texts.manualSteps}
    <ExternalLink aria-hidden="true" class="size-3.5" />
  </a>
</div>
