<script lang="ts">
  import { type AdminMessages, interpolate } from "@restow-backup/cicd-updater/messages";
  import type { StateView } from "@restow-backup/cicd-updater/protocol";
  import { RUNBOOK_DOCS } from "./explain.ts";

  /** What an admin needs when an update ended in needs_attention. */
  let { run, texts }: { run: NonNullable<StateView["run"]>; texts: AdminMessages } = $props();

  const schemaChanged = $derived(run.failure?.schemaChanged ?? null);
</script>

<div class="grid gap-2 rounded-md border border-destructive/40 px-4 py-3">
  <h3 class="font-semibold">{texts.attentionTitle}</h3>
  <p>{texts.attentionBody}</p>
  <p>
    {schemaChanged === true
      ? texts.attentionSchemaChanged
      : schemaChanged === false
        ? texts.attentionSchemaUnchanged
        : texts.attentionSchemaUnknown}
  </p>
  {#if run.recovery?.backup}
    <p class="break-all">{interpolate(texts.attentionBackup, { file: run.recovery.backup.file })}</p>
  {/if}
  <p>{texts.attentionCommand}</p>
  <pre class="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm"><code
      >docker compose exec updater cicd-updater recover show</code
    ></pre>
  {#if run.recovery && run.recovery.commands.length > 0}
    <details>
      <summary class="cursor-pointer">{texts.attentionCommands}</summary>
      <pre class="mt-2 overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-sm"><code
          >{run.recovery.commands.join("\n")}</code
        ></pre>
    </details>
  {/if}
  <p>
    <a href={RUNBOOK_DOCS} target="_blank" rel="noopener noreferrer" class="text-primary-text underline-offset-4 hover:underline"
      >{texts.attentionRunbook}</a
    >. {texts.attentionAcknowledge}
  </p>
</div>
