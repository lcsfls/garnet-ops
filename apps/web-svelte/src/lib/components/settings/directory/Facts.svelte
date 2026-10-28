<script lang="ts">
  import { formatDate } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";

  let {
    label,
    facts,
  }: {
    label: string;
    facts: { fingerprint: string; subject: string; issuer: string; validFrom: string; validTo: string };
  } = $props();
</script>

<section aria-label={label} class="grid gap-2 rounded-md border px-3 py-3">
  <h3 class="text-sm font-medium">{label}</h3>
  <code class="rounded-md border bg-muted px-3 py-2 font-mono text-sm break-all" data-testid="fingerprint">
    {facts.fingerprint}
  </code>
  <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
    <dt class="text-muted-foreground">{t("directory.certSubject")}</dt>
    <dd class="font-mono break-all">{facts.subject || "–"}</dd>
    <dt class="text-muted-foreground">{t("directory.certIssuer")}</dt>
    <dd class="font-mono break-all">{facts.issuer || "–"}</dd>
    <dt class="text-muted-foreground">{t("directory.certValid")}</dt>
    <dd>
      {formatDate(facts.validFrom)} – {formatDate(facts.validTo)}
      {#if new Date(facts.validTo) < new Date()}
        <span class="ml-2 text-destructive-text">{t("directory.certExpired")}</span>
      {/if}
    </dd>
  </dl>
</section>
