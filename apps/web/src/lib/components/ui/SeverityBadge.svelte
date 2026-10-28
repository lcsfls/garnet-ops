<script lang="ts">
  import { Flame } from "@lucide/svelte";
  import { t } from "../../i18n.svelte.ts";
  import type { Severity } from "../../types.ts";
  import Badge from "./Badge.svelte";
  import { SEVERITY_TONE } from "./tones.ts";

  /** Severity always carries its word, and critical an icon too, so colour is never the only signal. */
  let { severity, count }: { severity: Severity; count?: number } = $props();
</script>

<Badge tone={SEVERITY_TONE[severity]}>
  {#if severity === "critical"}<Flame aria-hidden="true" />{/if}
  {count === undefined ? t(`severity.${severity}`) : `${count} ${t(`severity.${severity}`)}`}
</Badge>
