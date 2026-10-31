<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import type { Severity } from "../../types.ts";
  import Badge from "./Badge.svelte";
  import SeverityIcon from "./SeverityIcon.svelte";
  import { SEVERITY_TONE } from "./tones.ts";

  /** Severity always carries its word and its own icon, so colour is never the only signal. */
  let { severity, count }: { severity: Severity; count?: number } = $props();
</script>

<Badge tone={SEVERITY_TONE[severity]}>
  <SeverityIcon {severity} />
  {count === undefined ? t(`severity.${severity}`) : `${count} ${t(`severity.${severity}`)}`}
</Badge>
