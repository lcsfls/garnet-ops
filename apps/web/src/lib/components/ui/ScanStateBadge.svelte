<script lang="ts">
  import { t } from "../../i18n.svelte.ts";
  import { SCAN_STATE_META } from "../../severity-meta.ts";
  import type { ScanState } from "../../types.ts";
  import Badge from "./Badge.svelte";

  let { state }: { state: ScanState | null } = $props();
  const meta = $derived(SCAN_STATE_META[state ?? "never"]);
</script>

<Badge tone={meta.tone}>{t(meta.label)}</Badge>
