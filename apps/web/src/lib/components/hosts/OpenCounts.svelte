<script lang="ts">
  import type { SeverityCounts } from "../../hosts.ts";
  import CountPill from "../websites/CountPill.svelte";

  /** Open vulnerabilities per severity, critical to medium; low is left to the image page. */
  let { open }: { open: SeverityCounts } = $props();
</script>

<span class="inline-flex gap-1">
  <CountPill severity="critical" n={open.critical} />
  <CountPill severity="high" n={open.high} />
  <CountPill severity="medium" n={open.medium} />
</span>
