<script lang="ts">
  import { t } from "../i18n.svelte.ts";
  import { GATE_META } from "../severity-meta.ts";
  import type { GateResult } from "../types.ts";
  import Badge from "./ui/Badge.svelte";
  import StateIcon from "./ui/StateIcon.svelte";

  /** Green means proof (AGENTS.md rule 6): only a gate that passed is green; blocked is red. */
  let { result }: { result: GateResult } = $props();
  const meta = $derived(GATE_META[result]);
</script>

<Badge tone={meta.tone}>
  {#if meta.icon}<StateIcon name={meta.icon} />{/if}
  {t(meta.label)}
</Badge>
