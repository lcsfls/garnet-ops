<script lang="ts">
  import { CircleAlert, CircleCheck, CircleX } from "@lucide/svelte";
  import { t } from "../i18n.svelte.ts";
  import type { GateResult } from "../types.ts";
  import Badge from "./ui/Badge.svelte";
  import type { BadgeTone } from "./ui/tones.ts";

  /** Green means proof (AGENTS.md rule 6): only a gate that passed is green. */
  const LOOK = {
    passed: { tone: "success", icon: CircleCheck },
    notes: { tone: "medium", icon: CircleAlert },
    blocked: { tone: "critical", icon: CircleX },
  } as const satisfies Record<GateResult, { tone: BadgeTone; icon: unknown }>;

  let { result }: { result: GateResult } = $props();
  const look = $derived(LOOK[result]);
</script>

<Badge tone={look.tone}>
  <look.icon aria-hidden="true" />
  {t(`gates.result.${result}`)}
</Badge>
