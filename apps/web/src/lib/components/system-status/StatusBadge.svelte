<script lang="ts" module>
  import { CircleCheck, CircleDashed, OctagonX, TriangleAlert } from "@lucide/svelte";

  const LEVEL_ICON = {
    ok: CircleCheck,
    attention: TriangleAlert,
    failed: OctagonX,
    inactive: CircleDashed,
  } as const;
</script>

<script lang="ts">
  import type { StatusLevel } from "@garnetops/core/system-status";
  import type { Snippet } from "svelte";
  import { LEVEL_TONE } from "../../system-status.ts";
  import Badge from "../ui/Badge.svelte";

  /** A level with its icon and a word. Colour only supports it (AGENTS.md rule 6). */
  let { level, children }: { level: StatusLevel; children: Snippet } = $props();
  const Icon = $derived(LEVEL_ICON[level]);
</script>

<Badge tone={LEVEL_TONE[level]}>
  <Icon aria-hidden="true" />
  {@render children()}
</Badge>
