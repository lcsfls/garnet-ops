<script lang="ts">
  import { CircleAlert, CircleCheck, CircleX, Flame, Info, TriangleAlert } from "@lucide/svelte";
  import type { IconName } from "../../severity-meta.ts";

  /** The icon behind a name from severity-meta.ts. Decorative: its word is always next to it or in its label. */
  let { name, class: className }: { name: IconName; class?: string } = $props();
  const ICONS = {
    flame: Flame,
    "triangle-alert": TriangleAlert,
    "circle-alert": CircleAlert,
    info: Info,
    "circle-check": CircleCheck,
    "circle-x": CircleX,
  } as const satisfies Record<IconName, unknown>;
  const Icon = $derived(ICONS[name]);
</script>

<Icon aria-hidden="true" class={className} />
