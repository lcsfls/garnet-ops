<script lang="ts">
  import Mark from "./Mark.svelte";
</script>

<span class="inline-flex items-center gap-2.5">
  <Mark class="size-6" />
  <span>
    <!-- Normal tracking on purpose: tighter spacing merges "rn" into "m" at this size. -->
    <span class="text-lg font-bold">garnet</span>
    <span class="ml-1 font-mono text-xs text-muted-foreground">ops</span>
  </span>
  <span class="sr-only">GarnetOps</span>
</span>
