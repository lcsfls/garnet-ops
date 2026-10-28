<script lang="ts">
  /** Mark draft from the mockup: a cut garnet, hexagonal outline with an inner facet in the brand colour. */
  let { class: className }: { class?: string } = $props();
</script>

<svg viewBox="0 0 48 48" aria-hidden="true" class={className}>
  <path
    d="M24 5 L40 14.5 V33.5 L24 43 L8 33.5 V14.5 Z"
    fill="none"
    stroke-width="4.5"
    stroke-linejoin="round"
    class="stroke-[var(--mark-hold)]"
  />
  <path d="M24 15 L32 24 L24 33 L16 24 Z" class="fill-[var(--mark-beam)]" />
</svg>
