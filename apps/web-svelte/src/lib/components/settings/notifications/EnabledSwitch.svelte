<script lang="ts">
  import { untrack } from "svelte";
  import Checkbox from "../../ui/Checkbox.svelte";

  /** On/off for a channel: moves at once, the list reload confirms it. */
  let {
    label,
    text,
    enabled,
    onChange,
  }: { label: string; text: string; enabled: boolean; onChange: (enabled: boolean) => void } = $props();

  // The parent remounts the switch when the stored state changes ({#key}), so the start value is enough.
  let on = $state(untrack(() => enabled));
</script>

<label class="flex items-center gap-2 text-sm">
  <Checkbox
    bind:checked={
      () => on,
      (value) => {
        on = value;
        onChange(value);
      }
    }
    aria-label={label}
  />
  {text}
</label>
