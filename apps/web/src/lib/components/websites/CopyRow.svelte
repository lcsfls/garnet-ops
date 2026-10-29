<script lang="ts">
  import CopyButton from "../ui/CopyButton.svelte";

  /** A label, a value in a monospace box and a copy button: what an admin pastes into a DNS panel or a file. */
  let { label, value, id }: { label: string; value: string; id: string } = $props();
</script>

<fieldset class="m-0 grid min-w-0 gap-1.5 border-0 p-0">
  <legend class="mb-1.5 p-0 text-sm font-medium">{label}</legend>
  <div class="flex min-w-0 items-center gap-2">
    <code
      data-testid={id}
      class="min-w-0 flex-1 rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all select-all"
    >
      {value}
    </code>
    <CopyButton text={value} />
  </div>
</fieldset>
