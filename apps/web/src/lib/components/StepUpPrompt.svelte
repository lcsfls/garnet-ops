<script lang="ts">
  import type { StepUp } from "../step-up.svelte.ts";
  import StepUpDialog from "./StepUpDialog.svelte";

  /** The confirmation dialog of a StepUp (see step-up.svelte.ts). */
  let { stepUp, email }: { stepUp: StepUp; email: string } = $props();
</script>

<StepUpDialog open={stepUp.open} {email} onClose={stepUp.close} onConfirmed={stepUp.confirmed} />
