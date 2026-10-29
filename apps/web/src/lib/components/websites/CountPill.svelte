<script lang="ts">
  import { cn } from "../../cn.ts";
  import { formatNumber } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { ExposureSeverity } from "../../websites.ts";
  import { BADGE_TONE } from "../ui/tones.ts";

  /** One number of open findings of a severity, in the fixed severity colour when it is above zero. */
  let { severity, n }: { severity: ExposureSeverity; n: number } = $props();
</script>

<span
  title={t("websites.openOfSeverity", { count: n, severity: t(`severity.${severity}`) })}
  class={cn(
    "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold",
    n > 0 ? BADGE_TONE[severity] : "font-normal text-muted-foreground",
  )}
>
  {formatNumber(n)}
</span>
