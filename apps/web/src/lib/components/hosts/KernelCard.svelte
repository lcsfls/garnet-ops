<script lang="ts">
  import { Flame, TriangleAlert } from "@lucide/svelte";
  import { formatRelative } from "../../format.ts";
  import { type HostDetail, kernelState } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import Facts from "../websites/Facts.svelte";

  /**
   * The host's running kernel (ADR 0034). "Affected" is said plainly and explained: the running version is one the distribution
   * lists as not fixed; whether the flaw can be exploited on this host is not claimed, because the agent does not see that.
   */
  let { kernel }: { kernel: HostDetail["kernel"] } = $props();
  const state = $derived(kernelState(kernel, kernel.findings.length));
  const fixText = (f: HostDetail["kernel"]["findings"][number]) =>
    f.fixedIn?.length
      ? t("hosts.kernelFixIn", { version: f.fixedIn.join(", ") })
      : f.fixState === "wont-fix"
        ? t("hosts.kernelFixWontFix")
        : t("hosts.kernelFixNone");
</script>

<Card>
  <CardHeader title={t("hosts.kernelTitle")} description={t("hosts.kernelDescription")} />
  <div data-testid="host-kernel">
    {#if kernel.release}
      <Facts
        rows={[
          { label: t("hosts.kernelRelease"), text: kernel.release, mono: true },
          {
            label: t("hosts.kernelPackage"),
            text: kernel.package ? `${kernel.package.name} ${kernel.package.version}` : null,
            mono: true,
            note: kernel.package?.distro ?? null,
          },
          { label: t("hosts.kernelChecked"), text: kernel.matchedAt ? formatRelative(kernel.matchedAt) : null },
        ]}
      />
    {/if}
    <div class="grid gap-2 px-5 pb-5 text-sm">
      {#if state === "oldAgent"}
        <p class="text-muted-foreground">{t("hosts.kernelOldAgent")}</p>
      {:else if state === "problem" && kernel.problem}
        <p class="text-muted-foreground">{t(`hosts.kernelProblem.${kernel.problem}`)}</p>
      {:else if state === "failed"}
        <p class="text-muted-foreground">{t("hosts.kernelMatchFailed")}</p>
      {:else if state === "waiting"}
        <p class="text-muted-foreground">{t("hosts.kernelWaiting")}</p>
      {:else if state === "clean"}
        <p>{t("hosts.kernelNone")}</p>
      {:else}
        <p class="flex items-center gap-2 font-medium" data-testid="kernel-affected">
          <TriangleAlert aria-hidden="true" class="size-4 text-high-text" />
          {t("hosts.kernelAffected", { count: kernel.findings.length })}
        </p>
        <p class="text-muted-foreground">{t("hosts.kernelAffectedNote")}</p>
        <p class="text-muted-foreground">{t("hosts.kernelRebootNote")}</p>
      {/if}
    </div>
    {#if kernel.findings.length > 0}
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm" data-testid="kernel-findings">
          <thead class="text-muted-foreground">
            <tr class="border-y">
              <th class="px-5 py-2 font-medium">{t("hosts.columnVulnerability")}</th>
              <th class="px-3 py-2 font-medium"><span title={t("hosts.ratingHint")}>{t("hosts.columnRating")}</span></th>
              <th class="px-5 py-2 font-medium">{t("hosts.columnFix")}</th>
            </tr>
          </thead>
          <tbody>
            {#each kernel.findings as f (f.id)}
              <tr class="border-b align-top last:border-0">
                <td class="px-5 py-2.5">
                  <span class="font-mono">{f.vulnerabilityId}</span>
                  {#if f.knownExploited}
                    <span class="ml-1 inline-flex items-center gap-1 text-destructive-text">
                      <Flame aria-hidden="true" class="size-3.5" />{t("hosts.knownExploited")}
                    </span>
                  {/if}
                </td>
                <td class="px-3 py-2.5">
                  <span class="inline-flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    {#if f.cvssScore !== null}<span class="text-muted-foreground">{t("hosts.cvss", { score: f.cvssScore.toFixed(1) })}</span>{/if}
                  </span>
                </td>
                <td class="px-5 py-2.5">{fixText(f)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="px-5 py-3 text-xs text-muted-foreground">{t("hosts.ratingHint")}</p>
    {/if}
  </div>
</Card>
