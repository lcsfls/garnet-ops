<script lang="ts">
  import { Flame, TriangleAlert } from "@lucide/svelte";
  import { formatRelative } from "../../format.ts";
  import type { HostDetail } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import Facts from "../websites/Facts.svelte";

  /**
   * The packages installed on the host itself (systemd agent, ADR 0037), matched against the local vulnerability database like an
   * image's. "Affected" means the installed version is one the distribution lists as vulnerable; installing the fixed version (and
   * restarting what uses it) clears it with the next report.
   */
  let { packages }: { packages: HostDetail["hostPackages"] } = $props();
  const state = $derived(
    packages.count === null
      ? "notYet"
      : packages.matchError
        ? "failed"
        : !packages.matchedAt
          ? "waiting"
          : packages.findings.length > 0
            ? "affected"
            : "clean",
  );
  const fixText = (f: HostDetail["hostPackages"]["findings"][number]) =>
    f.fixedIn?.length
      ? t("hosts.kernelFixIn", { version: f.fixedIn.join(", ") })
      : f.fixState === "wont-fix"
        ? t("hosts.kernelFixWontFix")
        : t("hosts.kernelFixNone");
</script>

<Card>
  <CardHeader title={t("hosts.packagesTitle")} description={t("hosts.packagesDescription")} />
  <div data-testid="host-packages">
    {#if packages.count !== null}
      <Facts
        rows={[
          { label: t("hosts.ownPackagesCount"), text: String(packages.count), note: packages.distro },
          {
            label: t("hosts.packagesReported"),
            text: packages.reportedAt ? formatRelative(packages.reportedAt) : null,
          },
          { label: t("hosts.kernelChecked"), text: packages.matchedAt ? formatRelative(packages.matchedAt) : null },
        ]}
      />
    {/if}
    <div class="grid gap-2 px-5 pb-5 text-sm">
      {#if state === "notYet"}
        <p class="text-muted-foreground">{t("hosts.packagesNotYet")}</p>
      {:else if state === "failed"}
        <p class="text-muted-foreground">{t("hosts.kernelMatchFailed")}</p>
      {:else if state === "waiting"}
        <p class="text-muted-foreground">{t("hosts.kernelWaiting")}</p>
      {:else if state === "clean"}
        <p>{t("hosts.packagesNone")}</p>
      {:else}
        <p class="flex items-center gap-2 font-medium" data-testid="packages-affected">
          <TriangleAlert aria-hidden="true" class="size-4 text-high-text" />
          {t("hosts.packagesAffected", { count: packages.findings.length })}
        </p>
      {/if}
    </div>
    {#if packages.findings.length > 0}
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm" data-testid="host-package-findings">
          <thead class="text-muted-foreground">
            <tr class="border-y">
              <th class="px-5 py-2 font-medium">{t("hosts.columnVulnerability")}</th>
              <th class="px-3 py-2 font-medium">{t("hosts.columnPackage")}</th>
              <th class="px-3 py-2 font-medium"><span title={t("hosts.ratingHint")}>{t("hosts.columnRating")}</span></th>
              <th class="px-5 py-2 font-medium">{t("hosts.columnFix")}</th>
            </tr>
          </thead>
          <tbody>
            {#each packages.findings as f (f.id)}
              <tr class="border-b align-top last:border-0">
                <td class="px-5 py-2.5">
                  <span class="font-mono">{f.vulnerabilityId}</span>
                  {#if f.knownExploited}
                    <span class="ml-1 inline-flex items-center gap-1 text-destructive-text">
                      <Flame aria-hidden="true" class="size-3.5" />{t("hosts.knownExploited")}
                    </span>
                  {/if}
                </td>
                <td class="px-3 py-2.5 font-mono break-all">{f.packageName} {f.packageVersion}</td>
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
    {/if}
  </div>
</Card>
