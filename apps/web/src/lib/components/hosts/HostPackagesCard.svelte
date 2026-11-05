<script lang="ts">
  import { cn } from "../../cn.ts";
  import { formatRelative } from "../../format.ts";
  import { type HostDetail, PATCH_SUMMARY_ORDER } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";
  import { TONE_CLASSES } from "../../severity-meta.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import StateIcon from "../ui/StateIcon.svelte";
  import CopyRow from "../websites/CopyRow.svelte";
  import Facts from "../websites/Facts.svelte";
  import Notice from "../websites/Notice.svelte";

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
  type Finding = HostDetail["hostPackages"]["findings"][number];
  const patch = $derived(packages.patch ?? null);
  /** "12 patchable now, 3 waiting for the mirror, apt lists 9 days old": the states that have findings, then the lists' age. */
  const summary = $derived.by(() => {
    if (!patch) return null;
    const parts: string[] = PATCH_SUMMARY_ORDER.filter((state) => patch.counts[state] > 0).map((state) =>
      t(`hosts.patchCounts.${state}`, { count: patch.counts[state] }),
    );
    if (patch.listsAgeDays !== null) parts.push(t("hosts.listsAge", { days: patch.listsAgeDays }));
    return parts.join(", ");
  });
  const sourceText = (o: { host: string | null; suite: string | null }) =>
    [o.host, o.suite].filter(Boolean).join(" ");
  /** What the host's own sources mean for one finding, in plain words; null where the fix column says it all. */
  const patchText = (f: Finding): string | null => {
    const p = f.patch;
    if (!p) return null;
    switch (p.state) {
      case "patchable-now":
        return p.offered
          ? t("hosts.patchState.patchableNow", { version: p.offered.version, source: sourceText(p.offered) })
          : null;
      case "waiting-for-mirror":
        return p.offered
          ? t("hosts.patchState.waitingForMirrorOffered", {
              offered: p.offered.version,
              source: sourceText(p.offered),
            })
          : t("hosts.patchState.waitingForMirror", { fixed: p.fixedIn ?? "" });
      case "lists-stale":
        return t("hosts.patchState.listsStale", { days: patch?.listsAgeDays ?? "" });
      case "pro-only":
        return t("hosts.patchState.proOnly");
      default:
        return null;
    }
  };
  const phpText = (j: NonNullable<typeof patch>["php"][number]) =>
    j.status === "endOfLife"
      ? t("hosts.phpEndOfLife", { version: j.version, line: j.cycle ?? "" })
      : j.status === "outdated"
        ? t("hosts.phpOutdated", { version: j.version, latest: j.latest ?? "" })
        : j.status === "current"
          ? t("hosts.phpCurrent", { version: j.version })
          : t("hosts.phpUnknown", { version: j.version });
  const fixText = (f: Finding) =>
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
          <StateIcon name="triangle-alert" class={cn("size-4", TONE_CLASSES.high.text)} />
          {t("hosts.packagesAffected", { count: packages.findings.length })}
        </p>
      {/if}
    </div>
    {#if patch && (packages.findings.length > 0 || patch.hints.length > 0)}
      <section class="grid gap-3 px-5 pb-5" aria-labelledby="host-patch-title" data-testid="host-patch">
        <h3 id="host-patch-title" class="text-sm font-medium">{t("hosts.patchTitle")}</h3>
        {#if summary}<p class="text-sm" data-testid="host-patch-summary">{summary}</p>{/if}
        {#if patch.command}
          <CopyRow id="host-patch-command" label={t("hosts.patchCommand")} value={patch.command} />
        {/if}
        {#each patch.hints as hint (hint.kind)}
          <Notice
            title={hint.kind === "noSecuritySource"
              ? t("hosts.hintNoSecurity")
              : hint.lagDays !== null && hint.lagDays >= 2
                ? t("hosts.hintSecurityMirrorLag", { host: hint.host, days: hint.lagDays })
                : t("hosts.hintSecurityMirrorWaiting", { host: hint.host })}
          >
            {#if hint.kind === "securityFromMirror"}<p>{t("hosts.hintSecurityAdvice")}</p>{/if}
            <div class="mt-2"><CopyRow id="host-patch-line" label={t("hosts.hintLine")} value={hint.line} /></div>
          </Notice>
        {/each}
      </section>
    {/if}
    {#if packages.findings.length > 0}
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm" data-testid="host-package-findings">
          <thead class="text-muted-foreground">
            <tr class="border-y">
              <th class="px-5 py-2 font-medium">{t("hosts.columnVulnerability")}</th>
              <th class="px-3 py-2 font-medium">{t("hosts.columnPackage")}</th>
              <th class="px-3 py-2 font-medium"><span title={t("hosts.ratingHint")}>{t("hosts.columnRating")}</span></th>
              <th class="px-3 py-2 font-medium">{t("hosts.columnFix")}</th>
              {#if patch}<th class="px-5 py-2 font-medium">{t("hosts.columnPatch")}</th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each packages.findings as f (f.id)}
              <tr class="border-b align-top last:border-0">
                <td class="px-5 py-2.5">
                  <span class="font-mono">{f.vulnerabilityId}</span>
                  {#if f.knownExploited}
                    <span class={cn("ml-1 inline-flex items-center gap-1", TONE_CLASSES.critical.text)}>
                      <StateIcon name="flame" class="size-3.5" />{t("hosts.knownExploited")}
                    </span>
                  {/if}
                  {#if f.configurationNote}
                    <!-- An explanation next to the finding; its severity and state stay as the vulnerability database has them. -->
                    <div class="mt-1.5 flex gap-1.5 text-sm" data-testid="host-package-note">
                      <StateIcon name="info" class={cn("mt-0.5 size-3.5 flex-none", TONE_CLASSES.info.text)} />
                      <div>
                        <span class="font-medium">{t("hosts.sshNoteTitle")}</span>
                        {#each f.configurationNote.reasons as reason (reason)}
                          <span class="block text-muted-foreground">{t(`hosts.sshNoteReasons.${reason}`)}</span>
                        {/each}
                        <span class="block text-muted-foreground">{t("hosts.sshNoteKeep")}</span>
                      </div>
                    </div>
                  {/if}
                </td>
                <td class="px-3 py-2.5 font-mono break-all">{f.packageName} {f.packageVersion}</td>
                <td class="px-3 py-2.5">
                  <span class="inline-flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    {#if f.cvssScore !== null}<span class="text-muted-foreground">{t("hosts.cvss", { score: f.cvssScore.toFixed(1) })}</span>{/if}
                  </span>
                </td>
                <td class="px-3 py-2.5">{fixText(f)}</td>
                {#if patch}
                  <td class="px-5 py-2.5" data-testid="host-package-patch" data-state={f.patch?.state ?? "unknown"}>
                    {patchText(f) ?? ""}
                    {#if f.patch?.command}
                      <code class="mt-1 block font-mono text-xs break-all text-muted-foreground">{f.patch.command}</code>
                    {/if}
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    {#if patch && patch.thirdParty.length > 0}
      <section class="grid gap-2 border-t px-5 py-4 text-sm" aria-labelledby="host-third-party-title" data-testid="host-third-party">
        <h3 id="host-third-party-title" class="font-medium">{t("hosts.thirdPartyTitle")}</h3>
        <p class="text-muted-foreground">{t("hosts.thirdPartyText")}</p>
        <ul class="grid gap-1.5">
          {#each patch.thirdParty as origin (origin.origin)}
            <li>
              <span class="font-medium">
                {t("hosts.thirdPartyOrigin", { origin: origin.origin, host: origin.host, count: origin.packages.length })}
              </span>
              <span class="block font-mono text-xs break-all text-muted-foreground">
                {origin.packages.map((p) => `${p.name} ${p.installed}`).join(", ")}
              </span>
            </li>
          {/each}
        </ul>
        {#if patch.php.length > 0}
          <ul class="grid gap-1.5" data-testid="host-third-party-php">
            {#each patch.php as j (j.version)}
              <li class="flex flex-wrap items-center gap-2">
                {#if j.severity}<SeverityBadge severity={j.severity} />{/if}
                <span>{phpText(j)}</span>
                <span class="font-mono text-xs text-muted-foreground">{j.packages.join(", ")}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}
  </div>
</Card>
