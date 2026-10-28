<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { camelState } from "../../system-status.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Row from "./Row.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  let { scanners, workerVersion }: { scanners: SystemStatus["scanners"]; workerVersion: string | null } =
    $props();

  /** Version, pinned version and when it was reported, on one line. */
  function detail(s: SystemStatus["scanners"]["items"][number]): string {
    const parts = [
      s.version
        ? t("systemStatus.scanners.version", { version: s.version })
        : t("systemStatus.scanners.noVersion"),
      t("systemStatus.scanners.pinned", { pinned: s.pinned }),
    ];
    if (s.reportedAt) parts.push(t("systemStatus.scanners.reported", { when: formatRelative(s.reportedAt) }));
    return parts.join(" · ");
  }

  /** Where syft and grype run (ADR 0028), as one of the isolation texts. */
  const isolationState = $derived.by(() => {
    const { mode, reachable } = scanners.isolation;
    if (mode === "worker") return "worker";
    if (mode === "service") {
      if (reachable === false) return "unreachable";
      return scanners.isolation.versionMatches ? "service" : "differs";
    }
    return "unknown";
  });
</script>

<Card>
  <CardHeader title={t("systemStatus.scanners.title")} description={t("systemStatus.scanners.description")} />
  <ul>
    {#each scanners.items as s (s.name)}
      {@const word = s.problem
        ? t(`systemStatus.scanners.problem.${camelState(s.problem)}`)
        : t(`systemStatus.scanners.match.${s.match}`)}
      <Row testId="scanner-{s.name}">
        {#snippet title()}<span class="font-mono">{s.name}</span>{/snippet}
        {#snippet badge()}<StatusBadge level={s.level}>{word}</StatusBadge>{/snippet}
        <span>{detail(s)}</span>
        {#if s.problem}
          <span>{t(`systemStatus.scanners.problemHint.${camelState(s.problem)}`)}</span>
        {:else if s.match === "differs"}
          <span>{t("systemStatus.scanners.differsHint")}</span>
        {/if}
      </Row>
    {/each}
    <Row testId="scanner-isolation" title={t("systemStatus.scanners.isolation.title")}>
      {#snippet badge()}
        <StatusBadge level={scanners.isolation.level}>{t(`systemStatus.scanners.isolation.state.${isolationState}`)}</StatusBadge>
      {/snippet}
      <span>
        {t(`systemStatus.scanners.isolation.hint.${isolationState}`, {
          version: scanners.isolation.version ?? "",
          worker: workerVersion ?? "",
        })}
      </span>
      {#if scanners.isolation.reportedAt}
        <span>{t("systemStatus.scanners.reported", { when: formatRelative(scanners.isolation.reportedAt) })}</span>
      {/if}
    </Row>
  </ul>
</Card>
