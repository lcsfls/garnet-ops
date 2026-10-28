<script lang="ts">
  import type { SystemStatus } from "@garnetops/core/system-status-view";
  import { formatBytes, formatDateTime, formatRelative } from "../../format.ts";
  import { language, t } from "../../i18n.svelte.ts";
  import { canOpenSection } from "../../system-status.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueuesBlock from "./QueuesBlock.svelte";
  import Row from "./Row.svelte";
  import StatusBadge from "./StatusBadge.svelte";

  let { worker, role }: { worker: SystemStatus["worker"]; role: string } = $props();

  const beat = $derived(worker.heartbeat);
  const nightly = $derived(worker.nightly);
  const database = $derived(worker.database);
  const nextDue = $derived(nightly.nextAt !== null && new Date(nightly.nextAt).getTime() <= Date.now());
  const level = $derived(worker.liveness === "running" ? "ok" : "failed");
</script>

<Card>
  <CardHeader title={t("systemStatus.worker.title")} description={t("systemStatus.worker.description")} />
  <ul>
    <Row testId="worker-heartbeat" title={t("systemStatus.worker.heartbeat")}>
      {#snippet badge()}
        <StatusBadge {level}>{t(`systemStatus.worker.state.${worker.liveness}`)}</StatusBadge>
      {/snippet}
      {#if beat && worker.liveness === "running"}
        <span>
          {t("systemStatus.worker.runningDetail", {
            version: beat.version,
            started: formatRelative(beat.startedAt),
            when: formatRelative(beat.beatAt),
          })}
        </span>
      {:else if beat}
        <span>{t("systemStatus.worker.lateDetail", { when: formatRelative(beat.beatAt) })}</span>
      {:else}
        <span>{t("systemStatus.worker.missingDetail")}</span>
      {/if}
      {#if beat && beat.instances > 1}
        <span>{t("systemStatus.worker.instances", { count: beat.instances })}</span>
      {/if}
    </Row>
    <Row testId="worker-nightly" title={t("systemStatus.worker.nightly")}>
      {#snippet badge()}
        <StatusBadge level={nightly.enabled ? "ok" : "inactive"}>
          {nightly.enabled ? t("systemStatus.integrations.state.current") : t("systemStatus.integrations.partOff")}
        </StatusBadge>
      {/snippet}
      {#if nightly.enabled}
        <span>
          {t("systemStatus.worker.nightlySchedule", {
            time: new Intl.DateTimeFormat(language(), {
              hour: "numeric",
              minute: "2-digit",
              timeZone: "UTC",
            }).format(new Date(`1970-01-01T${nightly.localTime}Z`)),
            zone: nightly.timeZone,
          })}
        </span>
        <span>
          {nightly.lastRun
            ? t("systemStatus.worker.lastRun", {
                when: formatRelative(nightly.lastRun.at),
                queued: nightly.lastRun.queued,
                succeeded: nightly.lastRun.succeeded,
                failed: nightly.lastRun.failed,
                pending: nightly.lastRun.pending,
              })
            : t("systemStatus.worker.noRun")}
        </span>
        {#if nightly.nextAt}
          <span>
            {#if nextDue}
              {t("systemStatus.worker.nextDue")}
            {:else}
              {t("systemStatus.worker.nextRun", { when: formatRelative(nightly.nextAt) })}
              <span title={formatDateTime(nightly.nextAt)}>({formatDateTime(nightly.nextAt)})</span>
            {/if}
          </span>
        {/if}
      {:else}
        <span>{t("systemStatus.worker.nightlyOff")}</span>
      {/if}
      {#if canOpenSection("scanning", role)}
        <span>
          <a
            href="/settings"
            class="text-primary-text underline-offset-4 hover:underline"
            data-testid="settings-link-scanning"
          >
            {t("systemStatus.settingsLink")}
          </a>
        </span>
      {/if}
    </Row>
    <Row testId="worker-database" title={t("systemStatus.worker.database")}>
      {#snippet badge()}
        <StatusBadge level={database.level}>
          {database.level === "ok" ? t("systemStatus.level.ok") : t("systemStatus.level.attention")}
        </StatusBadge>
      {/snippet}
      <span>
        {database.sizeBytes === null ? "–" : t("systemStatus.worker.size", { size: formatBytes(database.sizeBytes) })}
      </span>
      <span>
        {database.migrations.applied === database.migrations.expected
          ? t("systemStatus.worker.migrations", {
              applied: database.migrations.applied,
              expected: database.migrations.expected,
              latest: database.migrations.latest ?? "–",
            })
          : t("systemStatus.worker.migrationsBehind", {
              applied: database.migrations.applied,
              expected: database.migrations.expected,
            })}
      </span>
    </Row>
  </ul>
  <QueuesBlock queues={worker.queues} />
</Card>
