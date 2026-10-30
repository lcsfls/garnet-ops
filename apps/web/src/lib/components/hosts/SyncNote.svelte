<script lang="ts">
  import { formatDateTime } from "../../format.ts";
  import type { RevisionSync } from "../../hosts.ts";
  import { t } from "../../i18n.svelte.ts";

  /**
   * Whether a running image is the repository's latest scanned commit. Plain text, no colour: running the latest commit is a fact,
   * not proof of anything (AGENTS.md rule 6), and an older one is information for the team that deploys.
   */
  let { sync }: { sync: RevisionSync | null } = $props();
  const short = (commit: string) => commit.slice(0, 12);
</script>

{#if sync && sync.state !== "unknown" && sync.latest}
  <span class="block text-xs text-muted-foreground" data-sync={sync.state}>
    {#if sync.state === "current"}
      {t("hosts.syncCurrent")}
    {:else if sync.state === "older"}
      {t("hosts.syncOlder", {
        scanned: sync.runningScannedAt ? formatDateTime(sync.runningScannedAt) : "–",
        latest: short(sync.latest.commit),
        branch: sync.latest.branch ?? "–",
      })}
    {:else}
      {t("hosts.syncDifferent", { latest: short(sync.latest.commit), branch: sync.latest.branch ?? "–" })}
    {/if}
  </span>
{/if}
