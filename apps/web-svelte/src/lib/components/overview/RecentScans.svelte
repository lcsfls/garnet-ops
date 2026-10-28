<script lang="ts">
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { scanErrorText } from "../../scan-error.ts";
  import type { Overview } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import ScanStateBadge from "../ui/ScanStateBadge.svelte";

  let { items }: { items: Overview["recentScans"] } = $props();
</script>

<Card class="h-full">
  <CardHeader title={t("overview.recentScans")} description={t("overview.recentScansDescription")} />
  {#if items.length === 0}
    <p class="px-5 pb-6 text-muted-foreground">{t("overview.noScans")}</p>
  {:else}
    <ul>
      {#each items as s (s.id)}
        {@const at = s.finishedAt ?? s.createdAt}
        <li class="flex items-start gap-3 border-b px-5 py-3 last:border-0">
          <div class="min-w-0 flex-1">
            <RepositoryLink id={s.repositoryId} name={s.repositoryName} class="block truncate font-medium" />
            {#if s.state === "succeeded"}
              <a
                href={href("/findings", { scanId: s.id, state: "all" })}
                class="text-sm text-muted-foreground hover:underline"
              >
                {t("overview.scanSummary", {
                  added: s.newFindings ?? 0,
                  resolved: s.resolvedFindings ?? 0,
                })}
              </a>
            {:else if s.error}
              <div class="text-sm text-destructive-text">{scanErrorText(s.error)}</div>
            {/if}
          </div>
          <div class="flex flex-none flex-col items-end gap-1">
            <ScanStateBadge state={s.state} />
            <time datetime={at} title={formatDateTime(at)} class="dash-time text-sm text-muted-foreground">
              {formatRelative(at)}
            </time>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</Card>
