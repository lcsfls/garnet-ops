<script lang="ts">
  import { ArrowRight } from "@lucide/svelte";
  import { forgeOf } from "../../forge.ts";
  import { formatDate, formatDateTime, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { scanErrorText } from "../../scan-error.ts";
  import type { RepositoryDetail } from "../../types.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import ScanStateBadge from "../ui/ScanStateBadge.svelte";

  const SOURCE_ACCESS = {
    none: "repositories.sourcePublic",
    "https-token": "repositories.sourceToken",
    "ssh-deploy-key": "repositories.sourceDeployKey",
    connection: "repositories.sourceConnection",
  } as const;

  /** Where a repository comes from, its last scan and what has been resolved and accepted. */
  let { repo }: { repo: RepositoryDetail } = $props();
</script>

<Card>
  <CardHeader title={t("repository.facts")}>
    {#snippet actions()}
      <a
        href={href("/findings", { repositoryId: repo.id })}
        class="inline-flex items-center gap-1.5 text-sm font-medium text-primary-text hover:underline"
      >
        {t("overview.allFindings")}
        <ArrowRight aria-hidden="true" class="size-4" />
      </a>
    {/snippet}
  </CardHeader>
  <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-2 px-5 py-4">
    <dt class="text-muted-foreground">{t("repositories.columnSource")}</dt>
    <dd>{forgeOf(repo.url)} · {t(SOURCE_ACCESS[repo.authKind])}</dd>
    <dt class="text-muted-foreground">{t("repositories.columnBranch")}</dt>
    <dd class="font-mono">{repo.branch ?? t("repositories.defaultBranch")}</dd>
    <dt class="text-muted-foreground">{t("repositories.columnLastScan")}</dt>
    <dd>
      <span class="inline-flex flex-wrap items-center gap-2">
        <ScanStateBadge state={repo.lastScan?.state ?? null} />
        {#if repo.lastScan?.finishedAt}
          <time datetime={repo.lastScan.finishedAt} title={formatDateTime(repo.lastScan.finishedAt)}>
            {formatRelative(repo.lastScan.finishedAt)}
          </time>
        {/if}
      </span>
      {#if repo.lastScan?.state === "failed" && repo.lastScan.error}
        <div class="mt-1 text-sm text-destructive-text">{scanErrorText(repo.lastScan.error)}</div>
      {/if}
    </dd>
    <dt class="text-muted-foreground">{t("repository.resolvedTotal")}</dt>
    <dd>{formatNumber(repo.states.resolved ?? 0)}</dd>
    <dt class="text-muted-foreground">{t("overview.accepted")}</dt>
    <dd>{formatNumber(repo.states.accepted ?? 0)}</dd>
    <dt class="text-muted-foreground">{t("repository.added")}</dt>
    <dd>{formatDate(repo.createdAt)}</dd>
  </dl>
</Card>
