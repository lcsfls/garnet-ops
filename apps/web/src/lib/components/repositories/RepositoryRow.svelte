<script lang="ts" module>
  import type { MessageKey } from "../../i18n.svelte.ts";
  import type { RepositoryRow, Severity } from "../../types.ts";

  /** Open findings per severity get a column each (mockup); low lives in the findings list. */
  export const SEVERITY_COLUMNS = ["critical", "high", "medium"] as const satisfies readonly Severity[];
  const SOURCE_ACCESS = {
    none: "repositories.sourcePublic",
    "https-token": "repositories.sourceToken",
    "ssh-deploy-key": "repositories.sourceDeployKey",
    connection: "repositories.sourceConnection",
  } as const satisfies Record<RepositoryRow["authKind"], MessageKey>;
  /** Open findings per severity as small tinted counts (mockup .count). */
  const COUNT_PILL =
    "inline-block min-w-[26px] rounded-md px-1.5 py-px text-center text-[13px] font-semibold";
</script>

<script lang="ts">
  import { FolderGit2, GitFork, KeyRound, Lock, RefreshCw, Terminal, Trash2 } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { api } from "../../api.ts";
  import { cn } from "../../cn.ts";
  import { forgeOf } from "../../forge.ts";
  import { formatDateTime, formatNumber, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { rowClick } from "../../row-link.ts";
  import { scanErrorText } from "../../scan-error.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { GateResult } from "../../types.ts";
  import { href } from "../../url.ts";
  import GateBadge from "../GateBadge.svelte";
  import RepositoryLink from "../RepositoryLink.svelte";
  import ActionMenu, { type MenuAction } from "../ui/ActionMenu.svelte";
  import Badge from "../ui/Badge.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import ScanStateBadge from "../ui/ScanStateBadge.svelte";
  import { BADGE_TONE } from "../ui/tones.ts";
  import DeployKeyDetails from "./DeployKeyDetails.svelte";
  import GradeBadge from "./GradeBadge.svelte";
  import Sparkline from "./Sparkline.svelte";

  let {
    repo,
    gate,
    canEdit,
    canDelete,
  }: { repo: RepositoryRow; gate: GateResult | null; canEdit: boolean; canDelete: boolean } = $props();

  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["repositories"] });

  const scan = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}/scans`, { method: "POST" }),
    onSuccess: async () => {
      toast.success(t("toast.scanQueued", { repository: repo.name }));
      await refresh();
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api(`/repositories/${repo.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      confirmRemove = false;
      await queryClient.invalidateQueries();
    },
  }));
  let showKey = $state(false);
  let confirmRemove = $state(false);

  const scanState = $derived(repo.lastScan?.state ?? null);
  const busy = $derived(scanState === "queued" || scanState === "running");
  const when = $derived(repo.lastScan?.finishedAt ?? repo.lastScanAt);
  const SourceIcon = $derived(repo.authKind === "ssh-deploy-key" ? Terminal : GitFork);

  const actions = $derived.by(() => {
    const list: MenuAction[] = [];
    if (canEdit) {
      list.push({
        label: busy && scanState ? t(`scanState.${scanState}`) : t("repositories.scanNow"),
        icon: RefreshCw,
        disabled: busy || scan.isPending,
        onSelect: () => scan.mutate(),
      });
    }
    if (repo.deployPublicKey) {
      list.push({ label: t("repositories.deployKey"), icon: KeyRound, onSelect: () => (showKey = true) });
    }
    if (canDelete) {
      list.push({
        label: t("repositories.delete"),
        icon: Trash2,
        destructive: true,
        disabled: remove.isPending,
        onSelect: () => {
          remove.reset();
          confirmRemove = true;
        },
      });
    }
    return list;
  });
</script>

<!-- The whole row opens the repository for the mouse (mockup); the name link stays the keyboard and screen-reader path. -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<tr
  class="row-link border-b align-top last:border-0"
  onclick={rowClick(() => void goto(`/repositories/${encodeURIComponent(repo.id)}`))}
>
  <!-- The name column takes what the others leave and truncates, so a long address never pushes the table past its card. -->
  <td class="w-full max-w-0 px-5 py-3 @wide:w-auto @wide:max-w-none">
    <div class="flex min-w-0 items-start gap-2.5">
      <FolderGit2 aria-hidden="true" class="mt-1 size-4 flex-none text-muted-foreground" />
      <div class="min-w-0">
        <span class="flex flex-wrap items-center gap-2">
          <RepositoryLink id={repo.id} name={repo.name} class="font-medium" />
          {#if repo.visibility === "private"}
            <Badge tone="neutral">
              <Lock aria-hidden="true" /><span title={t("connections.privateHint")}>{t("connections.private")}</span>
            </Badge>
          {/if}
        </span>
        <div
          class="max-w-[32ch] truncate font-mono text-sm text-muted-foreground @xwide:max-w-[52ch]"
          title={repo.url}
        >
          {repo.url}
        </div>
      </div>
    </div>
  </td>
  <td class="px-2 py-3">
    <GradeBadge row={repo} id={repo.id} />
  </td>
  <td class="hidden px-3 py-3 @3xl:table-cell">
    <div class="flex items-start gap-2.5">
      <SourceIcon aria-hidden="true" class="mt-1 size-4 flex-none text-muted-foreground" />
      <div>
        <div>{forgeOf(repo.url)}</div>
        <div class="text-sm text-muted-foreground">{t(SOURCE_ACCESS[repo.authKind])}</div>
      </div>
    </div>
  </td>
  <td class="hidden px-3 py-3 font-mono text-sm @wide:table-cell">
    {#if repo.branch !== null}{repo.branch}{:else}
      <span class="font-sans text-muted-foreground">{t("repositories.defaultBranch")}</span>
    {/if}
  </td>
  {#each SEVERITY_COLUMNS as severity (severity)}
    {@const n = repo.open[severity] ?? 0}
    <td class="px-3 py-3 text-right tabular-nums">
      {#if n > 0}
        <a
          href={href("/findings", { repositoryId: repo.id, severity })}
          aria-label={t("repositories.openOfSeverity", { count: n, severity: t(`severity.${severity}`) })}
          class={cn(COUNT_PILL, BADGE_TONE[severity], "hover:underline")}
        >
          {formatNumber(n)}
        </a>
      {:else}
        <span class={cn(COUNT_PILL, "font-normal text-muted-foreground")}>0</span>
      {/if}
    </td>
  {/each}
  <td class="hidden px-3 py-3 @5xl:table-cell">
    {#if gate}<GateBadge result={gate} />{:else}<span class="text-muted-foreground">–</span>{/if}
  </td>
  <td class="hidden px-3 py-3 @xwide:table-cell">
    <div class="flex flex-wrap gap-1">
      {#each repo.scanners as scanner (scanner)}
        <Badge tone="neutral">{scanner}</Badge>
      {/each}
    </div>
  </td>
  <td class="hidden px-3 py-3 @xwide:table-cell">
    <Sparkline
      values={repo.trend}
      label={t("repositories.trendLabel", {
        first: formatNumber(repo.trend[0] ?? 0),
        last: formatNumber(repo.trend[repo.trend.length - 1] ?? 0),
      })}
    />
  </td>
  <td class="px-3 py-3">
    <div class="flex flex-wrap gap-1">
      <ScanStateBadge state={scanState} />
      <!-- Narrow screens have no gate column; the result moves here instead of disappearing. -->
      {#if gate}
        <span class="@5xl:hidden">
          <GateBadge result={gate} />
        </span>
      {/if}
    </div>
    {#if when && !busy}
      <time
        datetime={when}
        title={formatDateTime(when)}
        class="dash-time mt-1 block w-fit text-sm text-muted-foreground"
      >
        {formatRelative(when)}
      </time>
    {/if}
    {#if scanState === "failed" && repo.lastScan?.error}
      <div class="mt-1 max-w-[36ch] text-sm text-destructive-text">{scanErrorText(repo.lastScan.error)}</div>
    {/if}
  </td>
  <td class="px-3 py-2 text-right @wide:px-5">
    <ActionMenu label={t("repositories.moreActions", { name: repo.name })} {actions} />
    {#if scan.isError}
      <p role="alert" class="mt-1.5 text-right text-sm text-destructive-text">{t("errors.actionFailed")}</p>
    {/if}
    {#if canDelete}
      <ConfirmDialog
        open={confirmRemove}
        title={t("repositories.deleteTitle", { name: repo.name })}
        description={t("repositories.deleteDescription")}
        confirmLabel={t("repositories.delete")}
        pending={remove.isPending}
        error={remove.isError ? t("errors.actionFailed") : null}
        onConfirm={() => remove.mutate()}
        onClose={() => (confirmRemove = false)}
      />
    {/if}
    {#if repo.deployPublicKey}
      <Dialog
        open={showKey}
        onClose={() => (showKey = false)}
        title={t("repositories.deployKeyTitle", { name: repo.name })}
      >
        <DeployKeyDetails {repo} canReset={canDelete} />
      </Dialog>
    {/if}
  </td>
</tr>
