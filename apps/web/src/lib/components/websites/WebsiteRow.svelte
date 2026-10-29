<script lang="ts">
  import { Globe, KeyRound, Play, Trash2 } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { rowClick } from "../../row-link.ts";
  import { toast } from "../../toast.svelte.ts";
  import { href } from "../../url.ts";
  import { isBusy, SEVERITY_ORDER, type WebsiteAsset } from "../../websites.ts";
  import ActionMenu, { type MenuAction } from "../ui/ActionMenu.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";
  import CertificateExpiry from "./CertificateExpiry.svelte";
  import CountPill from "./CountPill.svelte";
  import StageBadge from "./StageBadge.svelte";
  import VerificationBadge from "./VerificationBadge.svelte";

  /** One website in the list (ADR 0023). Columns drop out on narrow screens; what they showed moves under the name. */
  let { asset, canEdit }: { asset: WebsiteAsset; canEdit: boolean } = $props();

  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["websites"] });
  let confirmRemove = $state(false);
  const detailHref = $derived(`/websites/${encodeURIComponent(asset.id)}`);

  const check = createMutation(() => ({
    mutationFn: () => api(`/exposure/${asset.id}/run`, { method: "POST" }),
    onSuccess: refresh,
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const remove = createMutation(() => ({
    mutationFn: () => api(`/exposure/${asset.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      confirmRemove = false;
      await refresh();
    },
  }));

  const summary = $derived(asset.stage1.summary);
  const when = $derived(asset.stage1.lastAt);
  const busy = $derived(isBusy(asset));
  const actions = $derived<MenuAction[]>(
    canEdit
      ? [
          {
            label: t("websites.checkNow"),
            icon: Play,
            disabled: busy || check.isPending,
            onSelect: () => check.mutate(),
          },
          {
            label: t("websites.verifyOpen"),
            icon: KeyRound,
            onSelect: () => void goto(href(detailHref, { verify: "1" })),
          },
          {
            label: t("websites.remove"),
            icon: Trash2,
            destructive: true,
            onSelect: () => {
              remove.reset();
              confirmRemove = true;
            },
          },
        ]
      : [],
  );
</script>

<!-- The whole row opens the website for the mouse; the name link stays the keyboard and screen-reader path. -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<tr
  class="row-link border-b align-top last:border-0"
  data-asset={asset.value}
  onclick={rowClick(() => void goto(detailHref))}
>
  <td class="w-full max-w-0 px-5 py-3 @wide:w-auto @wide:max-w-none">
    <div class="flex min-w-0 items-start gap-2.5">
      <Globe aria-hidden="true" class="mt-1 size-4 flex-none text-muted-foreground" />
      <div class="min-w-0">
        <a href={detailHref} class="font-medium break-all hover:underline">{asset.value}</a>
        <div class="text-sm text-muted-foreground">
          {t(`websites.kind.${asset.kind}`)}
          {#if summary && summary.addresses.length > 0}
            <span class="font-mono"> · {summary.addresses.slice(0, 2).join(", ")}</span>
          {/if}
        </div>
        <div class="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground @wide:hidden">
          <span class="@3xl:hidden"><VerificationBadge {asset} /></span>
          <StageBadge {asset} stage={1} />
          <span class="@3xl:hidden"><StageBadge {asset} stage={2} /></span>
          {#if summary?.certificateExpires}
            <span>{t("websites.columnCertificate")}: <CertificateExpiry expires={summary.certificateExpires} /></span>
          {/if}
          {#if when}<time datetime={when} class="@3xl:hidden">{formatRelative(when)}</time>{/if}
        </div>
      </div>
    </div>
  </td>
  <td class="hidden px-3 py-3 @3xl:table-cell"><VerificationBadge {asset} /></td>
  {#each SEVERITY_ORDER as severity (severity)}
    <td class={["px-3 py-3 text-right tabular-nums", severity === "low" && "hidden @wide:table-cell"]}>
      <CountPill {severity} n={asset.open[severity]} />
    </td>
  {/each}
  <td class="hidden px-3 py-3 @wide:table-cell">
    <CertificateExpiry expires={summary?.certificateExpires ?? null} />
  </td>
  <td class="hidden px-3 py-3 @wide:table-cell"><StageBadge {asset} stage={1} /></td>
  <td class="hidden px-3 py-3 @3xl:table-cell">
    <StageBadge {asset} stage={2} />
    {#if asset.stage2.summary && asset.stage2.enabled}
      <div class="mt-1 text-sm text-muted-foreground">
        {t("websites.openPortsCount", { count: asset.stage2.summary.open })}
      </div>
    {/if}
  </td>
  <td class="hidden px-3 py-3 @3xl:table-cell">
    {#if when}
      <time datetime={when} title={formatDateTime(when)} class="text-sm">{formatRelative(when)}</time>
    {:else}
      <span class="text-muted-foreground">–</span>
    {/if}
  </td>
  {#if canEdit}
    <td class="px-3 py-2 text-right @wide:px-5">
      <ActionMenu label={t("websites.moreActions", { name: asset.value })} {actions} />
      <ConfirmDialog
        open={confirmRemove}
        title={t("websites.removeTitle", { asset: asset.value })}
        description={t("websites.removeDescription")}
        confirmLabel={t("websites.remove")}
        pending={remove.isPending}
        error={remove.isError ? t("errors.actionFailed") : null}
        onConfirm={() => remove.mutate()}
        onClose={() => (confirmRemove = false)}
      />
    </td>
  {/if}
</tr>
