<script lang="ts">
  import { EXPOSURE_PORTS } from "@garnetops/core/exposure";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { hasKey, type MessageKey, t } from "../../i18n.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Button from "../ui/Button.svelte";
  import SeverityBadge from "../ui/SeverityBadge.svelte";
  import CertificateExpiry from "./CertificateExpiry.svelte";

  /** What stage 2 found open. The risk column says how unusual a service is on the internet, not that it is vulnerable. */
  let {
    detail,
    canEdit,
    onStage2,
    class: className = "",
  }: { detail: ExposureDetail; canEdit: boolean; onStage2: () => void; class?: string } = $props();
  const a = $derived(detail.active);
  const severityOf = (port: number) => EXPOSURE_PORTS.find((x) => x.port === port)?.severity ?? null;
  const serviceName = (service: string) =>
    hasKey(`websites.service.${service}`) ? t(`websites.service.${service}` as MessageKey) : service;
</script>

<Card class={className}>
  <CardHeader
    title={t("websites.portsTitle")}
    description={t("websites.portsDescription", { count: EXPOSURE_PORTS.length })}
  >
    {#snippet actions()}
      {#if canEdit}
        <Button variant="outline" class="h-9 px-3 text-sm" onclick={onStage2}>{t("websites.stage2Manage")}</Button>
      {/if}
    {/snippet}
  </CardHeader>
  {#if !a}
    <p class="px-5 pb-5 text-muted-foreground" data-testid="ports-empty">
      {detail.stage2.enabled ? t("websites.portsWaiting") : t("websites.portsOff")}
    </p>
  {:else}
    <p class="px-5 pb-3 text-sm text-muted-foreground">
      {t("websites.portsSummary", {
        checked: a.checked,
        open: detail.ports.length,
        closed: a.closed,
        silent: a.noAnswer,
        when: formatDateTime(a.takenAt),
      })}
    </p>
    {#if detail.ports.length === 0}
      <p class="px-5 pb-5">{t("websites.portsNoneOpen")}</p>
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm" data-testid="websites-ports">
          <thead class="text-muted-foreground">
            <tr class="border-y">
              <th class="px-5 py-2 font-medium">{t("websites.portColumn")}</th>
              <th class="px-3 py-2 font-medium">{t("websites.portService")}</th>
              <th class="px-3 py-2 font-medium">{t("websites.portRisk")}</th>
              <th class="px-3 py-2 font-medium">{t("websites.portBanner")}</th>
              <th class="hidden px-3 py-2 font-medium @xwide:table-cell">{t("websites.portFirstSeen")}</th>
            </tr>
          </thead>
          <tbody>
            {#each detail.ports as r (`${r.address}-${r.port}`)}
              {@const severity = severityOf(r.port)}
              <tr class="border-b align-top last:border-0">
                <td class="px-5 py-2.5">
                  <span class="font-mono font-medium">{r.port}</span>
                  <div class="font-mono text-xs break-all text-muted-foreground">{r.address}</div>
                </td>
                <td class="px-3 py-2.5">{serviceName(r.service)}</td>
                <td class="px-3 py-2.5">
                  {#if severity}<SeverityBadge {severity} />{:else}<span class="text-muted-foreground"
                      >{t("websites.portUsual")}</span
                    >{/if}
                </td>
                <td class="px-3 py-2.5">
                  {#if r.banner}
                    <pre class="max-w-[48ch] font-mono text-xs break-all whitespace-pre-wrap">{r.banner}</pre>
                  {:else if r.tls?.ok}
                    <span class="text-muted-foreground">
                      {r.tls.protocol} ·
                      {#if r.tls.cert}<CertificateExpiry expires={r.tls.cert.validTo} />{/if}
                    </span>
                  {:else}
                    <span class="text-muted-foreground">–</span>
                  {/if}
                </td>
                <td class="hidden px-3 py-2.5 @xwide:table-cell">
                  <time datetime={r.firstSeenAt}>{formatRelative(r.firstSeenAt)}</time>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</Card>
