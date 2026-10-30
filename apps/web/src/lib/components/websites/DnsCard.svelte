<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { formatDateTime } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Button from "../ui/Button.svelte";
  import Facts, { type Fact } from "./Facts.svelte";

  /** The DNS records stage 1 resolved, and names found under the domain, which an admin may add. */
  let {
    detail,
    canEdit,
    class: className = "",
  }: { detail: ExposureDetail; canEdit: boolean; class?: string } = $props();

  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["websites"] });
  const addName = createMutation(() => ({
    mutationFn: (id: string) => api(`/exposure/discoveries/${id}/add`, { method: "POST" }),
    onSuccess: refresh,
    onError: () => toast.error(t("errors.actionFailed")),
  }));
  const dismiss = createMutation(() => ({
    mutationFn: (id: string) => api(`/exposure/discoveries/${id}/dismiss`, { method: "POST" }),
    onSuccess: refresh,
    onError: () => toast.error(t("errors.actionFailed")),
  }));

  const p = $derived(detail.passive);
  const dns = $derived(p?.dns ?? null);
  const failedText = (kind: string, none: string) =>
    dns?.failed.includes(kind as never) ? t("websites.lookupFailed") : none;

  const rows = $derived.by((): Fact[] => {
    if (!p) return [];
    const list: Fact[] = [{ label: t("websites.dnsAddresses"), list: p.addresses }];
    if (p.nonPublic.length > 0) list.push({ label: t("websites.dnsNonPublic"), list: p.nonPublic });
    if (!dns) {
      list.push({ label: t("websites.dnsPtr"), list: p.ptr ?? [] });
      return list;
    }
    list.push(
      { label: t("websites.dnsCname"), list: dns.cname },
      { label: t("websites.dnsMx"), list: dns.mx.map((m) => `${m.priority} ${m.exchange}`) },
      { label: t("websites.dnsNs"), list: dns.ns },
      dns.caa.length > 0
        ? { label: t("websites.dnsCaa"), list: dns.caa.map((c) => `${c.tag} ${c.value}`) }
        : { label: t("websites.dnsCaa"), text: failedText("caa", t("websites.dnsNone")) },
      dns.spf.record && !dns.failed.includes("txt")
        ? {
            label: t("websites.dnsSpf"),
            text: dns.spf.record,
            mono: true,
            note: t(`websites.spfPolicy.${dns.spf.policy}`),
          }
        : { label: t("websites.dnsSpf"), text: failedText("txt", t("websites.dnsNone")) },
      dns.dmarc.record && !dns.failed.includes("dmarc")
        ? {
            label: t("websites.dnsDmarc"),
            text: dns.dmarc.record,
            mono: true,
            note: dns.dmarc.policy ? t(`websites.dmarcPolicy.${dns.dmarc.policy}`) : null,
          }
        : { label: t("websites.dnsDmarc"), text: failedText("dmarc", t("websites.dnsNone")) },
    );
    list.push(...dnssecRows(dns.dnssec));
    return list;
  });

  /** Technical names, the same in every language. */
  const ALGORITHMS: Record<number, string> = {
    5: "RSA/SHA-1",
    7: "RSA/SHA-1 NSEC3",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    13: "ECDSA P-256",
    14: "ECDSA P-384",
    15: "Ed25519",
    16: "Ed448",
  };
  const DIGESTS: Record<number, string> = { 1: "SHA-1", 2: "SHA-256", 4: "SHA-384" };
  const algorithm = (n: number) => `${ALGORITHMS[n] ?? "?"} (${n})`;

  function dnssecRows(d: NonNullable<typeof dns>["dnssec"]): Fact[] {
    if (d === "unknown") return [{ label: t("websites.dnsDnssec"), text: t("websites.dnssecUnknown") }];
    const rows: Fact[] = [
      {
        label: t("websites.dnsDnssec"),
        text: t(`websites.dnssecState.${d.state}`),
        note: d.problem
          ? t(`websites.dnssecProblem.${d.problem}`)
          : t("websites.dnssecZone", { zone: d.zone }),
      },
    ];
    if (d.keys.length > 0) {
      rows.push({
        label: t("websites.dnssecKeys"),
        list: d.keys.map((k) => `${k.flags & 1 ? "KSK" : "ZSK"} ${k.keyTag} · ${algorithm(k.algorithm)}`),
      });
    }
    if (d.ds.length > 0) {
      rows.push({
        label: t("websites.dnssecDs"),
        list: d.ds.map(
          (x) =>
            `${x.keyTag} · ${algorithm(x.algorithm)} · ${DIGESTS[x.digestType] ?? x.digestType} · ${
              x.matches ? t("websites.dnssecDsMatches") : t("websites.dnssecDsNoMatch")
            }`,
        ),
      });
    }
    if (d.expiresAt) rows.push({ label: t("websites.dnssecValidUntil"), text: formatDateTime(d.expiresAt) });
    return rows;
  }
</script>

<Card class={className}>
  <CardHeader title={t("websites.dnsTitle")} description={t("websites.dnsDescription")} />
  {#if !p}
    <p class="px-5 pb-5 text-muted-foreground">{t("websites.notYet")}</p>
  {:else}
    <Facts {rows} />
  {/if}
  {#if detail.suggestions.length > 0}
    <section aria-labelledby="websites-suggestions" class="border-t px-5 py-4">
      <h3 id="websites-suggestions" class="font-medium">{t("websites.suggestionsTitle")}</h3>
      <p class="mb-2 text-sm text-muted-foreground">{t("websites.suggestionsText")}</p>
      <ul class="grid gap-1.5" data-testid="websites-suggestions">
        {#each detail.suggestions as s (s.id)}
          <li class="flex flex-wrap items-center gap-2">
            <span class="font-mono text-sm break-all">{s.name}</span>
            <span class="text-xs text-muted-foreground">{t(`websites.suggestionSource.${s.source}`)}</span>
            {#if canEdit}
              <span class="ml-auto flex gap-1.5">
                <Button
                  variant="outline"
                  class="h-8 px-3 text-sm"
                  disabled={addName.isPending}
                  onclick={() => addName.mutate(s.id)}
                  aria-label={t("websites.suggestionAddNamed", { name: s.name })}
                >
                  {t("websites.suggestionAdd")}
                </Button>
                <Button
                  variant="ghost"
                  class="h-8 px-3 text-sm"
                  disabled={dismiss.isPending}
                  onclick={() => dismiss.mutate(s.id)}
                  aria-label={t("websites.suggestionDismissNamed", { name: s.name })}
                >
                  {t("websites.suggestionDismiss")}
                </Button>
              </span>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}
</Card>
