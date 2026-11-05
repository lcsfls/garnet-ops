<script lang="ts">
  import type { TlsSnapshot } from "@garnetops/core/exposure";
  import { wildcardMiss } from "@garnetops/core/exposure-certificates";
  import { formatDateTime, formatNumber } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { href } from "../../url.ts";
  import { daysUntil, type ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Facts, { type Fact } from "./Facts.svelte";

  /**
   * The TLS handshake on port 443 of each looked-at address, as any browser makes it. Under each certificate: the other websites
   * that serve the same one (a wildcard or multi-name certificate), and why a wildcard does not cover this name where it does not.
   */
  let { detail, class: className = "" }: { detail: ExposureDetail; class?: string } = $props();
  const p = $derived(detail.passive);
  const othersOf = (fingerprint: string) =>
    detail.sharedCertificates?.find((x) => x.fingerprint === fingerprint)?.others ?? [];

  /** Why the name check failed, when a wildcard of the certificate is the reason (it covers exactly one level). */
  function nameNote(tls: TlsSnapshot): string | null {
    if (tls.nameMatches !== false || !tls.cert) return null;
    const miss = wildcardMiss(detail.value, tls.cert.sans);
    return miss
      ? t(`websites.certificates.miss.${miss.reason}`, { wildcard: miss.wildcard, name: detail.value })
      : null;
  }

  function expiryText(validTo: string): string {
    const days = daysUntil(validTo) ?? 0;
    return days < 0 ? t("websites.expiredDaysAgo", { days: -days }) : t("websites.expiresInDays", { days });
  }

  function rowsOf(tls: TlsSnapshot): Fact[] {
    if (!tls.ok)
      return [
        { label: t("websites.tlsHandshake"), text: t(`websites.tlsError.${tls.error ?? "handshake"}`) },
      ];
    const rows: Fact[] = [
      {
        label: t("websites.tlsProtocol"),
        text: `${tls.protocol ?? ""}${tls.cipher ? ` · ${tls.cipher}` : ""}`,
      },
    ];
    if (tls.trusted !== null) {
      rows.push({
        label: t("websites.tlsTrust"),
        text: tls.trusted
          ? t("websites.tlsTrusted")
          : t("websites.tlsNotTrusted", { reason: tls.trustError ?? "" }),
      });
    }
    rows.push({
      label: t("websites.tlsName"),
      text:
        tls.nameMatches === null
          ? t("websites.tlsNameNotChecked")
          : tls.nameMatches
            ? t("websites.tlsNameMatches")
            : t("websites.tlsNameDiffers"),
      note: nameNote(tls),
    });
    if (tls.cert) {
      const cert = tls.cert;
      rows.push(
        { label: t("websites.tlsSubject"), text: cert.subject },
        { label: t("websites.tlsIssuer"), text: cert.issuer },
        { label: t("websites.tlsNames"), text: cert.sans.join(", "), mono: true },
        {
          label: t("websites.tlsValid"),
          text: `${formatDateTime(cert.validFrom)} – ${formatDateTime(cert.validTo)}`,
          note: expiryText(cert.validTo),
        },
        {
          label: t("websites.tlsKey"),
          text: `${(cert.keyType ?? "").toUpperCase()}${cert.keyBits ? ` ${cert.keyBits}` : ""}${cert.selfSigned ? ` · ${t("websites.tlsSelfSigned")}` : ""}`,
        },
        { label: t("websites.tlsFingerprint"), text: cert.fingerprint, mono: true },
      );
    }
    rows.push({ label: t("websites.tlsChain"), text: formatNumber(tls.chainLength) });
    if (tls.legacy) {
      const word = (v: boolean | null) => (v === null ? null : v ? t("websites.yes") : t("websites.no"));
      rows.push(
        { label: t("websites.tlsLegacy10"), text: word(tls.legacy.tls10) },
        { label: t("websites.tlsLegacy11"), text: word(tls.legacy.tls11) },
      );
    }
    return rows;
  }
</script>

<Card class={className}>
  <CardHeader title={t("websites.tlsTitle")} description={t("websites.tlsDescription")} />
  {#if !p}
    <p class="px-5 pb-5 text-muted-foreground">{t("websites.notYet")}</p>
  {:else if p.tls.length === 0}
    <p class="px-5 pb-5 text-muted-foreground">
      {p.addresses.length === 0 ? t("websites.noAddress") : t("websites.tlsNone")}
    </p>
  {:else}
    {#each p.tls as tls (tls.address)}
      <section class="border-t first:border-t-0" aria-label={tls.address}>
        <h3 class="px-5 pt-4 pb-2 font-mono text-sm font-medium">{tls.address}:{tls.port}</h3>
        <Facts rows={rowsOf(tls)} />
        {#if tls.cert}
          {@const others = othersOf(tls.cert.fingerprint)}
          {#if others.length > 0}
            <div class="px-5 pb-5 text-sm" data-testid="tls-shared">
              <p>{t("websites.tlsAlsoServed", { count: others.length })}</p>
              <ul class="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
                {#each others.slice(0, 12) as other (other.id)}
                  <li>
                    <a href={`/websites/${encodeURIComponent(other.id)}?tab=tls`} class="break-all text-primary-text hover:underline"
                      >{other.value}</a
                    >
                  </li>
                {/each}
              </ul>
              <a
                href={href("/websites/certificates", { certificate: tls.cert.fingerprint })}
                class="mt-1 inline-block text-primary-text hover:underline">{t("websites.tlsAllNames")}</a
              >
            </div>
          {/if}
        {/if}
      </section>
    {/each}
  {/if}
</Card>
