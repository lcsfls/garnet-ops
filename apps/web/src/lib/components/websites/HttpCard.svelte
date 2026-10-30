<script lang="ts">
  import { HSTS_WEAK_BELOW_SECONDS, parseHsts } from "@garnetops/core/exposure";
  import { t } from "../../i18n.svelte.ts";
  import type { ExposureDetail } from "../../websites.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Facts, { type Fact } from "./Facts.svelte";

  const SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
  ] as const;

  /** One request for the home page over HTTPS and one look at plain HTTP; headers shown as text, never interpreted as markup. */
  let { detail, class: className = "" }: { detail: ExposureDetail; class?: string } = $props();
  const p = $derived(detail.passive);
  const http = $derived(p?.http ?? null);

  const rows = $derived.by((): Fact[] => {
    if (!p) return [];
    const list: Fact[] = [
      {
        label: t("websites.httpPlain"),
        text: p.plain
          ? p.plain.status === null
            ? t(`websites.httpError.${p.plain.error ?? "refused"}`)
            : p.plain.redirectsToHttps
              ? t("websites.httpPlainRedirects", { status: p.plain.status })
              : t("websites.httpPlainAnswers", { status: p.plain.status })
          : null,
      },
      {
        label: t("websites.httpHttps"),
        text: http
          ? http.status === null
            ? t(`websites.httpError.${http.error ?? "refused"}`)
            : t("websites.httpStatus", { status: http.status })
          : t("websites.httpNotOpen"),
      },
    ];
    if (http?.finalUrl) list.push({ label: t("websites.httpFinal"), text: http.finalUrl, mono: true });
    for (const s of detail.software) {
      list.push({
        label: s.name,
        text: s.version,
        mono: true,
        note:
          s.status === "endOfLife"
            ? s.eol
              ? t("websites.softwareEndOfLifeSince", { cycle: s.cycle ?? "", date: s.eol })
              : t("websites.softwareEndOfLife", { cycle: s.cycle ?? "" })
            : s.status === "outdated"
              ? t("websites.softwareOutdated", { latest: s.latest ?? "" })
              : s.status === "current"
                ? t("websites.softwareCurrent", { cycle: s.cycle ?? "" })
                : s.status === "distribution"
                  ? t("websites.softwareDistribution")
                  : t("websites.softwareUnknown"),
      });
    }
    if (http && http.redirects.length > 0) {
      list.push({
        label: t("websites.httpRedirects"),
        list: http.redirects.map(
          (r) =>
            `${r.to} (${r.status}, ${r.followed ? t("websites.httpFollowed") : t("websites.httpNotFollowed")})`,
        ),
      });
    }
    return list;
  });
</script>

<Card class={className}>
  <CardHeader title={t("websites.httpTitle")} description={t("websites.httpDescription")} />
  {#if !p}
    <p class="px-5 pb-5 text-muted-foreground">{t("websites.notYet")}</p>
  {:else}
    <div data-testid="websites-http"><Facts {rows} /></div>
    {#if http && http.status !== null}
      <div class="border-t px-5 py-4">
        <h3 class="mb-2 font-medium">{t("websites.headersTitle")}</h3>
        <table class="w-full text-left text-sm" data-testid="websites-headers">
          <tbody>
            {#each SECURITY_HEADERS as name (name)}
              {@const value = http.headers[name]}
              {@const hsts = name === "strict-transport-security" ? parseHsts(value) : null}
              <tr class="border-b align-top last:border-0">
                <th scope="row" class="py-1.5 pr-4 font-mono text-xs font-normal text-muted-foreground">{name}</th>
                <td class="py-1.5 break-all">
                  {#if value}
                    <span class="font-mono">{value}</span>
                    {#if hsts && hsts.maxAge < HSTS_WEAK_BELOW_SECONDS}
                      <span class="block text-muted-foreground">{t("websites.hstsShort")}</span>
                    {/if}
                  {:else}
                    <span class="text-muted-foreground">{t("websites.headerMissing")}</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        <h3 class="mt-4 mb-1 font-medium">{t("websites.bannersTitle")}</h3>
        <table class="w-full text-left text-sm" data-testid="websites-banners">
          <tbody>
            {#each ["server", "x-powered-by"] as const as name (name)}
              <tr class="border-b align-top last:border-0">
                <th scope="row" class="py-1.5 pr-4 font-mono text-xs font-normal text-muted-foreground">{name}</th>
                <td class="py-1.5 font-mono break-all">
                  {#if http.headers[name]}{http.headers[name]}{:else}<span class="font-sans text-muted-foreground"
                      >{t("websites.headerMissing")}</span
                    >{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="mt-2 text-sm text-muted-foreground">{t("websites.bannerNote")}</p>
      </div>
    {/if}
  {/if}
</Card>
