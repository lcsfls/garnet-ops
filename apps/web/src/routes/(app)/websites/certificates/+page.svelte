<script lang="ts">
  import { Globe, ListPlus } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import ModuleOff from "#lib/components/ModuleOff.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import SearchInput from "#lib/components/SearchInput.svelte";
  import Badge from "#lib/components/ui/Badge.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import CertificateExpiry from "#lib/components/websites/CertificateExpiry.svelte";
  import WebsitesNav from "#lib/components/websites/WebsitesNav.svelte";
  import { formatDate } from "#lib/format.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { websiteCertificatesSearch } from "#lib/search.ts";
  import { href, parseSearch } from "#lib/url.ts";
  import type { CertificateGroup, CertificateServer } from "#lib/websites.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * The certificates of website monitoring, one row per certificate (by fingerprint) with every website that served it in its
   * latest look. A wildcard certificate on twelve names is one row here; each website keeps its own findings. Everyone reads.
   */
  let { data }: { data: PageData } = $props();
  const me = $derived(data.me);
  const on = $derived(me.organization.modules?.websites === true);
  const canEdit = $derived(isAdmin(me));
  const search = $derived(parseSearch(websiteCertificatesSearch, page.url));

  const query = createQuery(() => ({
    queryKey: ["websites", "certificates"],
    queryFn: () => api<{ items: CertificateGroup[] }>("/exposure/certificates"),
    enabled: on,
  }));

  const matches = (group: CertificateGroup, q: string) => {
    const needle = q.toLowerCase();
    return (
      group.subject.toLowerCase().includes(needle) ||
      group.issuer.toLowerCase().includes(needle) ||
      group.sans.some((s) => s.toLowerCase().includes(needle)) ||
      group.assets.some((x) => x.value.includes(needle))
    );
  };
  const items = $derived(
    (query.data?.items ?? []).filter(
      (group) =>
        (!search.certificate || group.fingerprint === search.certificate) &&
        (!search.q || matches(group, search.q)),
    ),
  );
  const names = $derived(new Set((query.data?.items ?? []).flatMap((g) => g.assets.map((x) => x.id))).size);

  /** Alternative names without the `DNS:` prefix the certificate reader keeps. */
  const sanText = (san: string) => san.replace(/^DNS:/i, "");
  const keyText = (group: CertificateGroup) =>
    `${(group.keyType ?? "").toUpperCase()}${group.keyBits ? ` ${group.keyBits}` : ""}`;
  const missText = (server: CertificateServer) =>
    server.wildcardMiss
      ? t(`websites.certificates.miss.${server.wildcardMiss.reason}`, {
          wildcard: server.wildcardMiss.wildcard,
          name: server.value,
        })
      : t("websites.certificates.notCovered");
  const setQuery = (q: string) =>
    void goto(href(page.url.pathname, { ...search, q: q || undefined }), { replace: true, reset: false });
</script>

<PageHeader icon={Globe} title={t("websites.title")} description={t("websites.certificates.description")}>
  {#snippet actions()}
    {#if on && canEdit}
      <Button variant="outline" onclick={() => void goto(href("/websites", { add: "1", list: "1" }))}>
        <ListPlus aria-hidden="true" class="size-4" />
        {t("websites.addList")}
      </Button>
    {/if}
  {/snippet}
</PageHeader>

{#if !on}
  <ModuleOff module="websites" canSwitch={canEdit} />
{:else}
  <WebsitesNav current="certificates" />

  <p class="mb-4 max-w-[80ch] text-sm text-muted-foreground" data-testid="certificates-help">
    {t("websites.certificates.help")}
  </p>

  <div class="mb-4 flex flex-wrap items-center gap-3">
    {#if search.certificate}
      <p class="text-sm">
        {t("websites.certificates.showingOne")}
        <a
          href={href(page.url.pathname, { q: search.q })}
          class="ml-1 text-primary-text hover:underline">{t("websites.certificates.showAll")}</a
        >
      </p>
    {:else if query.data}
      <p class="text-sm text-muted-foreground">
        {t("websites.certificates.summary", { certificates: query.data.items.length, names })}
      </p>
    {/if}
    <SearchInput
      class="ml-auto"
      label={t("websites.certificates.search")}
      value={search.q ?? ""}
      onChange={setQuery}
    />
  </div>

  <Card>
    <table class="w-full table-fixed text-left" data-testid="certificates-table">
      <thead class="text-sm text-muted-foreground">
        <tr class="border-b">
          <th class="px-5 py-2.5 font-medium">{t("websites.certificates.columnCertificate")}</th>
          <th class="w-36 px-3 py-2.5 font-medium">{t("websites.certificates.columnValidUntil")}</th>
          <th class="hidden w-[18%] px-3 py-2.5 font-medium @wide:table-cell">{t("websites.certificates.columnIssuer")}</th>
          <th class="hidden w-28 px-3 py-2.5 font-medium @xwide:table-cell">{t("websites.certificates.columnKey")}</th>
          <th class="w-[36%] px-3 py-2.5 font-medium @wide:px-5">{t("websites.certificates.columnWebsites")}</th>
        </tr>
      </thead>
      <tbody>
        {#each items as group (group.fingerprint)}
          <tr class="border-b align-top last:border-0" data-fingerprint={group.fingerprint}>
            <td class="px-5 py-3 break-words">
              <div class="flex flex-wrap items-center gap-1.5">
                <span class="font-medium break-all">{group.subject || sanText(group.sans[0] ?? "")}</span>
                {#if group.wildcards.length > 0}
                  <Badge tone="outline">{t("websites.certificates.wildcard")}</Badge>
                {/if}
                {#if group.selfSigned}
                  <Badge tone="neutral">{t("websites.tlsSelfSigned")}</Badge>
                {/if}
              </div>
              {#if group.sans.length > 0}
                <ul class="mt-1 flex flex-wrap gap-x-2 gap-y-0.5 font-mono text-sm text-muted-foreground" aria-label={t("websites.tlsNames")}>
                  {#each group.sans as san, i (i)}
                    <li class="break-all">
                      {#if san.replace(/^DNS:/i, "").startsWith("*.")}
                        <span class="font-semibold text-foreground">{sanText(san)}</span>
                      {:else}{sanText(san)}{/if}
                    </li>
                  {/each}
                </ul>
              {/if}
              <!-- Issuer and key move under the certificate where their columns do not fit. -->
              <div class="mt-1 text-sm text-muted-foreground @xwide:hidden">
                <span class="@wide:hidden">{group.issuer} · </span>{keyText(group)}
              </div>
              <details class="mt-1 text-sm">
                <summary class="cursor-pointer text-muted-foreground">{t("websites.tlsFingerprint")}</summary>
                <span class="font-mono break-all">{group.fingerprint}</span>
              </details>
            </td>
            <td class="px-3 py-3 text-sm">
              <div>{formatDate(group.validTo)}</div>
              <CertificateExpiry expires={group.validTo} />
            </td>
            <td class="hidden px-3 py-3 text-sm break-words @wide:table-cell">{group.issuer}</td>
            <td class="hidden px-3 py-3 text-sm break-words @xwide:table-cell">{keyText(group)}</td>
            <td class="px-3 py-3 @wide:px-5">
              <p class="mb-1 text-sm text-muted-foreground">
                {t("websites.certificates.servedOn", { count: group.assets.length })}
              </p>
              <ul class="grid gap-1 @xwide:grid-cols-2">
                {#each group.assets as server (server.id)}
                  <li class="min-w-0">
                    <a
                      href={`/websites/${encodeURIComponent(server.id)}?tab=tls`}
                      class="break-all text-primary-text hover:underline">{server.value}</a
                    >
                    {#if server.nameMatches === false}
                      <span class="block text-sm text-warning-text" data-testid="certificate-miss">{missText(server)}</span>
                    {/if}
                  </li>
                {/each}
              </ul>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    <QueryStatus {query} />
    {#if query.data && items.length === 0}
      <p class="px-5 py-6 text-muted-foreground">
        {query.data.items.length === 0 ? t("websites.certificates.empty") : t("websites.certificates.noMatch")}
      </p>
    {/if}
  </Card>
{/if}
