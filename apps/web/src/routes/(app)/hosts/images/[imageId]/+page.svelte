<script lang="ts">
  import { ArrowLeft, Flame, Layers } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import UpdateBadge from "#lib/components/hosts/UpdateBadge.svelte";
  import ModuleOff from "#lib/components/ModuleOff.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import QueryStatus from "#lib/components/QueryStatus.svelte";
  import RepositoryLink from "#lib/components/RepositoryLink.svelte";
  import SeverityBadge from "#lib/components/ui/SeverityBadge.svelte";
  import Facts from "#lib/components/websites/Facts.svelte";
  import { formatDateTime, formatRelative } from "#lib/format.ts";
  import { type ImageDetail, shortId } from "#lib/hosts.ts";
  import { t } from "#lib/i18n.svelte.ts";
  import { isAdmin } from "#lib/nav.ts";
  import { page } from "$app/state";
  import type { PageData } from "./$types";

  /**
   * One image a host runs (ADR 0034): where it runs, the repository it was built from, newer images, and the known vulnerabilities in
   * its packages.
   */
  let { data: pageData }: { data: PageData } = $props();
  const me = $derived(pageData.me);
  const on = $derived(me.organization.modules?.hosts === true);
  const imageId = $derived(page.params.imageId ?? "");
  const query = createQuery(() => ({
    queryKey: ["hosts", "image", imageId],
    queryFn: () => api<ImageDetail>(`/hosts/images/${encodeURIComponent(imageId)}`),
    enabled: on,
    refetchInterval: (q: { state: { data?: ImageDetail } }) =>
      q.state.data && (!q.state.data.packagesAt || !q.state.data.matchedAt) ? 5000 : false,
  }));
  const image = $derived(query.data);
  const title = $derived(image ? (image.tags[0] ?? shortId(image.imageId)) : t("hosts.imageTitle"));
  const revision = $derived(image?.labels["org.opencontainers.image.revision"] ?? null);
</script>

<a href="/hosts" class="mb-3 inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground hover:underline">
  <ArrowLeft aria-hidden="true" class="size-4" />{t("hosts.back")}
</a>
<PageHeader icon={Layers} {title} description={image ? `${t("hosts.imageTitle")} ${shortId(image.imageId)}` : ""} />

{#if !on}
  <ModuleOff module="hosts" canSwitch={isAdmin(me)} />
{:else if !image}
  <Card><QueryStatus {query} /></Card>
{:else}
  <div class="grid items-start gap-4 @wide:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
    <div class="grid gap-4">
      <Card>
        <CardHeader title={t("hosts.imageFacts")} />
        <Facts
          rows={[
            { label: t("hosts.source"), value: image.repository ? repositoryLink : undefined, text: image.repository ? null : t("hosts.noRepository"), note: image.repository ? null : t("hosts.noRepositoryHint") },
            { label: t("hosts.tags"), list: image.tags },
            { label: t("hosts.digests"), list: image.digests.map((d) => d.slice(d.indexOf("@") + 1)) },
            { label: t("hosts.builtAt"), text: image.builtAt ? formatDateTime(image.builtAt) : null },
            { label: t("hosts.platform"), text: [image.os, image.architecture].filter(Boolean).join("/") || null },
            { label: t("hosts.distro"), text: image.distro },
            {
              label: t("hosts.packages"),
              text: image.packageCount !== null ? t("hosts.packagesCount", { count: image.packageCount }) : t("hosts.packagesWaiting"),
            },
            { label: t("hosts.matchedAt"), text: image.matchedAt ? formatRelative(image.matchedAt) : null },
          ]}
        />
      </Card>
      <Card>
        <CardHeader title={t("hosts.runsOn")} />
        <ul class="grid gap-1.5 px-5 pb-5 text-sm" data-testid="image-running">
          {#each image.running as r (`${r.hostId}-${r.containerId}`)}
            <li>
              <a href={`/hosts/${encodeURIComponent(r.hostId)}`} class="font-medium text-primary-text hover:underline">{r.hostName}</a>
              <span class="text-muted-foreground">· {r.name}</span>
            </li>
          {/each}
        </ul>
      </Card>
      <Card>
        <CardHeader title={t("hosts.updatesTitle")} description={t("hosts.updatesDescription")} />
        <ul class="grid gap-2 px-5 pb-5 text-sm">
          {#each image.updates as u (u.ref)}
            <li class="grid gap-1">
              <span class="font-mono break-all">{u.ref}</span>
              <span><UpdateBadge update={u} /></span>
            </li>
          {/each}
        </ul>
      </Card>
    </div>

    <Card>
      <CardHeader title={t("hosts.findingsTitle")} description={t("hosts.findingsDescription")} />
      {#if !image.matchedAt}
        <p class="px-5 pb-5 text-muted-foreground">{t("hosts.findingsWaiting")}</p>
      {:else if image.findings.length === 0}
        <p class="px-5 pb-5 text-muted-foreground">{t("hosts.findingsNone")}</p>
      {:else}
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm" data-testid="image-findings">
            <thead class="text-muted-foreground">
              <tr class="border-y">
                <th class="px-5 py-2 font-medium">{t("hosts.columnSeverity")}</th>
                <th class="px-3 py-2 font-medium">{t("hosts.columnVulnerability")}</th>
                <th class="px-3 py-2 font-medium">{t("hosts.columnPackage")}</th>
                <th class="px-5 py-2 font-medium">{t("hosts.columnFixedIn")}</th>
              </tr>
            </thead>
            <tbody>
              {#each image.findings as f (f.id)}
                <tr class="border-b align-top last:border-0">
                  <td class="px-5 py-2.5"><SeverityBadge severity={f.severity} /></td>
                  <td class="px-3 py-2.5">
                    <span class="font-mono">{f.vulnerabilityId}</span>
                    {#if f.knownExploited}
                      <span class="ml-1 inline-flex items-center gap-1 text-destructive-text">
                        <Flame aria-hidden="true" class="size-3.5" />{t("hosts.knownExploited")}
                      </span>
                    {/if}
                  </td>
                  <td class="px-3 py-2.5 font-mono break-all">{f.packageName}@{f.packageVersion}</td>
                  <td class="px-5 py-2.5 font-mono">{f.fixedIn?.length ? f.fixedIn.join(", ") : "–"}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </Card>
  </div>
{/if}

{#snippet repositoryLink()}
  {#if image?.repository}
    <RepositoryLink id={image.repository.id} name={image.repository.name} />
    {#if revision}<span class="block font-mono text-xs text-muted-foreground">{t("hosts.revision", { revision: revision.slice(0, 12) })}</span>{/if}
  {/if}
{/snippet}
