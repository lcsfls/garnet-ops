<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import type { HostSettings } from "../../../hosts.ts";
  import { type MessageKey, t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import type { ExposureSettings } from "../../../websites.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Badge from "../../ui/Badge.svelte";
  import CertificateTransparency from "./CertificateTransparency.svelte";
  import PublicDns from "./PublicDns.svelte";
  import RegistryChecks from "./RegistryChecks.svelte";
  import Wordfence from "./Wordfence.svelte";
  import WordPressOrg from "./WordPressOrg.svelte";

  /**
   * Settings, External services: every connection GarnetOps makes on the organisation's behalf beyond the systems it was given,
   * in one place (AGENTS.md rule 1: anything that phones home is opt-in, documented and visible). First a list of what is on and
   * what it sends where, then each switch. All are off by default.
   */
  let { me }: { me: Me } = $props();
  const websites = $derived(me.organization.modules?.websites === true);
  const hosts = $derived(me.organization.modules?.hosts === true);

  const dns = createQuery(() => ({
    queryKey: ["organization", "dns"],
    queryFn: () =>
      api<{ provider: string | null; providers: { id: string; name: string }[] }>("/organization/dns"),
  }));
  const exposure = createQuery(() => ({
    queryKey: ["websites", "settings"],
    queryFn: () => api<ExposureSettings>("/exposure/settings"),
    enabled: websites,
  }));
  const hostSettings = createQuery(() => ({
    queryKey: ["hosts", "settings"],
    queryFn: () => api<HostSettings>("/hosts/settings"),
    enabled: hosts,
  }));

  interface Row {
    id: string;
    name: MessageKey;
    sends: MessageKey;
    on: boolean | null;
    state?: string;
  }
  const rows = $derived.by((): Row[] => {
    const dnsProvider = dns.data?.provider
      ? (dns.data.providers.find((p) => p.id === dns.data?.provider)?.name ?? dns.data.provider)
      : null;
    const list: Row[] = [
      {
        id: "ext-dns",
        name: "settings.externalDns",
        sends: "settings.externalDnsSends",
        on: dns.data ? dnsProvider !== null : null,
        ...(dnsProvider ? { state: dnsProvider } : {}),
      },
    ];
    if (websites) {
      const e = exposure.data;
      list.push(
        {
          id: "ext-ct",
          name: "settings.externalCt",
          sends: "settings.externalCtSends",
          on: e ? e.certificateTransparency.enabled : null,
        },
        {
          id: "ext-wordpress-org",
          name: "settings.externalWordpressOrg",
          sends: "settings.externalWordpressOrgSends",
          on: e ? e.wordpressOrg.enabled : null,
        },
        {
          id: "ext-wordfence",
          name: "settings.externalWordfence",
          sends: "settings.externalWordfenceSends",
          on: e ? e.wordfence.configured : null,
        },
      );
    }
    if (hosts) {
      list.push({
        id: "ext-registries",
        name: "settings.externalRegistries",
        sends: "settings.externalRegistriesSends",
        on: hostSettings.data ? hostSettings.data.registryChecks.enabled : null,
      });
    }
    return list;
  });
</script>

<div class="grid gap-4">
  <Card>
    <CardHeader title={t("settings.externalTitle")} description={t("settings.externalDescription")} />
    <ul class="border-t" data-testid="external-services">
      {#each rows as row (row.id)}
        <li class="flex flex-wrap items-start gap-x-3 gap-y-1 border-b px-5 py-3 last:border-0" data-service={row.id}>
          <span class="min-w-0 flex-1">
            <a href={`#${row.id}`} class="font-medium hover:underline">{t(row.name)}</a>
            <span class="block text-sm text-muted-foreground">{t(row.sends)}</span>
          </span>
          {#if row.on !== null}
            <Badge tone={row.on ? "info" : "neutral"}>
              {row.on ? (row.state ?? t("settings.externalOn")) : t("settings.externalOff")}
            </Badge>
          {/if}
        </li>
      {/each}
      <li class="flex flex-wrap items-start gap-x-3 gap-y-1 px-5 py-3">
        <span class="min-w-0 flex-1">
          <a href="/system" class="font-medium hover:underline">{t("settings.externalVulnDb")}</a>
          <span class="block text-sm text-muted-foreground">{t("settings.externalVulnDbSends")}</span>
        </span>
      </li>
    </ul>
  </Card>

  <div id="ext-dns" class="scroll-mt-4"><PublicDns {me} /></div>
  {#if websites}
    <div id="ext-ct" class="scroll-mt-4"><CertificateTransparency {me} /></div>
    <div id="ext-wordpress-org" class="scroll-mt-4"><WordPressOrg {me} /></div>
    <div id="ext-wordfence" class="scroll-mt-4"><Wordfence {me} /></div>
  {/if}
  {#if hosts}<div id="ext-registries" class="scroll-mt-4"><RegistryChecks {me} /></div>{/if}
  {#if !websites || !hosts}<p class="text-sm text-muted-foreground">{t("settings.externalMoreWithModules")}</p>{/if}
</div>
