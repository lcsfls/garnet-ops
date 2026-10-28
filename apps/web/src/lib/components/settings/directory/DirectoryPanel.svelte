<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { directoryQuery } from "../../../directory.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import QueryStatus from "../../QueryStatus.svelte";
  import Alert from "../../ui/Alert.svelte";
  import CertificatesCard from "./CertificatesCard.svelte";
  import SettingsCard from "./SettingsCard.svelte";
  import TestCard from "./TestCard.svelte";

  /**
   * Settings → Sign-in (owners): signing in with LDAP or Active Directory (ADR 0020). The service account's password is
   * write-only; the connection test shows what the directory says about a person and never a password.
   */
  let { me }: { me: Me } = $props();

  const query = createQuery(() => ({
    ...directoryQuery,
    // The worker reads certificates a moment after they are asked for.
    refetchInterval: (q) =>
      q.state.data?.servers.some((s) => s.certificate?.status === "pending" && !s.certificate.candidate)
        ? 2500
        : false,
  }));
  let version = $state(0);
  const view = $derived(query.data);
</script>

{#if me.role !== "owner"}
  <Card>
    <CardHeader title={t("directory.panelTitle")} description={t("directory.panelDescription")} />
    <div class="px-5 pb-5">
      <Alert tone="info">{t("directory.ownersOnly")}</Alert>
    </div>
  </Card>
{:else if !view}
  <Card>
    <CardHeader title={t("directory.panelTitle")} description={t("directory.panelDescription")} />
    <QueryStatus {query} />
  </Card>
{:else}
  {#key `${version}:${view.configured}`}
    <SettingsCard {me} {view} onSaved={() => version++} />
  {/key}
  {#if view.configured && view.settings?.tlsTrust === "pin"}<CertificatesCard {me} {view} />{/if}
  {#if view.configured}<TestCard {view} />{/if}
{/if}
