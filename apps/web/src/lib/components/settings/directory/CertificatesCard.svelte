<script lang="ts">
  import { Fingerprint } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../../api.ts";
  import type { DirectoryView } from "../../../directory.ts";
  import { t } from "../../../i18n.svelte.ts";
  import type { Me } from "../../../session.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import CertificateBadge from "./CertificateBadge.svelte";
  import CertificateDialog from "./CertificateDialog.svelte";

  let { me, view }: { me: Me; view: DirectoryView } = $props();

  const queryClient = useQueryClient();
  let reviewing = $state<string | null>(null);
  const scan = createMutation(() => ({
    mutationFn: (url: string | null) =>
      api<DirectoryView>("/directory/certificates/scan", { method: "POST", body: url ? { url } : {} }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["directory"] }),
  }));
  const server = $derived(view.servers.find((s) => s.url === reviewing) ?? null);
</script>

<Card>
  <CardHeader title={t("directory.certificatesTitle")} description={t("directory.certificatesDescription")}>
    {#snippet actions()}
      <Button variant="outline" disabled={scan.isPending} onclick={() => scan.mutate(null)}>
        <Fingerprint aria-hidden="true" class="size-4" />
        {scan.isPending ? t("common.loading") : t("directory.readCertificates")}
      </Button>
    {/snippet}
  </CardHeader>
  {#if scan.isError}
    <div class="px-5 pb-3">
      <Alert tone="error">{t("errors.actionFailed")}</Alert>
    </div>
  {/if}
  <ul>
    {#each view.servers as s (s.url)}
      <li class="grid gap-1 border-t px-5 py-3" data-testid={`dir-server-${s.url}`}>
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-mono text-sm break-all">{s.url}</span>
          <Badge tone="neutral">{t(`directory.transport.${s.transport}`)}</Badge>
          <CertificateBadge server={s} />
          {#if s.certificate?.candidate}
            <Button class="ml-auto h-9" onclick={() => (reviewing = s.url)}>
              <Fingerprint aria-hidden="true" class="size-4" />
              {t(s.certificate.status === "changed" ? "directory.reviewChange" : "directory.confirmCertificate")}
            </Button>
          {/if}
        </div>
        {#if s.certificate?.pin}
          <div class="font-mono text-[13px] break-all text-muted-foreground">
            {s.certificate.pin.fingerprint}
          </div>
        {:else}
          <div class="text-sm text-muted-foreground">
            {s.certificate?.candidate ? t("directory.waitingForConfirmation") : t("directory.noCertificateYet")}
          </div>
        {/if}
      </li>
    {/each}
  </ul>
  {#if server}<CertificateDialog {me} {server} onClose={() => (reviewing = null)} />{/if}
</Card>
