<script lang="ts">
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { page } from "$app/state";

  const notFound = $derived(page.status === 404);

  // Comes back by itself, e.g. after an update restarted the API.
  $effect(() => {
    if (notFound) return;
    const timer = setInterval(async () => {
      const ok = await fetch("/api/health", { cache: "no-store" })
        .then((r) => r.ok && Boolean(r.headers.get("content-type")?.includes("json")))
        .catch(() => false);
      if (ok) window.location.reload();
    }, 5000);
    return () => clearInterval(timer);
  });
</script>

{#if notFound}
  <!-- An address that does not exist, such as a bookmark to a module removed in 0.0.4 (ADR 0025). -->
  <AuthLayout title={t("notFound.title")}>
    <div class="grid gap-4">
      <p>{t("notFound.text")}</p>
      <a href="/" class="text-primary-text underline-offset-4 hover:underline">{t("notFound.back")}</a>
    </div>
  </AuthLayout>
{:else}
  <AuthLayout title={t("errors.generic")}>
    <div class="grid gap-4">
      <Alert tone="error">{t("errors.network")}</Alert>
      <p class="text-sm text-muted-foreground">{t("errors.reconnects")}</p>
      <Button onclick={() => window.location.reload()}>{t("common.continue")}</Button>
    </div>
  </AuthLayout>
{/if}
