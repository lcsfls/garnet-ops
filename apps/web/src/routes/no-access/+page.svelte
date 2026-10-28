<script lang="ts">
  import { authClient } from "#lib/auth-client.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { signOutAndLeave } from "#lib/session-end.ts";
</script>

<AuthLayout title={t("signIn.title")}>
  <div class="grid gap-4">
    <Alert tone="info">{t("errors.noOrganization")}</Alert>
    <Button variant="outline" onclick={() => signOutAndLeave(() => authClient.signOut())}>{t("common.signOut")}</Button>
  </div>
</AuthLayout>
