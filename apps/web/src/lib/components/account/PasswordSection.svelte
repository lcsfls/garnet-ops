<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { accountQuery } from "../../account.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Alert from "../ui/Alert.svelte";
  import LocalPassword from "./LocalPassword.svelte";

  /** Account → Password: current and new password, and whether the other sessions end. */
  let { email }: { email: string } = $props();
  const account = createQuery(() => accountQuery);
</script>

<!-- The password of a directory account is the directory's (ADR 0020): nothing to change here. -->
{#if account.data?.profile.source === "directory"}
  <Card>
    <CardHeader title={t("account.password.title")} description={t("account.password.managedDescription")} />
    <div class="grid gap-2 px-5 py-5" data-testid="password-managed">
      <Alert tone="info">{t("account.password.managed")}</Alert>
      <p class="text-sm text-muted-foreground">{t("account.password.managedHint")}</p>
    </div>
  </Card>
{:else}
  <LocalPassword {email} />
{/if}
