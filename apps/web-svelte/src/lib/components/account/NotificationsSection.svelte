<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { t } from "../../i18n.svelte.ts";
  import { preferencesQuery } from "../../notifications.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import NotificationsMatrix from "./NotificationsMatrix.svelte";

  /**
   * Account → Notifications (ADR 0019): the matrix of what this person receives, per event type,
   * in the app and by email. Not the organisation's shared channels, which admins manage under
   * Settings → Notifications; the text says so in both places.
   */
  const query = createQuery(() => preferencesQuery);
</script>

{#if !query.data}
  <Card>
    <CardHeader title={t("account.notifications.title")} description={t("account.notifications.description")} />
    <QueryStatus {query} />
  </Card>
{:else}
  <NotificationsMatrix data={query.data} />
{/if}
