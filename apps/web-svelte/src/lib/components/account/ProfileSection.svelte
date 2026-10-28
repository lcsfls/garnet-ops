<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { accountQuery } from "../../account.ts";
  import Card from "../Card.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import ProfileNameCard from "./ProfileNameCard.svelte";
  import ProfilePreferencesCard from "./ProfilePreferencesCard.svelte";

  /** Account → Profile: display name, the (fixed) email address, language and time zone. */
  const query = createQuery(() => accountQuery);
</script>

{#if !query.data}
  <Card>
    <QueryStatus {query} />
  </Card>
{:else}
  <ProfileNameCard profile={query.data.profile} />
  <ProfilePreferencesCard profile={query.data.profile} />
{/if}
