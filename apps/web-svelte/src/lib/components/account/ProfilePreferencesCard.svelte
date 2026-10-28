<script lang="ts">
  import { LANGUAGE_NAMES, LANGUAGES, type Language, resolveLanguage } from "@garnetops/i18n";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import type { AccountOverview } from "../../account.ts";
  import { api } from "../../api.ts";
  import { language, setLanguage, t } from "../../i18n.svelte.ts";
  import { browserTimeZone, setPreferredTimeZone, timeZoneChoices } from "../../time-zone.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import FormField from "../ui/FormField.svelte";
  import FormRow from "../ui/FormRow.svelte";
  import Select from "../ui/Select.svelte";
  import { refreshMe } from "./refresh-me.ts";

  /** Account → Profile: language and time zone, stored on the account (ADR 0017). */
  let { profile }: { profile: AccountOverview["profile"] } = $props();
  const queryClient = useQueryClient();
  // svelte-ignore state_referenced_locally
  let locale = $state<Language>(profile.locale ?? resolveLanguage(language()));
  // "" is automatic: the browser's zone.
  // svelte-ignore state_referenced_locally
  let zone = $state(profile.timeZone ?? "");
  let error = $state<string | null>(null);
  const zones = $derived(timeZoneChoices(profile.timeZone));
  const save = createMutation(() => ({
    mutationFn: () =>
      api("/account/preferences", { method: "PUT", body: { locale, timeZone: zone === "" ? null : zone } }),
    onSuccess: async () => {
      setPreferredTimeZone(zone === "" ? null : zone);
      await setLanguage(locale);
      toast.success(t("account.profile.saved"));
      await refreshMe(queryClient);
    },
    onError: () => {
      error = t("errors.generic");
    },
  }));
  function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    save.mutate();
  }
</script>

<Card>
  <CardHeader
    title={t("account.profile.preferencesTitle")}
    description={t("account.profile.preferencesDescription")}
  />
  <form class="grid gap-5 px-5 py-5" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <FormRow columns={["12rem", "1fr"]} from="md">
      <FormField label={t("account.profile.language")}>
        {#snippet children(control)}
          <Select {...control} bind:value={locale}>
            {#each LANGUAGES as l (l)}
              <option value={l} lang={l}>{LANGUAGE_NAMES[l]}</option>
            {/each}
          </Select>
        {/snippet}
      </FormField>
      <FormField label={t("account.profile.timeZone")} hint={t("account.profile.timeZoneHint")}>
        {#snippet children(control)}
          <Select {...control} bind:value={zone}>
            <option value="">{t("account.profile.timeZoneAuto", { zone: browserTimeZone() })}</option>
            {#each zones as z (z)}
              <option value={z}>{z}</option>
            {/each}
          </Select>
        {/snippet}
      </FormField>
    </FormRow>
    <div class="flex items-center gap-3">
      <Button type="submit" disabled={save.isPending}>
        {save.isPending ? t("common.loading") : t("account.profile.save")}
      </Button>
    </div>
  </form>
</Card>
