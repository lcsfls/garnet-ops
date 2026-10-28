<script lang="ts" module>
  import type { NotificationPreferences, PreferenceRow } from "../../notifications.ts";

  type Draft = Record<string, PreferenceRow["preference"]>;
  const GROUPS = ["code", "account", "system"] as const;

  const toDraft = (data: NotificationPreferences): Draft =>
    Object.fromEntries(data.events.map((row) => [row.event, row.preference]));
</script>

<script lang="ts">
  import { defaultPreference, type UserEvent } from "@garnetops/core/user-notifications";
  import { Mail } from "@lucide/svelte";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import { eventMessageKey, preferencesQuery } from "../../notifications.ts";
  import { toast } from "../../toast.svelte.ts";
  import { href } from "../../url.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Select from "../ui/Select.svelte";

  /** The matrix of Account → Notifications, editable until saved. */
  let { data }: { data: NotificationPreferences } = $props();
  const queryClient = useQueryClient();
  // A reload from the server (after saving, or a mail channel that appeared) replaces what was shown: the draft is
  // derived from the data and only overridden locally until the data changes.
  let draft = $derived<Draft>(toDraft(data));
  const saved = $derived<Draft>(toDraft(data));

  const dirty = $derived(
    data.events.some((row) => JSON.stringify(draft[row.event]) !== JSON.stringify(saved[row.event])),
  );
  const save = createMutation(() => ({
    mutationFn: () =>
      api("/me/notification-preferences", {
        method: "PUT",
        body: {
          preferences: data.events.map((row) => ({
            event: row.event,
            ...(draft[row.event] ?? row.preference),
          })),
        },
      }),
    onSuccess: async () => {
      toast.success(t("account.notifications.saved"));
      await queryClient.invalidateQueries({ queryKey: preferencesQuery.queryKey });
    },
    onError: (error: Error) => {
      toast.error(
        error instanceof ApiError && error.status === 422 ? t("errors.invalidValue") : t("errors.actionFailed"),
      );
      void queryClient.invalidateQueries({ queryKey: preferencesQuery.queryKey });
    },
  }));

  function set(row: PreferenceRow, change: Partial<PreferenceRow["preference"]>) {
    draft = { ...draft, [row.event]: { ...(draft[row.event] ?? row.preference), ...change } };
  }
  function restoreDefaults() {
    draft = Object.fromEntries(data.events.map((row) => [row.event, defaultPreference(row.event as UserEvent)]));
  }

  const label = (row: PreferenceRow) =>
    t(`account.notifications.events.${eventMessageKey(row.event)}.label` as MessageKey);
  const hint = (row: PreferenceRow) =>
    t(`account.notifications.events.${eventMessageKey(row.event)}.hint` as MessageKey);
</script>

<Card>
  <CardHeader title={t("account.notifications.title")} description={t("account.notifications.description")} />
  <div class="grid gap-4 px-5 pb-5">
    <p class="text-sm text-muted-foreground">{t("account.notifications.relation")}</p>
    {#if data.canManageChannels}
      <p class="text-sm">
        <a
          href={href("/settings", { section: "notifications" })}
          class="font-medium text-primary-text underline underline-offset-4"
        >
          {t("account.notifications.settingsLink")}
        </a>
      </p>
    {/if}
    {#if data.mailAvailable}
      <p class="flex items-start gap-2 text-sm text-muted-foreground">
        <Mail aria-hidden="true" class="mt-0.5 size-4 flex-none" />
        <span>{t("account.notifications.emailRules", { email: data.email })}</span>
      </p>
    {:else}
      <Alert tone="info">
        <b class="block font-medium">{t("account.notifications.emailUnavailable")}</b>
        {data.canManageChannels
          ? t("account.notifications.emailUnavailableAdmin")
          : t("account.notifications.emailUnavailableMember")}
      </Alert>
    {/if}
    <p class="text-sm text-muted-foreground">{t("account.notifications.onlyRole")}</p>

    <table data-testid="notification-matrix" class="w-full table-fixed border-collapse text-left">
      <thead>
        <tr class="border-b text-sm text-muted-foreground">
          <th scope="col" class="py-2 pr-3 font-medium">
            <span class="sr-only">{t("account.notifications.title")}</span>
          </th>
          <th scope="col" class="w-20 py-2 text-center font-medium">
            {t("account.notifications.inApp")}
          </th>
          <th scope="col" class="w-20 py-2 text-center font-medium">
            {t("account.notifications.email")}
          </th>
        </tr>
      </thead>
      {#each GROUPS as group (group)}
        {@const rows = data.events.filter((row) => row.group === group)}
        {#if rows.length > 0}
          <tbody>
            <tr>
              <th colspan={3} scope="colgroup" class="pt-5 pb-1 text-[13px] font-medium text-muted-foreground">
                {t(`account.notifications.groups.${group}`)}
              </th>
            </tr>
            {#each rows as row (row.event)}
              {@const current = draft[row.event] ?? row.preference}
              <tr data-event={row.event} class="border-t align-top">
                <th scope="row" class="py-3 pr-3 font-normal">
                  <span class="block font-medium">{label(row)}</span>
                  <span class="block text-sm text-muted-foreground">{hint(row)}</span>
                  {#if row.scoped}
                    <Select
                      class="mt-2 h-9 max-w-full text-sm"
                      aria-label={t("account.notifications.scopeLabel", { event: label(row) })}
                      value={current.scope}
                      disabled={!current.inApp && !(current.email && data.mailAvailable)}
                      onchange={(event) => set(row, { scope: event.currentTarget.value as "all" | "mine" })}
                    >
                      <option value="all">
                        {t(`account.notifications.scopes.${row.scopeKind}.all`)}
                      </option>
                      <option value="mine">
                        {t(`account.notifications.scopes.${row.scopeKind}.mine`)}
                      </option>
                    </Select>
                  {/if}
                </th>
                <td class="py-3 text-center">
                  <Checkbox
                    class="mx-auto mt-1"
                    aria-label={t("account.notifications.inAppLabel", { event: label(row) })}
                    checked={current.inApp}
                    onchange={(event) => set(row, { inApp: event.currentTarget.checked })}
                  />
                </td>
                <td class="py-3 text-center">
                  <Checkbox
                    class="mx-auto mt-1"
                    aria-label={t("account.notifications.emailLabel", { event: label(row) })}
                    checked={current.email && data.mailAvailable}
                    disabled={!data.mailAvailable}
                    title={data.mailAvailable ? undefined : t("account.notifications.emailUnavailable")}
                    onchange={(event) => set(row, { email: event.currentTarget.checked })}
                  />
                </td>
              </tr>
            {/each}
          </tbody>
        {/if}
      {/each}
    </table>

    <div class="flex flex-wrap items-center gap-3">
      <Button disabled={save.isPending || !dirty} onclick={() => save.mutate()}>
        {save.isPending ? t("common.loading") : t("account.notifications.save")}
      </Button>
      <Button variant="outline" onclick={restoreDefaults}>
        {t("account.notifications.restore")}
      </Button>
      <span class="text-sm text-muted-foreground">{t("account.notifications.restoreHint")}</span>
    </div>
  </div>
</Card>
