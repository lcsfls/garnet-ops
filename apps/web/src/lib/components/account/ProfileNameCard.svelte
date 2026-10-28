<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import type { AccountOverview } from "../../account.ts";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Field from "../ui/Field.svelte";
  import { refreshMe } from "./refresh-me.ts";

  /** Account → Profile: the display name and the (fixed) email address. */
  let { profile }: { profile: AccountOverview["profile"] } = $props();
  const queryClient = useQueryClient();
  // svelte-ignore state_referenced_locally
  let name = $state(profile.name);
  let error = $state<string | null>(null);
  // The name of a directory account comes from the directory (ADR 0020).
  const directory = $derived(profile.source === "directory");
  const save = createMutation(() => ({
    mutationFn: (value: string) => api("/account/profile", { method: "PATCH", body: { name: value } }),
    onSuccess: async () => {
      toast.success(t("account.profile.saved"));
      await refreshMe(queryClient);
    },
    onError: (e: Error) => {
      error =
        e instanceof ApiError && e.status === 422 ? t("account.profile.errorName") : t("errors.generic");
    },
  }));
  function submit(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    save.mutate(name.trim());
  }
</script>

<Card>
  <CardHeader title={t("account.profile.title")} description={t("account.profile.description")} />
  <form class="grid gap-5 px-5 py-5" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <Field
      label={t("account.profile.name")}
      hint={directory ? t("account.profile.nameManaged") : undefined}
      name="name"
      required
      maxlength={100}
      autocomplete="name"
      bind:value={name}
      readonly={directory}
      class={directory ? "bg-muted text-muted-foreground" : undefined}
    />
    <Field
      label={t("account.profile.email")}
      hint={t("account.profile.emailHint")}
      name="email"
      type="email"
      readonly
      value={profile.email}
      class="bg-muted text-muted-foreground"
    />
    {#if !directory}
      <div class="flex items-center gap-3">
        <Button type="submit" disabled={save.isPending || name.trim() === "" || name.trim() === profile.name}>
          {save.isPending ? t("common.loading") : t("account.profile.save")}
        </Button>
      </div>
    {/if}
  </form>
</Card>
