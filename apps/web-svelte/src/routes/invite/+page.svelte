<script lang="ts">
  import { createMutation, createQuery } from "@tanstack/svelte-query";
  import { ApiError, api } from "#lib/api.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { t } from "#lib/i18n.svelte.ts";

  interface Lookup {
    organizationName: string;
    email: string;
    role: "owner" | "admin" | "member" | "viewer";
    invitedBy: string | null;
    hasAccount: boolean;
  }

  /**
   * Accepting an invitation (ADR 0009). The token is in the URL fragment, which the browser never sends to a server;
   * this page posts it to the API itself.
   */
  const token = window.location.hash.slice(1);
  const valid = /^[A-Za-z0-9_-]{43}$/.test(token);
  let fieldErrors = $state<Record<string, string>>({});
  const lookup = createQuery(() => ({
    queryKey: ["invitation", token],
    queryFn: () => api<Lookup>("/invitations/lookup", { method: "POST", body: { token } }),
    enabled: valid,
    retry: false,
  }));
  const accept = createMutation(() => ({
    mutationFn: (body: { token: string; name?: string; password?: string }) =>
      api<{ email: string }>("/invitations/accept", { method: "POST", body }),
    onError: (e: Error) => {
      if (e instanceof ApiError && e.status === 422) {
        fieldErrors = Object.fromEntries((e.problem?.errors ?? []).map((x) => [x.path.split(".")[0], x.message]));
      }
    },
  }));

  function submit(event: SubmitEvent, info: Lookup) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    fieldErrors = {};
    accept.mutate(
      info.hasAccount
        ? { token }
        : { token, name: String(form.get("name") ?? "").trim(), password: String(form.get("password") ?? "") },
    );
  }
</script>

{#if !valid}
  <AuthLayout title={t("invite.signIn")}><Alert tone="error">{t("invite.missing")}</Alert></AuthLayout>
{:else if lookup.isError || (accept.error instanceof ApiError && accept.error.status === 410)}
  <AuthLayout title={t("invite.signIn")}><Alert tone="error">{t("invite.invalid")}</Alert></AuthLayout>
{:else if !lookup.data}
  <AuthLayout title={t("common.loading")}><p class="text-muted-foreground">{t("common.loading")}</p></AuthLayout>
{:else}
  {@const info = lookup.data}
  {@const role = t(`team.roles.${info.role}`)}
  {@const title = t("invite.title", { organization: info.organizationName })}
  {#if accept.isSuccess}
    <AuthLayout {title}>
      <div class="grid gap-4">
        <Alert tone="info">{t("invite.done", { organization: info.organizationName })}</Alert>
        <a
          href="/sign-in"
          class="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 font-medium text-primary-foreground shadow-xs hover:bg-primary/90"
          >{t("invite.signIn")}</a
        >
      </div>
    </AuthLayout>
  {:else}
    <AuthLayout
      {title}
      description={info.invitedBy
        ? t("invite.description", { inviter: info.invitedBy, email: info.email, role })
        : t("invite.descriptionNoInviter", { email: info.email, role })}
    >
      <form class="grid gap-4" onsubmit={(e) => submit(e, info)}>
        {#if accept.isError && !(accept.error instanceof ApiError && accept.error.status === 422)}
          <Alert tone="error">{t("errors.actionFailed")}</Alert>
        {/if}
        {#if info.hasAccount}
          <Alert tone="info">{t("invite.existingAccount")}</Alert>
        {:else}
          <Field
            label={t("invite.name")}
            name="name"
            required
            maxlength={100}
            autocomplete="name"
            error={fieldErrors.name}
          />
          <Field
            label={t("invite.password")}
            hint={t("invite.passwordHint")}
            name="password"
            type="password"
            required
            minlength={12}
            maxlength={256}
            autocomplete="new-password"
            error={fieldErrors.password}
          />
          <input type="email" name="username" value={info.email} autocomplete="username" readonly hidden />
        {/if}
        <Button type="submit" disabled={accept.isPending}>
          {accept.isPending ? t("common.loading") : t("invite.submit")}
        </Button>
      </form>
    </AuthLayout>
  {/if}
{/if}
