<script lang="ts">
  import { goto } from "$app/navigation";
  import { ApiError, api } from "#lib/api.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { queryClient } from "#lib/query.ts";

  let error = $state<MessageKey | null>(null);
  let alreadyDone = $state(false);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    busy = true;
    error = null;
    try {
      await api("/setup", {
        method: "POST",
        body: {
          token: String(form.get("token")).trim(),
          organizationName: String(form.get("organizationName")),
          name: String(form.get("name")),
          email: String(form.get("email")),
          password: String(form.get("password")),
          // Nightly scans run at 04:00 in the owner's zone; changeable later.
          timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        },
      });
      await queryClient.invalidateQueries();
      await goto("/sign-in?setup=done");
    } catch (e) {
      if (e instanceof ApiError && e.code === "invalid-setup-token") error = "setup.invalidToken";
      else if (e instanceof ApiError && e.code === "already-set-up") alreadyDone = true;
      else error = e instanceof ApiError ? "errors.generic" : "errors.network";
    } finally {
      busy = false;
    }
  }
</script>

{#if alreadyDone}
  <AuthLayout title={t("setup.title")}>
    <div class="grid gap-4">
      <Alert tone="info">{t("setup.alreadyDone")}</Alert>
      <a href="/sign-in" class="font-medium text-primary-text underline-offset-4 hover:underline">{t("signIn.title")}</a>
    </div>
  </AuthLayout>
{:else}
  <AuthLayout title={t("setup.title")} description={t("setup.description")}>
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      <Field
        label={t("setup.token")}
        hint={t("setup.tokenHint")}
        name="token"
        required
        autocomplete="off"
        spellcheck={false}
        class="font-mono"
      />
      <Field label={t("setup.organization")} name="organizationName" required minlength={2} maxlength={100} />
      <Field label={t("common.name")} name="name" required autocomplete="name" maxlength={100} />
      <Field label={t("common.email")} name="email" type="email" required autocomplete="email" />
      <Field
        label={t("common.password")}
        hint={t("errors.passwordTooShort")}
        name="password"
        type="password"
        required
        minlength={12}
        maxlength={256}
        autocomplete="new-password"
      />
      <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("setup.submit")}</Button>
    </form>
  </AuthLayout>
{/if}
