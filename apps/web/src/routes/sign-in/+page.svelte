<script lang="ts">
  import { Fingerprint } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { authClient, authErrorKey, directorySignIn } from "#lib/auth-client.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { signInOptionsQuery } from "#lib/directory.ts";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { PASSKEY_FAILURE_KEYS, passkeysSupported, signInWithPasskey } from "#lib/passkeys.ts";
  import { queryClient } from "#lib/query.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  const setup = $derived(page.url.searchParams.get("setup") === "done");
  const ended = $derived(page.url.searchParams.get("ended") === "1");
  const via = $derived(page.url.searchParams.get("via"));
  const options = createQuery(() => signInOptionsQuery);
  // A deep link to the directory form only counts while the directory sign-in is switched on.
  const directory = $derived(options.data?.directory === true);
  const mode: "local" | "directory" = $derived(directory && via === "directory" ? "directory" : "local");
  let error = $state<MessageKey | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    busy = true;
    error = null;
    const result =
      mode === "directory"
        ? await directorySignIn(String(form.get("username")), String(form.get("password")))
        : await authClient.signIn.email({
            email: String(form.get("email")),
            password: String(form.get("password")),
          });
    busy = false;
    if (result.error) {
      error = authErrorKey(result.error);
      return;
    }
    const data = result.data as { twoFactorRedirect?: boolean } | null;
    if (data?.twoFactorRedirect) return goto("/two-factor");
    // No second factor yet: the guards send the user on to enrolment.
    await queryClient.invalidateQueries();
    await goto("/");
  }

  async function withPasskey() {
    busy = true;
    error = null;
    const result = await signInWithPasskey();
    busy = false;
    if (!result.ok) {
      // Closing the prompt is a choice, not an error.
      if (result.reason !== "cancelled") error = PASSKEY_FAILURE_KEYS[result.reason];
      return;
    }
    await queryClient.invalidateQueries();
    await goto("/");
  }
</script>

<AuthLayout title={t("signIn.title")} description={t("signIn.description")}>
  {#if directory}
    <fieldset class="mb-4 grid min-w-0 grid-cols-2 gap-1 rounded-lg border-0 bg-muted p-1">
      <legend class="sr-only">{t("signIn.modeLabel")}</legend>
      {#each ["local", "directory"] as const as m (m)}
        <button
          type="button"
          aria-pressed={mode === m}
          onclick={() => void goto(m === "directory" ? "/sign-in?via=directory" : "/sign-in")}
          class="grid h-9 place-items-center rounded-md text-center text-sm font-medium {mode === m
            ? 'bg-card shadow-xs'
            : 'text-muted-foreground hover:text-foreground'}"
        >
          {t(m === "directory" ? "signIn.modeDirectory" : "signIn.modeLocal")}
        </button>
      {/each}
    </fieldset>
  {/if}
  {#key mode}
    <form class="grid gap-4" onsubmit={submit}>
      {#if setup}<Alert tone="info">{t("setup.done")}</Alert>{/if}
      {#if ended && !error}<Alert tone="info">{t("errors.sessionExpired")}</Alert>{/if}
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      {#if mode === "directory"}
        <Field
          label={t("signIn.username")}
          hint={t("signIn.usernameHint")}
          name="username"
          required
          autocomplete="username"
          autocapitalize="off"
          spellcheck={false}
          maxlength={128}
        />
        <Field
          label={t("common.password")}
          name="password"
          type="password"
          required
          autocomplete="current-password"
          maxlength={512}
        />
        <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("signIn.submitDirectory")}</Button>
      {:else}
        <Field label={t("common.email")} name="email" type="email" required autocomplete="username" />
        <Field label={t("common.password")} name="password" type="password" required autocomplete="current-password" />
        <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("signIn.submit")}</Button>
      {/if}
    </form>
  {/key}
  {#if passkeysSupported()}
    <div class="mt-5 grid gap-3 border-t pt-5">
      <Button variant="outline" disabled={busy} onclick={() => void withPasskey()}>
        <Fingerprint aria-hidden="true" class="size-4" />
        {t("signIn.passkey")}
      </Button>
      <p class="text-center text-sm text-muted-foreground">{t("signIn.passkeyHint")}</p>
    </div>
  {/if}
</AuthLayout>
