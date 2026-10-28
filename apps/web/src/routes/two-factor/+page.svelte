<script lang="ts">
  import { authClient, authErrorKey } from "#lib/auth-client.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { PASSKEY_FAILURE_KEYS, passkeysSupported, signInWithPasskey } from "#lib/passkeys.ts";
  import { queryClient } from "#lib/query.ts";
  import { goto } from "$app/navigation";

  /** Second step of sign-in. Only reachable while signed out; the pending sign-in lives in a short-lived cookie. */
  let mode = $state<"totp" | "backup">("totp");
  let error = $state<MessageKey | null>(null);
  let busy = $state(false);

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget as HTMLFormElement).get("code")).replace(/\s+/g, "");
    busy = true;
    error = null;
    const result =
      mode === "totp"
        ? await authClient.twoFactor.verifyTotp({ code })
        : await authClient.twoFactor.verifyBackupCode({ code });
    busy = false;
    if (result.error) {
      error = authErrorKey(result.error);
      return;
    }
    await queryClient.invalidateQueries();
    await goto("/");
  }

  /** A passkey is a second factor on its own (user verification is required), so it completes the sign-in. */
  async function withPasskey() {
    busy = true;
    error = null;
    const result = await signInWithPasskey();
    busy = false;
    if (!result.ok) {
      if (result.reason !== "cancelled") error = PASSKEY_FAILURE_KEYS[result.reason];
      return;
    }
    await queryClient.invalidateQueries();
    await goto("/");
  }
</script>

<AuthLayout
  title={t("twoFactor.title")}
  description={mode === "totp" ? t("twoFactor.description") : t("twoFactor.backupDescription")}
>
  {#key mode}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      {#if mode === "totp"}
        <!-- svelte-ignore a11y_autofocus -->
        <Field
          label={t("twoFactor.code")}
          name="code"
          required
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern={"[0-9 ]{6,7}"}
          maxlength={7}
          autofocus
          class="font-mono tracking-widest"
        />
      {:else}
        <!-- svelte-ignore a11y_autofocus -->
        <Field
          label={t("twoFactor.backupCode")}
          name="code"
          required
          autocomplete="off"
          spellcheck={false}
          maxlength={64}
          autofocus
          class="font-mono"
        />
      {/if}
      <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("twoFactor.submit")}</Button>
      <Button
        variant="link"
        onclick={() => {
          error = null;
          mode = mode === "totp" ? "backup" : "totp";
        }}
      >
        {mode === "totp" ? t("twoFactor.useBackupCode") : t("twoFactor.useAuthenticator")}
      </Button>
      {#if passkeysSupported()}
        <Button variant="link" disabled={busy} onclick={() => void withPasskey()}>{t("twoFactor.usePasskey")}</Button>
      {/if}
    </form>
  {/key}
  {#snippet footer()}
    <a href="/sign-in" class="underline-offset-4 hover:underline">{t("common.back")}</a>
  {/snippet}
</AuthLayout>
