<script lang="ts">
  import { createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { accountQuery } from "../account.ts";
  import { authClient, authErrorKey, directorySignIn } from "../auth-client.ts";
  import { type MessageKey, t } from "../i18n.svelte.ts";
  import { PASSKEY_FAILURE_KEYS, passkeysSupported, signInWithPasskey } from "../passkeys.ts";
  import Alert from "./ui/Alert.svelte";
  import Button from "./ui/Button.svelte";
  import Dialog from "./ui/Dialog.svelte";
  import DialogFooter from "./ui/DialogFooter.svelte";
  import Field from "./ui/Field.svelte";

  /**
   * "Confirm it is you" before a sensitive action (scheduling an update). It is a real sign-in with password and TOTP,
   * so the API sees a fresh session and the audit log records both steps. Once the password is accepted the old session
   * has ended; closing the dialog before the code is confirmed therefore leads to the sign-in page.
   */
  let {
    open,
    email,
    onConfirmed,
    onClose,
  }: { open: boolean; email: string; onConfirmed: () => void; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  let stage = $state<"password" | "code">("password");
  let error = $state<MessageKey | null>(null);
  let busy = $state(false);
  // A passkey (with user verification) confirms it is you as well as a password and a code.
  const account = createQuery(() => ({ ...accountQuery, enabled: open }));
  const hasPasskey = $derived((account.data?.secondFactor.passkeys.length ?? 0) > 0 && passkeysSupported());
  // A directory account confirms with its directory name and password (ADR 0020).
  const directory = $derived(account.data?.profile.source === "directory");
  const loginName = $derived(account.data?.profile.loginName ?? "");

  async function withPasskey() {
    busy = true;
    error = null;
    try {
      const result = await signInWithPasskey();
      if (!result.ok) {
        if (result.reason !== "cancelled") error = PASSKEY_FAILURE_KEYS[result.reason];
        return;
      }
      stage = "password";
      await queryClient.invalidateQueries();
      onConfirmed();
    } finally {
      busy = false;
    }
  }

  async function close() {
    const signedOut = stage === "code";
    stage = "password";
    error = null;
    onClose();
    if (signedOut) {
      queryClient.clear();
      await goto("/sign-in");
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const code = String(form.get("code") ?? "").replace(/\s+/g, "");
    busy = true;
    error = null;
    try {
      if (stage === "password") {
        const result = directory
          ? await directorySignIn(String(form.get("username") ?? loginName), String(form.get("password")))
          : await authClient.signIn.email({ email, password: String(form.get("password")) });
        if (result.error) {
          error = authErrorKey(result.error);
          return;
        }
        if (!(result.data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) {
          error = "errors.generic";
          return;
        }
        stage = "code";
      }
      const verified = await authClient.twoFactor.verifyTotp({ code });
      if (verified.error) {
        error = authErrorKey(verified.error);
        return;
      }
      stage = "password";
      await queryClient.invalidateQueries();
      onConfirmed();
    } finally {
      busy = false;
    }
  }
</script>

<Dialog {open} onClose={() => void close()} title={t("stepUp.title")} description={t("stepUp.description")}>
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
    {#if stage === "code"}<Alert tone="info">{t("stepUp.passwordAccepted")}</Alert>{/if}
    {#if stage === "password" && directory}
      <Field
        label={t("signIn.username")}
        name="username"
        required
        value={loginName}
        autocomplete="username"
        autocapitalize="off"
        spellcheck={false}
        maxlength={128}
      />
    {/if}
    {#if stage === "password"}
      <Field label={t("common.password")} name="password" type="password" required autocomplete="current-password" />
    {/if}
    <Field
      label={t("twoFactor.code")}
      name="code"
      required
      inputmode="numeric"
      autocomplete="one-time-code"
      pattern={"[0-9 ]{6,7}"}
    />
    <DialogFooter>
      <Button variant="outline" onclick={() => void close()}>{t("common.cancel")}</Button>
      <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("stepUp.confirm")}</Button>
    </DialogFooter>
    {#if hasPasskey && stage === "password"}
      <Button variant="outline" disabled={busy} onclick={() => void withPasskey()}>{t("stepUp.passkey")}</Button>
    {/if}
  </form>
</Dialog>
