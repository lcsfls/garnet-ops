<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { authClient, authErrorKey, directoryMe } from "#lib/auth-client.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import QrCode from "#lib/components/QrCode.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Checkbox from "#lib/components/ui/Checkbox.svelte";
  import CopyButton from "#lib/components/ui/CopyButton.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { queryClient } from "#lib/query.ts";
  import { signOutAndLeave } from "#lib/session-end.ts";

  type Step =
    | { kind: "password" }
    | { kind: "scan"; uri: string; backupCodes: string[] }
    | { kind: "backup"; backupCodes: string[] };

  let step = $state<Step>({ kind: "password" });
  // A directory account has no local password to ask for (ADR 0020).
  const account = createQuery(() => ({
    queryKey: ["directory-me"],
    queryFn: async () => (await directoryMe()).data?.managed === true,
  }));
  const managed = $derived(account.data === true);
  let error = $state<MessageKey | null>(null);
  let busy = $state(false);
  let saved = $state(false);

  const signOut = () => signOutAndLeave(() => authClient.signOut());

  async function start(event: SubmitEvent) {
    event.preventDefault();
    const password = managed ? "" : String(new FormData(event.currentTarget as HTMLFormElement).get("password"));
    busy = true;
    error = null;
    const result = await authClient.twoFactor.enable({ password });
    busy = false;
    if (result.error || result.data?.method !== "totp") {
      error = authErrorKey(result.error);
      return;
    }
    step = { kind: "scan", uri: result.data.totpURI, backupCodes: result.data.backupCodes };
  }

  async function confirm(event: SubmitEvent, backupCodes: string[]) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget as HTMLFormElement).get("code")).replace(/\s+/g, "");
    busy = true;
    error = null;
    const result = await authClient.twoFactor.verifyTotp({ code });
    busy = false;
    if (result.error) {
      error = authErrorKey(result.error);
      return;
    }
    step = { kind: "backup", backupCodes };
  }

  async function finish() {
    await queryClient.invalidateQueries();
    await goto("/");
  }
</script>

{#snippet footer()}
  <Button variant="link" onclick={signOut}>{t("common.signOut")}</Button>
{/snippet}

{#if step.kind === "password"}
  <AuthLayout
    title={t("enroll.title")}
    description={managed ? t("enroll.descriptionDirectory") : t("enroll.description")}
    {footer}
  >
    <form class="grid gap-4" onsubmit={start}>
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      {#if !managed}
        <Field label={t("common.password")} name="password" type="password" required autocomplete="current-password" />
      {/if}
      <Button type="submit" disabled={busy || account.isLoading}>{busy ? t("common.loading") : t("enroll.start")}</Button>
    </form>
  </AuthLayout>
{:else if step.kind === "scan"}
  {@const scan = step}
  {@const secret = new URL(scan.uri).searchParams.get("secret") ?? ""}
  <AuthLayout title={t("enroll.scanTitle")} description={t("enroll.scanDescription")} {footer}>
    <form class="grid gap-5" onsubmit={(e) => confirm(e, scan.backupCodes)}>
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      <div class="flex justify-center"><QrCode value={scan.uri} label={t("enroll.qrLabel")} /></div>
      <div class="grid gap-1.5">
        <span class="text-sm font-medium">{t("enroll.manualKey")}</span>
        <div class="flex items-center gap-2">
          <code class="min-w-0 flex-1 rounded-md bg-muted px-3 py-2 font-mono text-sm break-all"
            >{secret.replace(/(.{4})/g, "$1 ").trim()}</code
          >
          <CopyButton text={secret} />
        </div>
      </div>
      <Field
        label={t("twoFactor.code")}
        name="code"
        required
        inputmode="numeric"
        autocomplete="one-time-code"
        pattern={"[0-9 ]{6,7}"}
        maxlength={7}
        class="font-mono tracking-widest"
      />
      <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("enroll.confirm")}</Button>
    </form>
  </AuthLayout>
{:else}
  <AuthLayout title={t("enroll.backupTitle")} description={t("enroll.backupDescription")}>
    <div class="grid gap-5">
      <ul class="grid grid-cols-2 gap-2 rounded-md bg-muted p-4 font-mono text-sm">
        {#each step.backupCodes as code (code)}<li>{code}</li>{/each}
      </ul>
      <div class="flex justify-end"><CopyButton text={step.backupCodes.join("\n")} /></div>
      <label class="flex items-start gap-2.5 text-sm">
        <Checkbox class="mt-0.5" bind:checked={saved} />
        {t("enroll.backupConfirm")}
      </label>
      <Button disabled={!saved} onclick={finish}>{t("enroll.finish")}</Button>
    </div>
  </AuthLayout>
{/if}
