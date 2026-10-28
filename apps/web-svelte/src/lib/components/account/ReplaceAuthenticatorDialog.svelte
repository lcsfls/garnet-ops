<script lang="ts">
  import { createMutation } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import type { StepUp } from "../../step-up.svelte.ts";
  import QrCode from "../QrCode.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import CopyButton from "../ui/CopyButton.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  /** Replaces the authenticator app: password (or a recent sign-in), then scan and confirm a code. */
  let {
    open,
    managed,
    stepUp,
    onClose,
    onReplaced,
  }: {
    open: boolean;
    /** A directory account has no local password; the recent sign-in is the proof (ADR 0020). */
    managed: boolean;
    stepUp: StepUp;
    onClose: () => void;
    onReplaced: () => void;
  } = $props();
  let uri = $state<string | null>(null);
  let error = $state<string | null>(null);

  const reset = () => {
    uri = null;
    error = null;
  };
  const close = () => {
    reset();
    onClose();
  };

  const begin = createMutation(() => ({
    mutationFn: (password: string) =>
      api<{ uri: string }>("/account/totp/begin", { method: "POST", body: managed ? {} : { password } }),
    onSuccess: (result: { uri: string }) => {
      uri = result.uri;
    },
    onError: (e: Error, password: string): void => {
      if (stepUp.handled(e, () => begin.mutate(password))) return;
      error =
        e instanceof ApiError && e.code === "invalid-password"
          ? t("account.authenticator.errorPassword")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : t("errors.generic");
    },
  }));
  const confirm = createMutation(() => ({
    mutationFn: (code: string) => api("/account/totp/confirm", { method: "POST", body: { code } }),
    onSuccess: () => {
      reset();
      onReplaced();
    },
    onError: (e: Error, code: string): void => {
      if (stepUp.handled(e, () => confirm.mutate(code))) return;
      if (e instanceof ApiError && e.code === "no-pending-enrolment") {
        uri = null;
        error = t("account.authenticator.errorExpired");
        return;
      }
      error =
        e instanceof ApiError && e.code === "invalid-code"
          ? t("account.authenticator.errorCode")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : t("errors.generic");
    },
  }));

  function submitPassword(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    begin.mutate(managed ? "" : String(new FormData(event.currentTarget as HTMLFormElement).get("password")));
  }
  function submitCode(event: SubmitEvent) {
    event.preventDefault();
    error = null;
    confirm.mutate(String(new FormData(event.currentTarget as HTMLFormElement).get("code")).replace(/\s+/g, ""));
  }
  const secret = $derived(uri ? (new URL(uri).searchParams.get("secret") ?? "") : "");
</script>

<Dialog
  {open}
  onClose={close}
  title={t("account.authenticator.replaceTitle")}
  description={uri ? t("account.authenticator.scanDescription") : t("account.authenticator.replaceDescription")}
>
  {#if uri}
    <form class="grid gap-5" onsubmit={submitCode}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <div class="flex justify-center">
        <QrCode value={uri} label={t("enroll.qrLabel")} />
      </div>
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
      <DialogFooter>
        <Button variant="outline" onclick={close}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={confirm.isPending}>
          {confirm.isPending ? t("common.loading") : t("account.authenticator.confirm")}
        </Button>
      </DialogFooter>
    </form>
  {:else}
    <form class="grid gap-4" onsubmit={submitPassword}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      {#if managed}
        <p class="text-sm text-muted-foreground">{t("account.authenticator.managedStart")}</p>
      {:else}
        <Field label={t("common.password")} name="password" type="password" required autocomplete="current-password" />
      {/if}
      <DialogFooter>
        <Button variant="outline" onclick={close}>
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={begin.isPending}>
          {begin.isPending ? t("common.loading") : t("account.authenticator.start")}
        </Button>
      </DialogFooter>
    </form>
  {/if}
</Dialog>
