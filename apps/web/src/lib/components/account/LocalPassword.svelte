<script lang="ts">
  import { createMutation } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Field from "../ui/Field.svelte";

  const MIN_LENGTH = 12;

  type ChangeInput = { currentPassword: string; newPassword: string; revokeOtherSessions: boolean };

  /** The password form of a local account. */
  let { email }: { email: string } = $props();
  const stepUp = new StepUp();
  let form: HTMLFormElement | undefined = $state();
  let revoke = $state(true);
  let error = $state<string | null>(null);
  let mismatch = $state(false);
  const change = createMutation(() => ({
    mutationFn: (body: ChangeInput) =>
      api<{ revokedSessions: number }>("/account/password", { method: "POST", body }),
    onSuccess: (result: { revokedSessions: number }) => {
      toast.success(
        `${t("account.password.done")} ${t("account.password.doneRevoked", { count: result.revokedSessions })}`,
      );
      form?.reset();
    },
    onError: (e: Error, body: ChangeInput): void => {
      // A sign-in older than ten minutes: confirm it is you, then the change runs again.
      if (stepUp.handled(e, () => change.mutate(body))) return;
      if (e instanceof ApiError && e.code === "invalid-password") error = t("account.password.errorCurrent");
      else if (e instanceof ApiError && e.code === "same-password") error = t("account.password.errorSame");
      else if (e instanceof ApiError && e.status === 422) error = t("account.password.errorShort");
      else if (e instanceof ApiError && e.status === 429) error = t("errors.tooManyAttempts");
      else error = t("errors.generic");
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const data = new FormData(event.currentTarget as HTMLFormElement);
    const next = String(data.get("newPassword"));
    error = null;
    mismatch = false;
    if (next !== String(data.get("repeat"))) {
      mismatch = true;
      return;
    }
    change.mutate({
      currentPassword: String(data.get("currentPassword")),
      newPassword: next,
      revokeOtherSessions: revoke,
    });
  }
</script>

<Card>
  <CardHeader title={t("account.password.title")} description={t("account.password.description")} />
  <form bind:this={form} class="grid gap-5 px-5 py-5" onsubmit={submit}>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <!-- Lets a password manager attach the new password to the right account. -->
    <input type="email" name="username" value={email} autocomplete="username" readonly hidden />
    <Field
      label={t("account.password.current")}
      name="currentPassword"
      type="password"
      required
      autocomplete="current-password"
    />
    <Field
      label={t("account.password.new")}
      hint={t("account.password.newHint")}
      name="newPassword"
      type="password"
      required
      minlength={MIN_LENGTH}
      maxlength={256}
      autocomplete="new-password"
    />
    <Field
      label={t("account.password.repeat")}
      name="repeat"
      type="password"
      required
      minlength={MIN_LENGTH}
      maxlength={256}
      autocomplete="new-password"
      error={mismatch ? t("account.password.mismatch") : null}
    />
    <label class="flex items-start gap-2.5">
      <Checkbox class="mt-1" bind:checked={revoke} />
      <span>
        {t("account.password.revoke")}
        <span class="block text-sm text-muted-foreground">{t("account.password.revokeHint")}</span>
      </span>
    </label>
    <div>
      <Button type="submit" disabled={change.isPending}>
        {change.isPending ? t("common.loading") : t("account.password.submit")}
      </Button>
    </div>
  </form>
  <StepUpPrompt {stepUp} {email} />
</Card>
