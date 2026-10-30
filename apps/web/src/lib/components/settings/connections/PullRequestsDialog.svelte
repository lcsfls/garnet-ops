<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import { formatDateTime } from "../../../format.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { StepUp } from "../../../step-up.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { AvailableForgeApp, ForgeConnection } from "../../../types.ts";
  import StepUpPrompt from "../../StepUpPrompt.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import Checkbox from "../../ui/Checkbox.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";

  /**
   * Fix pull requests in the owner's name through one connected account (ADR 0039). Switching on says what the token will
   * be used for and asks for an explicit acknowledgement; the API wants a recent sign-in. A Gitea or Forgejo sign-in made
   * with read access only signs in again with write access first. Switching off is one click. Mounted fresh each time.
   */
  let {
    connection: c,
    apps,
    email,
    onClose,
  }: {
    connection: ForgeConnection;
    apps: AvailableForgeApp[];
    email: string;
    onClose: () => void;
  } = $props();

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let acknowledged = $state(false);
  let error = $state<string | null>(null);
  let redirecting = $state(false);

  const account = $derived(c.accountLogin ?? new URL(c.webBaseUrl).host);
  const forgeName = $derived(t(`repository.writeAccess.forgeNames.${c.forgeKind}`));
  // The sign-in application of this forge, for signing in again with write access.
  const app = $derived(apps.find((a) => a.webBaseUrl === c.webBaseUrl && a.flow === "code") ?? null);

  async function done(message: string) {
    await queryClient.invalidateQueries({ queryKey: ["forge-connections"] });
    await queryClient.invalidateQueries({ queryKey: ["fixes"] });
    toast.success(message);
    onClose();
  }
  function fail(e: Error, again: () => void) {
    if (stepUp.handled(e, again)) return;
    if (e instanceof ApiError && e.code === "acknowledgement-required")
      error = t("connections.pullRequests.needsAcknowledgement");
    else if (e instanceof ApiError && e.code === "write-sign-in-required")
      error = t("connections.pullRequests.writeSignInText", { forge: forgeName });
    else if (e instanceof ApiError && e.status === 429) error = t("errors.tooManyAttempts");
    else error = t("errors.actionFailed");
  }

  const enable = createMutation(() => ({
    mutationFn: () =>
      api(`/forge-connections/${c.id}/pull-requests`, {
        method: "PUT",
        body: { enabled: true, acknowledged },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => done(t("connections.pullRequests.switchedOn")),
    onError: (e: Error) => fail(e, () => enable.mutate()),
  }));
  const disable = createMutation(() => ({
    mutationFn: () =>
      api(`/forge-connections/${c.id}/pull-requests`, { method: "PUT", body: { enabled: false } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => done(t("connections.pullRequests.switchedOff")),
    onError: (e: Error) => fail(e, () => disable.mutate()),
  }));
  // Gitea and Forgejo: the forge's own sign-in page, asking for write:repository this time; it comes back to the callback.
  const signInWithWrite = createMutation(() => ({
    mutationFn: (appId: string) =>
      api<{ id: string; authorizeUrl?: string }>("/forge-sign-in", {
        method: "POST",
        body: { appId, write: true },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: (result: { id: string; authorizeUrl?: string }) => {
      if (!result.authorizeUrl) {
        error = t("errors.actionFailed");
        return;
      }
      redirecting = true;
      window.location.assign(result.authorizeUrl);
    },
    onError: (e: Error) => fail(e, () => undefined),
  }));
</script>

<Dialog
  open
  {onClose}
  title={t("connections.pullRequests.title", { account })}
  description={t("connections.pullRequests.description")}
>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}

    <section class="grid gap-2" aria-labelledby="pr-uses">
      <h3 id="pr-uses" class="font-medium">{t("connections.pullRequests.usesTitle")}</h3>
      <ul class="grid list-disc gap-1 pl-5 text-sm">
        <li>{t("connections.pullRequests.usesBranch")}</li>
        <li>{t("connections.pullRequests.usesCommit")}</li>
        <li>{t("connections.pullRequests.usesPullRequest")}</li>
      </ul>
      <p class="text-sm text-muted-foreground">{t("connections.pullRequests.never")}</p>
      {#if c.authMethod === "sign-in" && c.forgeKind === "github"}
        <p class="text-sm text-muted-foreground">{t("connections.pullRequests.githubHint")}</p>
      {:else if c.authMethod === "token"}
        <p class="text-sm text-muted-foreground">{t("connections.pullRequests.tokenHint")}</p>
      {/if}
    </section>

    {#if c.pullRequests}
      {#if c.pullRequestsAt}
        <p class="text-sm text-muted-foreground">
          {t("connections.pullRequests.onSince", { when: formatDateTime(c.pullRequestsAt) })}
        </p>
      {/if}
    {:else if c.needsWriteSignIn}
      <section class="grid gap-2 rounded-md border p-3" aria-labelledby="pr-write">
        <h3 id="pr-write" class="font-medium">{t("connections.pullRequests.writeSignInTitle")}</h3>
        <p class="text-sm">{t("connections.pullRequests.writeSignInText", { forge: forgeName })}</p>
        {#if app}
          <div>
            <Button
              variant="outline"
              disabled={signInWithWrite.isPending || redirecting}
              onclick={() => signInWithWrite.mutate(app.id)}
            >
              {t("connections.pullRequests.writeSignIn")}
            </Button>
          </div>
          {#if redirecting}
            <p role="status" class="text-sm text-muted-foreground">
              {t("connections.signIn.redirecting", { forge: forgeName })}
            </p>
          {/if}
        {:else}
          <Alert tone="info">{t("connections.pullRequests.noApp")}</Alert>
        {/if}
      </section>
    {:else}
      <label class="flex items-start gap-2.5 rounded-md border p-3">
        <Checkbox class="mt-1" bind:checked={acknowledged} />
        <span>
          <b class="font-medium">{t("connections.pullRequests.acknowledge", { account })}</b>
          <span class="block text-sm text-muted-foreground">{t("connections.pullRequests.acknowledgeHint")}</span>
        </span>
      </label>
    {/if}

    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.close")}</Button>
      {#if c.pullRequests}
        <Button variant="destructive" disabled={disable.isPending} onclick={() => disable.mutate()}>
          {t("connections.pullRequests.turnOff")}
        </Button>
      {:else if !c.needsWriteSignIn}
        <Button disabled={!acknowledged || enable.isPending} onclick={() => enable.mutate()}>
          {enable.isPending ? t("common.loading") : t("connections.pullRequests.turnOn")}
        </Button>
      {/if}
    </DialogFooter>
  </div>
</Dialog>
<StepUpPrompt {stepUp} {email} />
