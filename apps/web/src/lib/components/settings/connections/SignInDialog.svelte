<script lang="ts">
  import { ExternalLink, KeyRound, LogIn } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { api } from "../../../api.ts";
  import { t } from "../../../i18n.svelte.ts";
  import { toast } from "../../../toast.svelte.ts";
  import type { AvailableForgeApp, ForgeSignIn } from "../../../types.ts";
  import Alert from "../../ui/Alert.svelte";
  import Button from "../../ui/Button.svelte";
  import CopyButton from "../../ui/CopyButton.svelte";
  import Dialog from "../../ui/Dialog.svelte";
  import DialogFooter from "../../ui/DialogFooter.svelte";
  import { signInProblem } from "./sign-in.ts";

  /**
   * Connect account (ADR 0031): sign in with one of the forges an admin set up, or paste a token instead. GitHub shows a
   * code to confirm on github.com and continues by itself; Gitea and Forgejo open their own sign-in page and come back.
   */
  let {
    apps,
    onClose,
    onUseToken,
  }: { apps: AvailableForgeApp[]; onClose: () => void; onUseToken: () => void } = $props();

  const queryClient = useQueryClient();
  let signInId = $state<string | null>(null);
  let chosen = $state<AvailableForgeApp | null>(null);
  let redirecting = $state(false);

  const forgeName = (a: AvailableForgeApp) => t(`repository.writeAccess.forgeNames.${a.forgeKind}`);
  const hostOf = (address: string) => new URL(address).host;

  const start = createMutation(() => ({
    mutationFn: (target: AvailableForgeApp) =>
      api<{ id: string; flow: "device" | "code"; authorizeUrl?: string }>("/forge-sign-in", {
        method: "POST",
        body: { appId: target.id },
      }),
    onSuccess: (result: { id: string; flow: "device" | "code"; authorizeUrl?: string }) => {
      if (result.flow === "code" && result.authorizeUrl) {
        redirecting = true;
        window.location.assign(result.authorizeUrl);
        return;
      }
      signInId = result.id;
    },
  }));

  const progress = createQuery(() => ({
    queryKey: ["forge-sign-in", signInId],
    queryFn: () => api<ForgeSignIn>(`/forge-sign-in/${signInId}`),
    enabled: signInId !== null,
    refetchInterval: (query: { state: { data?: ForgeSignIn } }) =>
      query.state.data && ["done", "failed"].includes(query.state.data.state) ? false : 2000,
  }));

  // A finished device flow closes the dialog and shows the new connection.
  let finished = false;
  $effect(() => {
    if (progress.data?.state !== "done") return;
    untrack(() => {
      if (finished) return;
      finished = true;
      void queryClient.invalidateQueries({ queryKey: ["forge-connections"] });
      toast.success(t("connections.signIn.connected"));
      onClose();
    });
  });

  async function cancel() {
    if (signInId && progress.data?.state !== "done") {
      await api(`/forge-sign-in/${signInId}`, { method: "DELETE" }).catch(() => undefined);
    }
    onClose();
  }
</script>

<Dialog
  open
  onClose={() => void cancel()}
  title={chosen && signInId ? t("connections.signIn.deviceTitle", { forge: forgeName(chosen) }) : t("connections.add")}
  description={signInId ? undefined : t("connections.description")}
>
  <div class="grid gap-4">
    {#if start.isError}<Alert tone="error">{t("errors.actionFailed")}</Alert>{/if}
    {#if !signInId}
      <ul class="grid gap-2">
        {#each apps as a (a.id)}
          <li>
            <Button
              variant="outline"
              class="h-auto w-full justify-start py-2.5 text-left"
              disabled={start.isPending || redirecting}
              onclick={() => {
                chosen = a;
                start.mutate(a);
              }}
            >
              <LogIn aria-hidden="true" class="size-4" />
              <span class="grid">
                <span>{t("connections.signIn.with", { forge: forgeName(a) })}</span>
                <span class="text-sm font-normal text-muted-foreground">{hostOf(a.webBaseUrl)}</span>
              </span>
            </Button>
          </li>
        {/each}
      </ul>
      {#if redirecting && chosen}
        <p role="status" class="text-sm text-muted-foreground">
          {t("connections.signIn.redirecting", { forge: forgeName(chosen) })}
        </p>
      {/if}
      <div class="flex items-center gap-3 text-sm text-muted-foreground">
        <span class="h-px flex-1 bg-border"></span>{t("connections.signIn.or")}<span class="h-px flex-1 bg-border"></span>
      </div>
      <Button variant="ghost" class="justify-start" onclick={onUseToken}>
        <KeyRound aria-hidden="true" class="size-4" />
        {t("connections.signIn.useToken")}
      </Button>
    {:else if chosen}
      {@const p = progress.data}
      {#if !p || p.state === "starting"}
        <p role="status" class="text-muted-foreground">{t("connections.signIn.starting", { forge: forgeName(chosen) })}</p>
      {:else if p.state === "failed"}
        <Alert tone="error">{signInProblem(p.problem)}</Alert>
      {:else if p.userCode && p.verificationUri}
        <p>{t("connections.signIn.deviceText")}</p>
        <div class="flex flex-wrap items-center gap-3">
          <output
            class="rounded-md border bg-muted/40 px-4 py-2 font-mono text-2xl tracking-[0.15em]"
            data-testid="device-code">{p.userCode}</output
          >
          <CopyButton text={p.userCode} />
        </div>
        <a
          href={p.verificationUri}
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-1.5 font-medium text-primary-text underline underline-offset-4"
        >
          {t("connections.signIn.openPage", { address: hostOf(p.verificationUri) + new URL(p.verificationUri).pathname })}
          <ExternalLink aria-hidden="true" class="size-4" />
        </a>
        <p role="status" class="text-sm text-muted-foreground">{t("connections.signIn.waiting")}</p>
      {/if}
    {/if}
    <DialogFooter>
      <Button variant="outline" onclick={() => void cancel()}>
        {signInId ? t("connections.signIn.cancel") : t("common.cancel")}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
