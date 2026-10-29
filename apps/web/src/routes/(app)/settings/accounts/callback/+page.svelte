<script lang="ts">
  import { createQuery } from "@tanstack/svelte-query";
  import { onMount, untrack } from "svelte";
  import { ApiError, api } from "#lib/api.ts";
  import Card from "#lib/components/Card.svelte";
  import CardHeader from "#lib/components/CardHeader.svelte";
  import { signInProblem } from "#lib/components/settings/connections/sign-in.ts";
  import Alert from "#lib/components/ui/Alert.svelte";
  import { t } from "#lib/i18n.svelte.ts";
  import { toast } from "#lib/toast.svelte.ts";
  import type { ForgeSignIn } from "#lib/types.ts";
  import { href } from "#lib/url.ts";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  /**
   * Where Gitea and Forgejo send the browser back after signing in (ADR 0031). The code and state leave the address at
   * once (history and logs keep nothing); the API checks the state and the worker exchanges the code, then this page
   * returns to the connected accounts.
   */
  let signInId = $state<string | null>(null);
  let problem = $state<string | null>(null);

  onMount(() => {
    const params = page.url.searchParams;
    const state = params.get("state") ?? "";
    const code = params.get("code") ?? undefined;
    const error = params.get("error") ?? undefined;
    history.replaceState(history.state, "", page.url.pathname);
    api<{ id: string }>("/forge-sign-in/callback", { method: "POST", body: { state, code, error } })
      .then((r) => {
        signInId = r.id;
      })
      .catch((e: Error) => {
        problem = e instanceof ApiError && (e.status === 409 || e.status === 422) ? "unknown" : "unexpected";
      });
  });

  const progress = createQuery(() => ({
    queryKey: ["forge-sign-in", signInId],
    queryFn: () => api<ForgeSignIn>(`/forge-sign-in/${signInId}`),
    enabled: signInId !== null,
    refetchInterval: (query: { state: { data?: ForgeSignIn } }) =>
      query.state.data && ["done", "failed"].includes(query.state.data.state) ? false : 1500,
  }));

  // Once, and outside the effect's dependencies: the toast store and the navigation must not run it again.
  let finished = false;
  $effect(() => {
    const state = progress.data?.state;
    const failure = progress.data?.problem ?? "denied";
    untrack(() => {
      if (finished || (state !== "done" && state !== "failed")) return;
      finished = true;
      if (state === "failed") {
        problem = failure;
        return;
      }
      toast.success(t("connections.signIn.connected"));
      void goto(href("/settings", { section: "accounts" }), { replaceState: true });
    });
  });
</script>

<div class="mx-auto max-w-[46rem]">
  <Card>
    <CardHeader title={t("connections.signIn.callbackTitle")} />
    <div class="grid gap-3 px-5 pb-5">
      {#if problem}
        <Alert tone="error">{signInProblem(problem)}</Alert>
      {:else}
        <p role="status" class="text-muted-foreground">{t("connections.signIn.callbackWorking")}</p>
      {/if}
      <a
        href={href("/settings", { section: "accounts" })}
        class="text-sm font-medium text-primary-text underline underline-offset-4"
      >
        {t("connections.signIn.back")}
      </a>
    </div>
  </Card>
</div>
