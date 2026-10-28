<script lang="ts">
  import { DIRECTORY_LIMITS } from "@garnetops/core/directory";
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../../api.ts";
  import type { DirectoryView, TestView } from "../../../directory.ts";
  import { hasKey, t } from "../../../i18n.svelte.ts";
  import Card from "../../Card.svelte";
  import CardHeader from "../../CardHeader.svelte";
  import Alert from "../../ui/Alert.svelte";
  import Badge from "../../ui/Badge.svelte";
  import Button from "../../ui/Button.svelte";
  import Field from "../../ui/Field.svelte";

  let { view }: { view: DirectoryView } = $props();

  const queryClient = useQueryClient();

  function problemText(problem: string | undefined, detail?: string) {
    if (!problem) return "";
    const key = `directory.problem.${problem}`;
    const text = hasKey(key) ? t(key as never) : t("directory.problem.internal");
    return detail ? `${text} (${detail})` : text;
  }

  let username = $state("");
  let error = $state<string | null>(null);
  const run = createMutation(() => ({
    mutationFn: (name: string) =>
      api<{ result: TestView }>("/directory/test", { method: "POST", body: name ? { username: name } : {} }),
    onMutate: () => {
      error = null;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["directory"] }),
    onError: (e: Error) => {
      error =
        e instanceof ApiError && e.status === 429
          ? t("errors.tooManyAttempts")
          : e instanceof ApiError && e.status === 422
            ? t("directory.fieldError.username_invalid")
            : t("errors.actionFailed");
    },
  }));
  const result = $derived(run.data?.result ?? null);

  function submit(event: SubmitEvent) {
    event.preventDefault();
    run.mutate(username.trim());
  }
</script>

<Card>
  <CardHeader title={t("directory.testTitle")} description={t("directory.testDescription")} />
  <form class="grid gap-4 px-5 pb-5" onsubmit={submit} novalidate>
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <Field
      id="directory-test-user"
      label={t("directory.testUser")}
      hint={t("directory.testUserHint")}
      bind:value={username}
      maxlength={DIRECTORY_LIMITS.usernameMax}
      autocapitalize="off"
      autocomplete="off"
      spellcheck={false}
      class="max-w-96"
    />
    <div>
      <Button type="submit" variant="outline" disabled={run.isPending} data-testid="directory-test">
        {run.isPending ? t("directory.testing") : t("directory.testRun")}
      </Button>
    </div>
    {#if view.settings?.enabled === false}
      <p class="text-sm text-muted-foreground">{t("directory.testSaved")}</p>
    {/if}
    {#if result}
      <div class="grid gap-4" data-testid="directory-test-result" aria-live="polite">
        <div class="flex flex-wrap items-center gap-2">
          <Badge tone={result.ok ? "neutral" : "critical"}>
            {result.ok ? t("directory.testOk") : t("directory.testFailed")}
          </Badge>
          {#if !result.ok && result.problem}
            <span class="text-sm text-destructive-text">{problemText(result.problem)}</span>
          {/if}
          <span class="ml-auto text-sm text-muted-foreground">
            {t("directory.testLatency", { ms: result.latencyMs })}
          </span>
        </div>
        <ul class="grid gap-1.5">
          {#each result.servers as s (s.url)}
            <li class="flex flex-wrap items-center gap-2 text-sm">
              <span class="font-mono break-all">{s.url}</span>
              <Badge tone="neutral">{t(`directory.transport.${s.transport}`)}</Badge>
              <Badge tone={s.ok ? "neutral" : "critical"}>
                {s.ok ? t("directory.serverOk") : t("directory.serverFailed")}
              </Badge>
              {#if !s.ok}
                <span class="text-destructive-text">{problemText(s.problem, s.detail)}</span>
              {/if}
            </li>
          {/each}
        </ul>
        {#if result.user}
          <section aria-label={t("directory.testPerson")} class="grid gap-2 rounded-md border px-3 py-3">
            <h3 class="text-sm font-medium">{t("directory.testPerson")}</h3>
            <dl class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              <dt class="text-muted-foreground">{t("directory.testDn")}</dt>
              <dd class="font-mono break-all">{result.user.dn}</dd>
              <dt class="text-muted-foreground">{t("directory.testName")}</dt>
              <dd>{result.user.name ?? "–"}</dd>
              <dt class="text-muted-foreground">{t("directory.testEmail")}</dt>
              <dd class="break-all">{result.user.email ?? t("directory.testNoEmail")}</dd>
              <dt class="text-muted-foreground">{t("directory.testUniqueId")}</dt>
              <dd class="font-mono break-all">{result.user.uniqueId}</dd>
              <dt class="text-muted-foreground">{t("directory.testGroups")}</dt>
              <dd class="font-mono break-all">
                {result.user.groups.length > 0 ? result.user.groups.join("; ") : t("directory.testNoGroups")}
              </dd>
              <dt class="text-muted-foreground">{t("directory.testRole")}</dt>
              <dd>
                {#if result.user.role}
                  <Badge tone="neutral">{t(`team.roles.${result.user.role}`)}</Badge>
                {:else}
                  <span class="text-destructive-text">{t("directory.testNoRole")}</span>
                {/if}
              </dd>
            </dl>
            {#if !result.user.email}<Alert tone="error">{t("directory.testNoEmailWarning")}</Alert>{/if}
          </section>
        {/if}
        {#if result.groups && result.groups.length > 0}
          <section aria-label={t("directory.testGroupsTitle")} class="grid gap-1.5">
            <h3 class="text-sm font-medium">{t("directory.testGroupsTitle")}</h3>
            <ul class="grid gap-1 text-sm">
              {#each result.groups as g (g.dn)}
                <li class="flex flex-wrap items-center gap-2">
                  <span class="font-mono break-all">{g.dn}</span>
                  <Badge tone={g.exists ? "neutral" : "medium"}>
                    {g.exists ? t("directory.groupExists") : t("directory.groupMissing")}
                  </Badge>
                  {#if result.user && g.exists}
                    <Badge tone="neutral">
                      {g.member ? t("directory.groupMember") : t("directory.groupNotMember")}
                    </Badge>
                  {/if}
                </li>
              {/each}
            </ul>
          </section>
        {/if}
      </div>
    {/if}
  </form>
</Card>
