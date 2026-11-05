<script lang="ts">
  import { ChevronDown, Circle, CircleCheck, Rocket } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { untrack } from "svelte";
  import { api } from "../api.ts";
  import { cn } from "../cn.ts";
  import { formatNumber } from "../format.ts";
  import { t } from "../i18n.svelte.ts";

  /**
   * "Getting started" for owners and admins, at the foot of the sidebar: the six steps that make GarnetOps useful, each ticked
   * off from what is really there (GET /overview/setup), each leading to the place where it is done. Closed it is one line
   * with the progress; opened it lists the steps. It can be hidden in this browser and shows again only if a step that was done
   * is undone. A done step is steel blue with a check, not green: it is set up, not proven. In the collapsed sidebar only the
   * rocket shows; it opens the sidebar and the list.
   */
  let {
    organizationId,
    collapsed,
    onExpand,
  }: { organizationId: string; collapsed: boolean; onExpand: () => void } = $props();

  type Step = { id: StepId; done: boolean; count?: number; total?: number };
  type StepId = "forge" | "repositories" | "scanOnPush" | "notifications" | "vulnDb" | "ciGate";
  const LINKS: Record<StepId, string> = {
    forge: "/settings?section=accounts",
    repositories: "/repositories?add=1",
    scanOnPush: "/repositories",
    notifications: "/settings?section=notifications",
    vulnDb: "/system",
    ciGate: "/gates?wizard=1",
  };
  const OPEN_KEY = "garnetops.setupOpen";

  const query = createQuery(() => ({
    queryKey: ["overview", "setup"],
    queryFn: () => api<{ steps: Step[]; done: number; total: number }>("/overview/setup"),
    refetchInterval: 60_000,
  }));
  const data = $derived(query.data);
  const storageKey = $derived(`garnetops.setupHidden.${organizationId}`);

  function read(key: string): string | null {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }
  function write(key: string, value: string) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // Not kept: this page view only.
    }
  }
  // Hidden at a number of done steps: if fewer are done later (something was removed), it shows again.
  // Read again whenever the organisation changes (one browser, several organisations).
  const parse = (stored: string | null) => (stored === null ? null : Number(stored));
  // Read at once (no flash of a list that was hidden), and again whenever the organisation changes.
  let hiddenAt = $state<number | null>(untrack(() => parse(read(storageKey))));
  $effect(() => {
    hiddenAt = parse(read(storageKey));
  });
  const hidden = $derived(data !== undefined && hiddenAt !== null && data.done >= hiddenAt);
  let open = $state(read(OPEN_KEY) === "1");
  function setOpen(value: boolean) {
    open = value;
    write(OPEN_KEY, value ? "1" : "0");
  }
  function hide() {
    if (!data) return;
    hiddenAt = data.done;
    write(storageKey, String(data.done));
  }
  const next = $derived(data?.steps.find((s) => !s.done)?.id ?? null);
  const progressText = $derived(
    data ? t("setupChecklist.progress", { done: data.done, total: data.total }) : "",
  );
</script>

{#if data && !hidden}
  <section class="border-t py-2" aria-labelledby="setup-progress-title" data-testid="setup-progress-panel">
    {#if collapsed}
      <button
        type="button"
        class="grid h-9 w-full place-items-center rounded-md text-muted-foreground hover:bg-accent"
        title={`${t("setupChecklist.title")}: ${progressText}`}
        onclick={() => {
          setOpen(true);
          onExpand();
        }}
      >
        <Rocket aria-hidden="true" class="size-4" />
        <span class="sr-only" id="setup-progress-title">{t("setupChecklist.title")}: {progressText}</span>
      </button>
    {:else}
      <button
        type="button"
        class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent"
        aria-expanded={open}
        aria-controls="setup-steps-region"
        onclick={() => setOpen(!open)}
      >
        <Rocket aria-hidden="true" class="size-4 flex-none text-muted-foreground" />
        <span class="min-w-0 flex-1">
          <span class="block font-medium" id="setup-progress-title">{t("setupChecklist.title")}</span>
          <span class="block text-muted-foreground tabular-nums" data-testid="setup-progress">{progressText}</span>
        </span>
        <ChevronDown
          aria-hidden="true"
          class={cn("size-4 flex-none text-muted-foreground motion-safe:transition-transform", open && "rotate-180")}
        />
      </button>
      <progress
        max={data.total}
        value={data.done}
        aria-hidden="true"
        class="mx-2 mt-1 block h-1.5 w-[calc(100%-1rem)] overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info-fill [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info-fill"
      ></progress>
      {#if open}
        <div id="setup-steps-region" class="mt-2 px-1">
          {#if data.done === data.total}
            <p class="px-1 pb-2 text-sm text-muted-foreground">{t("setupChecklist.allDone")}</p>
          {/if}
          <ol class="grid gap-0.5" id="setup-steps" data-testid="setup-steps">
            {#each data.steps as step, i (step.id)}
              <li data-step={step.id} data-done={step.done}>
                <a
                  href={LINKS[step.id]}
                  class={cn(
                    "flex items-start gap-2 rounded-md px-1 py-1.5 text-sm hover:bg-accent",
                    step.id === next ? "font-semibold" : step.done ? "text-muted-foreground" : undefined,
                  )}
                  title={step.done && step.id === "scanOnPush" && step.total !== undefined
                    ? t("setupChecklist.ofRepositories", {
                        count: formatNumber(step.count ?? 0),
                        total: formatNumber(step.total),
                      })
                    : t(`setupChecklist.step.${step.id}.text`)}
                >
                  {#if step.done}
                    <CircleCheck aria-hidden="true" class="mt-0.5 size-4 flex-none text-info" />
                  {:else}
                    <Circle aria-hidden="true" class="mt-0.5 size-4 flex-none text-muted-foreground" />
                  {/if}
                  <span class="min-w-0">
                    <span class="tabular-nums">{i + 1}.</span>
                    {t(`setupChecklist.step.${step.id}.title`)}
                    <span class="sr-only">, {step.done ? t("setupChecklist.doneLabel") : t("setupChecklist.openLabel")}</span>
                  </span>
                </a>
              </li>
            {/each}
          </ol>
          <button type="button" class="link mt-1 px-1 text-sm text-muted-foreground" onclick={hide}>
            {t("setupChecklist.hide")}
          </button>
        </div>
      {/if}
    {/if}
  </section>
{/if}
