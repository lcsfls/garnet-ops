<script lang="ts">
  import { ArrowRight, Circle, CircleCheck, X } from "@lucide/svelte";
  import { createQuery } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { cn } from "../../cn.ts";
  import { formatNumber } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import Card from "../Card.svelte";
  import Button from "../ui/Button.svelte";

  /**
   * "Getting started" for owners and admins: the six steps that make GarnetOps useful, each ticked off from what is really there
   * (GET /overview/setup), each leading to the place where it is done. It can be hidden in this browser; it shows again only if
   * a step that was done is undone. A done step is shown in steel blue with a check, not green: it is set up, not proven.
   */
  let { organizationId }: { organizationId: string } = $props();

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

  const query = createQuery(() => ({
    queryKey: ["overview", "setup"],
    queryFn: () => api<{ steps: Step[]; done: number; total: number }>("/overview/setup"),
    refetchInterval: 60_000,
  }));
  const data = $derived(query.data);
  const storageKey = $derived(`garnetops.setupHidden.${organizationId}`);

  function readHidden(): number | null {
    try {
      const v = localStorage.getItem(storageKey);
      return v === null ? null : Number(v);
    } catch {
      return null;
    }
  }
  // Hidden at a number of done steps: if fewer are done later (something was removed), it shows again.
  let hiddenAt = $state<number | null>(readHidden());
  const hidden = $derived(data !== undefined && hiddenAt !== null && data.done >= hiddenAt);
  function hide() {
    if (!data) return;
    hiddenAt = data.done;
    try {
      localStorage.setItem(storageKey, String(data.done));
    } catch {
      // Not kept: hidden for this page view only.
    }
  }
  const percent = $derived(data ? Math.round((data.done / data.total) * 100) : 0);
  const next = $derived(data?.steps.find((s) => !s.done)?.id ?? null);
</script>

{#if data && !hidden}
  <Card class="mb-4" id="setup-checklist">
    <div class="flex flex-wrap items-start gap-4 px-5 pt-5">
      <div class="min-w-0 flex-1">
        <h2 class="text-lg font-semibold">{t("setupChecklist.title")}</h2>
        <p class="text-sm text-muted-foreground">
          {data.done === data.total ? t("setupChecklist.allDone") : t("setupChecklist.description")}
        </p>
      </div>
      <Button variant="ghost" class="h-9 px-2" onclick={hide} title={t("setupChecklist.hide")}>
        <X aria-hidden="true" class="size-4" />
        <span class="sr-only">{t("setupChecklist.hide")}</span>
      </Button>
    </div>
    <div class="px-5 pt-3">
      <div class="flex items-center gap-3">
        <progress
          max={data.total}
          value={data.done}
          aria-label={t("setupChecklist.progress", { done: data.done, total: data.total })}
          class="h-2 flex-1 overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info-fill [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info-fill"
        ></progress>
        <span class="text-sm whitespace-nowrap tabular-nums" data-testid="setup-progress">
          {t("setupChecklist.progress", { done: data.done, total: data.total })} · {percent} %
        </span>
      </div>
    </div>
    <ol class="mt-3 grid border-t @3xl:grid-cols-2 @wide:grid-cols-3" data-testid="setup-steps">
      {#each data.steps as step, i (step.id)}
        <li
          class={cn("flex items-start gap-3 border-b px-5 py-3 @3xl:odd:border-r @wide:border-r", step.id === next && "bg-surface-2")}
          data-step={step.id}
          data-done={step.done}
        >
          {#if step.done}
            <CircleCheck aria-hidden="true" class="mt-0.5 size-5 flex-none text-info" />
          {:else}
            <Circle aria-hidden="true" class="mt-0.5 size-5 flex-none text-muted-foreground" />
          {/if}
          <div class="min-w-0 flex-1">
            <p class="font-medium">
              <span class="text-muted-foreground tabular-nums">{i + 1}.</span>
              {t(`setupChecklist.step.${step.id}.title`)}
              <span class="sr-only">
                , {step.done ? t("setupChecklist.doneLabel") : t("setupChecklist.openLabel")}
              </span>
            </p>
            <p class="text-sm text-muted-foreground">
              {#if step.done && step.id === "scanOnPush" && step.total !== undefined}
                {t("setupChecklist.ofRepositories", {
                  count: formatNumber(step.count ?? 0),
                  total: formatNumber(step.total),
                })}
              {:else}
                {t(`setupChecklist.step.${step.id}.text`)}
              {/if}
            </p>
            {#if !step.done || step.id === "scanOnPush"}
              <a
                href={LINKS[step.id]}
                class={cn(
                  "link mt-1 inline-flex items-center gap-1 text-sm",
                  step.id === next ? "font-semibold" : "font-medium",
                )}
              >
                {step.done ? t("setupChecklist.more") : t(`setupChecklist.step.${step.id}.action`)}
                <ArrowRight aria-hidden="true" class="size-3.5" />
              </a>
            {/if}
          </div>
        </li>
      {/each}
    </ol>
  </Card>
{/if}
