<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { goto } from "$app/navigation";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import { href } from "../../url.ts";
  import Segmented from "../Segmented.svelte";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import TextAreaField from "../ui/TextAreaField.svelte";

  /** The codes the API gives for a value it refused, each with its sentence. */
  const ADD_PROBLEMS = [
    "empty",
    "tooLong",
    "url",
    "wildcard",
    "characters",
    "label",
    "singleLabel",
    "numericTld",
    "reservedName",
    "notPublic",
  ] as const;
  const isAddProblem = (code: string): code is (typeof ADD_PROBLEMS)[number] =>
    (ADD_PROBLEMS as readonly string[]).includes(code);
  /** At most this many lines: the per-organisation limit of the API. */
  const MAX_LINES = 200;

  /** One line of a checked list, as the API answers a dry run. */
  type ListItem =
    | {
        line: number;
        input: string;
        ok: true;
        value: string;
        coveredBy: { id: string; value: string } | null;
      }
    | { line: number; input: string; ok: false; problem: string; firstLine?: number };

  /**
   * Adds a domain, host name or public address (ADR 0023), or a pasted list of them (subdomains behind a wildcard certificate,
   * which Certificate Transparency cannot show). Nothing is looked at from outside until it exists, and only stage 1. A single
   * website then opens with its proof of control to set up; a list is checked line by line first and added in one go.
   * Mounted fresh each time it opens.
   */
  let { list = false, onClose }: { list?: boolean; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  // svelte-ignore state_referenced_locally
  let mode = $state<"one" | "list">(list ? "list" : "one");
  let value = $state("");
  let subdomains = $state(false);
  let error = $state<string | null>(null);

  const add = createMutation(() => ({
    mutationFn: () =>
      api<{ id: string }>("/exposure", { method: "POST", body: { value, includeSubdomains: subdomains } }),
    onMutate: () => {
      error = null;
    },
    // The proof of control comes right after: the new website opens with its TXT record and file to set up.
    onSuccess: async ({ id }) => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.added"));
      await goto(href(`/websites/${encodeURIComponent(id)}`, { verify: "1" }));
    },
    onError: (e: Error) => {
      error = problemText(e);
    },
  }));

  function problemText(e: Error): string {
    if (e instanceof ApiError && e.code === "duplicate") return t("websites.addErrors.duplicate");
    if (e instanceof ApiError && e.code === "limit-reached") return t("websites.addErrors.limit");
    if (e instanceof ApiError && e.code === "rate-limited") return t("websites.addErrors.rateLimited");
    if (e instanceof ApiError && e.status === 422) {
      const code = e.problem?.errors?.[0]?.message ?? "";
      return isAddProblem(code) ? t(`websites.addErrors.${code}`) : t("websites.addErrors.invalid");
    }
    return t("errors.actionFailed");
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (value.trim() !== "") add.mutate();
  }

  /* ------------------------------ a list ------------------------------ */

  let text = $state("");
  /** The checked lines; null while the list is being written. */
  let checked = $state<ListItem[] | null>(null);
  /** The non-blank lines that were checked, with their line number in the text. */
  let sent = $state<{ lineNo: number; value: string }[]>([]);

  const lines = $derived(
    text
      .split(/\r?\n/)
      .map((raw, i) => ({ lineNo: i + 1, value: raw.trim() }))
      .filter((l) => l.value !== ""),
  );
  const tooMany = $derived(lines.length > MAX_LINES);
  const accepted = $derived((checked ?? []).flatMap((item) => (item.ok ? [item] : [])));
  const refused = $derived((checked ?? []).flatMap((item) => (item.ok ? [] : [item])));
  /** The line number in the text of a checked line. */
  const lineNo = (line: number) => sent[line - 1]?.lineNo ?? line;

  const check = createMutation(() => ({
    mutationFn: (values: string[]) =>
      api<{ items: ListItem[]; valid: number }>("/exposure/list", {
        method: "POST",
        body: { values, includeSubdomains: subdomains, dryRun: true },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: (result) => {
      checked = result.items;
    },
    onError: (e: Error) => {
      error = problemText(e);
    },
  }));

  const addList = createMutation(() => ({
    mutationFn: (values: string[]) =>
      api<{ added: number }>("/exposure/list", {
        method: "POST",
        body: { values, includeSubdomains: subdomains },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async ({ added }) => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.listAdded", { count: added }));
      onClose();
    },
    // Something changed since the check (a name was added elsewhere, the limit was reached): check again and say so.
    onError: (e: Error) => {
      error =
        e instanceof ApiError && (e.status === 422 || e.code === "limit-reached")
          ? t("websites.listChanged")
          : problemText(e);
      if (e instanceof ApiError && (e.status === 422 || e.code === "limit-reached")) {
        check.mutate(sent.map((l) => l.value));
      }
    },
  }));

  function checkList(event: SubmitEvent) {
    event.preventDefault();
    if (lines.length === 0 || tooMany) return;
    sent = lines;
    check.mutate(lines.map((l) => l.value));
  }

  const reason = (item: Extract<ListItem, { ok: false }>) => {
    if (item.problem === "repeated")
      return t("websites.listProblem.repeated", { line: lineNo(item.firstLine ?? 0) });
    if (item.problem === "duplicate" || item.problem === "limit")
      return t(`websites.listProblem.${item.problem}`);
    return isAddProblem(item.problem)
      ? t(`websites.addErrors.${item.problem}`)
      : t("websites.addErrors.invalid");
  };
</script>

{#snippet subdomainsBox(hint: string)}
  <label class="flex items-start gap-2.5">
    <Checkbox class="mt-1" bind:checked={subdomains} />
    <span>
      {t("websites.addSubdomains")}
      <span class="block text-sm text-muted-foreground">{hint}</span>
    </span>
  </label>
{/snippet}

<Dialog open {onClose} title={t("websites.addTitle")} description={t("websites.addDescription")}>
  <div class="mb-4">
    <Segmented
      label={t("websites.addMode")}
      value={mode}
      options={[
        { value: "one", label: t("websites.addModeOne") },
        { value: "list", label: t("websites.addModeList") },
      ]}
      onChange={(next) => {
        mode = next;
        error = null;
      }}
    />
  </div>

  {#if mode === "one"}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <Field
        label={t("websites.addValue")}
        hint={t("websites.addValueHint")}
        name="value"
        bind:value
        autocomplete="off"
        autocapitalize="none"
        spellcheck={false}
        required
        maxlength={300}
        placeholder="www.example.com"
      />
      {@render subdomainsBox(t("websites.addSubdomainsHint"))}
      <p class="text-sm text-muted-foreground">{t("websites.addStage1Note")}</p>
      <DialogFooter>
        <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={add.isPending || value.trim() === ""}>
          {add.isPending ? t("common.loading") : t("websites.addSubmit")}
        </Button>
      </DialogFooter>
    </form>
  {:else if checked === null}
    <form class="grid gap-4" onsubmit={checkList}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <TextAreaField
        label={t("websites.listValue")}
        hint={t("websites.listValueHint", { max: MAX_LINES })}
        error={tooMany ? t("websites.listTooMany", { max: MAX_LINES, count: lines.length }) : null}
        name="values"
        bind:value={text}
        rows={10}
        class="font-mono text-sm"
        autocomplete="off"
        autocapitalize="none"
        spellcheck={false}
        placeholder={"www.example.com\napi.example.com\nshop.example.com"}
      />
      {@render subdomainsBox(t("websites.listSubdomainsHint"))}
      <p class="text-sm text-muted-foreground">{t("websites.listCoverNote")}</p>
      <DialogFooter>
        <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
        <Button type="submit" disabled={check.isPending || lines.length === 0 || tooMany}>
          {check.isPending ? t("common.loading") : t("websites.listCheck", { count: lines.length })}
        </Button>
      </DialogFooter>
    </form>
  {:else}
    <div class="grid gap-4" data-testid="list-review">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <p>{t("websites.listSummary", { valid: accepted.length, total: checked.length })}</p>

      {#if refused.length > 0}
        <section aria-labelledby="list-refused">
          <h3 id="list-refused" class="mb-1.5 font-medium">
            {t("websites.listRefused", { count: refused.length })}
          </h3>
          <ul class="grid gap-1.5 text-sm" data-testid="list-refused">
            {#each refused as item (item.line)}
              <li class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2.5">
                <span class="text-muted-foreground tabular-nums">{t("websites.listLine", { line: lineNo(item.line) })}</span>
                <span class="min-w-0">
                  <span class="font-mono break-all">{item.input}</span>
                  <span class="block text-muted-foreground">{reason(item)}</span>
                </span>
              </li>
            {/each}
          </ul>
          <p class="mt-1.5 text-sm text-muted-foreground">{t("websites.listRefusedNote")}</p>
        </section>
      {/if}

      {#if accepted.length > 0}
        <section aria-labelledby="list-accepted">
          <h3 id="list-accepted" class="mb-1.5 font-medium">
            {t("websites.listAccepted", { count: accepted.length })}
          </h3>
          <ul class="grid max-h-64 gap-1 overflow-y-auto text-sm" data-testid="list-accepted">
            {#each accepted as item (item.line)}
              <li class="min-w-0">
                <span class="font-mono break-all">{item.value}</span>
                {#if item.coveredBy}
                  <span class="text-muted-foreground">
                    · {t("websites.listCoveredBy", { domain: item.coveredBy.value })}</span
                  >
                {/if}
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      <p class="text-sm text-muted-foreground">{t("websites.addStage1Note")}</p>
      <DialogFooter>
        <Button
          variant="outline"
          onclick={() => {
            checked = null;
            error = null;
          }}>{t("websites.listBack")}</Button
        >
        <Button
          disabled={addList.isPending || check.isPending || accepted.length === 0}
          onclick={() => addList.mutate(accepted.map((item) => item.value))}
        >
          {addList.isPending ? t("common.loading") : t("websites.listAdd", { count: accepted.length })}
        </Button>
      </DialogFooter>
    </div>
  {/if}
</Dialog>
