<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Checkbox from "../ui/Checkbox.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

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

  /**
   * Adds a domain, host name or public address (ADR 0023). Nothing is looked at from outside until it exists, and only stage 1;
   * verification comes later. Mounted fresh each time it opens.
   */
  let { onClose }: { onClose: () => void } = $props();

  const queryClient = useQueryClient();
  let value = $state("");
  let subdomains = $state(false);
  let error = $state<string | null>(null);

  const add = createMutation(() => ({
    mutationFn: () =>
      api<{ id: string }>("/exposure", { method: "POST", body: { value, includeSubdomains: subdomains } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["websites"] });
      toast.success(t("websites.added"));
      onClose();
    },
    onError: (e: Error) => {
      if (e instanceof ApiError && e.code === "duplicate") error = t("websites.addErrors.duplicate");
      else if (e instanceof ApiError && e.code === "limit-reached") error = t("websites.addErrors.limit");
      else if (e instanceof ApiError && e.status === 422) {
        const code = e.problem?.errors?.[0]?.message ?? "";
        error = isAddProblem(code) ? t(`websites.addErrors.${code}`) : t("websites.addErrors.invalid");
      } else error = t("errors.actionFailed");
    },
  }));

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (value.trim() !== "") add.mutate();
  }
</script>

<Dialog open {onClose} title={t("websites.addTitle")} description={t("websites.addDescription")}>
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
    <label class="flex items-start gap-2.5">
      <Checkbox class="mt-1" bind:checked={subdomains} />
      <span>
        {t("websites.addSubdomains")}
        <span class="block text-sm text-muted-foreground">{t("websites.addSubdomainsHint")}</span>
      </span>
    </label>
    <p class="text-sm text-muted-foreground">{t("websites.addStage1Note")}</p>
    <DialogFooter>
      <Button variant="outline" onclick={onClose}>{t("common.cancel")}</Button>
      <Button type="submit" disabled={add.isPending || value.trim() === ""}>
        {add.isPending ? t("common.loading") : t("websites.addSubmit")}
      </Button>
    </DialogFooter>
  </form>
</Dialog>
