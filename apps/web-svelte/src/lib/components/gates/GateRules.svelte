<script lang="ts">
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import type { GateMode, GateRuleState } from "../../types.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Segmented from "../Segmented.svelte";
  import Badge from "../ui/Badge.svelte";
  import LicenseList from "./LicenseList.svelte";

  const MODES: GateMode[] = ["off", "report", "block"];
  const MODE_TONE = { off: "neutral", report: "medium", block: "critical" } as const;

  /** The gate rules with their modes; admins change them. */
  let { canEdit }: { canEdit: boolean } = $props();

  const queryClient = useQueryClient();
  const rules = createQuery(() => ({
    queryKey: ["gate-rules"],
    queryFn: () => api<GateRuleState[]>("/gates/rules"),
  }));
  const save = createMutation(() => ({
    mutationFn: (input: { rule: string; mode: GateMode; deniedLicenses?: string[] }) =>
      api(`/gates/rules/${input.rule}`, {
        method: "PUT",
        body: { mode: input.mode, deniedLicenses: input.deniedLicenses },
      }),
    onSuccess: async () => {
      toast.success(t("gates.saved"));
      await queryClient.invalidateQueries({ queryKey: ["gate-rules"] });
    },
    onError: () => toast.error(t("errors.actionFailed")),
  }));
</script>

<Card>
  <CardHeader title={t("gates.rulesTitle")} description={t("gates.rulesDescription")} />
  <QueryStatus query={rules} />
  <ul>
    {#each rules.data ?? [] as rule (rule.rule)}
      <li class="grid gap-3 border-t px-5 py-3">
        <div class="flex flex-wrap items-start gap-3">
          <Badge tone={MODE_TONE[rule.mode]} class="mt-0.5">{t(`gates.mode.${rule.mode}`)}</Badge>
          <div class="min-w-0 flex-[1_1_14rem]">
            <div class="font-medium">{t(`gates.rule.${rule.rule}`)}</div>
            <div class="text-[13.5px] text-muted-foreground">{t(`gates.ruleHint.${rule.rule}`)}</div>
          </div>
          {#if canEdit}
            <Segmented
              label={t("gates.modeLabel", { rule: t(`gates.rule.${rule.rule}`) })}
              value={rule.mode}
              options={MODES.map((mode) => ({ value: mode, label: t(`gates.mode.${mode}`) }))}
              onChange={(mode) => save.mutate({ rule: rule.rule, mode })}
            />
          {/if}
        </div>
        <p class="text-[13px] text-muted-foreground">{t(`gates.modeHint.${rule.mode}`)}</p>
        {#if rule.rule === "license-denied" && canEdit}
          <LicenseList
            value={rule.deniedLicenses ?? []}
            pending={save.isPending}
            onSave={(deniedLicenses) => save.mutate({ rule: rule.rule, mode: rule.mode, deniedLicenses })}
          />
        {/if}
      </li>
    {/each}
  </ul>
</Card>
