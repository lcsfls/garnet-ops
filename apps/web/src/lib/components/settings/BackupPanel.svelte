<script lang="ts">
  import { BACKUP_PASSPHRASE_MIN } from "@garnetops/core/backup";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { formatDateTime, formatNumber } from "../../format.ts";
  import { type MessageKey, t } from "../../i18n.svelte.ts";
  import type { Me } from "../../session.ts";
  import type { BadgeTone } from "../../severity-meta.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import Field from "../ui/Field.svelte";

  /**
   * Settings, Backup (ADR 0046), for owners: a backup of the whole installation, encrypted with a passphrase the owner chooses,
   * built by the worker and downloadable for an hour by the owner who asked. A restore happens in the setup of a new
   * installation. The passphrase is sent once and never stored readable; without it the file cannot be opened.
   */
  let { me }: { me: Me } = $props();

  interface BackupItem {
    id: string;
    state: "pending" | "building" | "ready" | "failed" | "expired";
    error: string | null;
    sizeBytes: number | null;
    sha256: string | null;
    rowCount: number | null;
    createdAt: string;
    readyAt: string | null;
    expiresAt: string | null;
    downloadedAt: string | null;
    requestedBy: string | null;
    canDownload: boolean;
    fileName: string;
  }

  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let passphrase = $state("");
  let confirm = $state("");
  let error = $state<MessageKey | null>(null);
  const long = $derived(passphrase.trim().length >= BACKUP_PASSPHRASE_MIN);
  const same = $derived(passphrase === confirm);

  const list = createQuery(() => ({
    queryKey: ["backup"],
    queryFn: () => api<{ items: BackupItem[] }>("/backup"),
    // While the worker builds one, ask again every few seconds.
    refetchInterval: (query: { state: { data?: { items: BackupItem[] } } }) =>
      query.state.data?.items.some((item) => item.state === "pending" || item.state === "building")
        ? 3000
        : false,
  }));
  const busy = $derived(
    list.data?.items.some((item) => item.state === "pending" || item.state === "building") ?? false,
  );

  const create = createMutation(() => ({
    mutationFn: () => api("/backup", { method: "POST", body: { passphrase } }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      passphrase = "";
      confirm = "";
      await queryClient.invalidateQueries({ queryKey: ["backup"] });
      toast.success(t("backup.requested"));
    },
    onError: (e: Error) => {
      if (stepUp.handled(e, () => create.mutate())) return;
      const code = e instanceof ApiError ? e.code : null;
      error =
        code === "backup-running"
          ? "backup.errorRunning"
          : code === "backup-several-organisations"
            ? "backup.errorSeveral"
            : code === "rate-limited"
              ? "backup.errorRateLimited"
              : code?.startsWith("passphrase-")
                ? "backup.passphraseTooShort"
                : "errors.actionFailed";
    },
  }));

  // A failed backup is not a severity: it gets the outline badge and its reason in words (AGENTS.md rule 6).
  const STATE: Record<BackupItem["state"], { label: MessageKey; tone: BadgeTone }> = {
    pending: { label: "backup.statePending", tone: "neutral" },
    building: { label: "backup.stateBuilding", tone: "neutral" },
    ready: { label: "backup.stateReady", tone: "info" },
    failed: { label: "backup.stateFailed", tone: "outline" },
    expired: { label: "backup.stateExpired", tone: "neutral" },
  };
  const ERRORS: Record<string, MessageKey> = {
    "secret-missing": "backup.errorSecretMissing",
    "build-failed": "backup.errorBuildFailed",
    expired: "backup.errorExpired",
  };
  const megabytes = (bytes: number) => formatNumber(Math.max(0.1, Math.round(bytes / 104_857.6) / 10));
</script>

<StepUpPrompt {stepUp} email={me.user.email} />
<Card>
  <CardHeader title={t("backup.title")} description={t("backup.description")} />
  <form
    class="grid gap-4 px-5 py-4"
    data-testid="backup-form"
    onsubmit={(event) => {
      event.preventDefault();
      if (long && same) create.mutate();
    }}
  >
    <Alert tone="info">{t("backup.contains")}</Alert>
    {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
    <Field
      label={t("backup.passphrase")}
      hint={t("backup.passphraseHint", { min: BACKUP_PASSPHRASE_MIN })}
      name="passphrase"
      type="password"
      autocomplete="new-password"
      required
      maxlength={1024}
      bind:value={passphrase}
    />
    <Field
      label={t("backup.confirm")}
      name="confirm"
      type="password"
      autocomplete="new-password"
      required
      maxlength={1024}
      bind:value={confirm}
      error={confirm.length > 0 && !same ? t("backup.mismatch") : undefined}
    />
    <div>
      <Button type="submit" disabled={!long || !same || busy || create.isPending}>
        {busy ? t("backup.building") : t("backup.create")}
      </Button>
    </div>
  </form>

  <section class="border-t px-5 py-4" aria-labelledby="backup-list-title" data-testid="backup-list">
    <h3 id="backup-list-title" class="mb-2 font-medium">{t("backup.listTitle")}</h3>
    {#if list.data && list.data.items.length === 0}
      <p class="text-sm text-muted-foreground">{t("backup.none")}</p>
    {:else if list.data}
      <ul class="grid gap-3">
        {#each list.data.items as item (item.id)}
          <li class="grid gap-1 rounded-md border px-4 py-3" data-testid="backup-item">
            <div class="flex flex-wrap items-center gap-2">
              <Badge tone={STATE[item.state].tone}>{t(STATE[item.state].label)}</Badge>
              <span class="text-sm">{formatDateTime(item.createdAt)}</span>
              {#if item.requestedBy}
                <span class="text-sm text-muted-foreground">{t("backup.by", { name: item.requestedBy })}</span>
              {/if}
              {#if item.canDownload}
                <a
                  class="ml-auto inline-flex h-9 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
                  href={`/api/v1/backup/${item.id}/download`}
                  download={item.fileName}
                  data-testid="backup-download"
                  onclick={() => setTimeout(() => queryClient.invalidateQueries({ queryKey: ["backup"] }), 1500)}
                >
                  {t("backup.download")}
                </a>
              {/if}
            </div>
            {#if item.state === "ready" && item.sizeBytes !== null}
              <p class="text-sm text-muted-foreground">
                {t("backup.readyFacts", {
                  size: megabytes(item.sizeBytes),
                  rows: formatNumber(item.rowCount ?? 0),
                  until: item.expiresAt ? formatDateTime(item.expiresAt) : "",
                })}
              </p>
              {#if item.sha256}
                <p class="break-all font-mono text-xs text-muted-foreground">SHA-256 {item.sha256}</p>
              {/if}
            {/if}
            {#if item.state === "failed" && item.error}
              <p class="text-sm">{t(ERRORS[item.error] ?? "backup.errorBuildFailed")}</p>
            {/if}
            {#if item.downloadedAt}
              <p class="text-sm text-muted-foreground">
                {t("backup.downloadedAt", { when: formatDateTime(item.downloadedAt) })}
              </p>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</Card>
