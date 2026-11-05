<script lang="ts">
  import { ApiError, api } from "#lib/api.ts";
  import AuthLayout from "#lib/components/AuthLayout.svelte";
  import Alert from "#lib/components/ui/Alert.svelte";
  import Button from "#lib/components/ui/Button.svelte";
  import Field from "#lib/components/ui/Field.svelte";
  import { type MessageKey, t } from "#lib/i18n.svelte.ts";
  import { queryClient } from "#lib/query.ts";
  import { goto } from "$app/navigation";

  /**
   * First start: set up a new installation, or bring back an existing one from a backup (ADR 0046). The restore sends the setup
   * token and passphrase first (they never travel in a header or the URL), then the file itself as it is, so a large backup
   * streams. Everything is restored in one transaction, or nothing is.
   */
  type Mode = "choose" | "new" | "restore";
  let mode = $state<Mode>("choose");
  let error = $state<MessageKey | null>(null);
  let alreadyDone = $state(false);
  let busy = $state(false);
  let restored = $state<{ rows: number; createdAt: string; secretsNotOpened: number } | null>(null);

  const RESTORE_ERRORS: Record<string, MessageKey> = {
    "invalid-setup-token": "setup.invalidToken",
    "restore-passphrase": "setup.restore.errorPassphrase",
    "restore-not-a-backup": "setup.restore.errorNotABackup",
    "restore-incomplete": "setup.restore.errorIncomplete",
    "restore-newer": "setup.restore.errorNewer",
    "restore-foreign": "setup.restore.errorNotABackup",
    "restore-expired": "setup.restore.errorExpired",
    "restore-failed": "setup.restore.errorFailed",
    "rate-limited": "setup.restore.errorRateLimited",
  };

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    busy = true;
    error = null;
    try {
      await api("/setup", {
        method: "POST",
        body: {
          token: String(form.get("token")).trim(),
          organizationName: String(form.get("organizationName")),
          name: String(form.get("name")),
          email: String(form.get("email")),
          password: String(form.get("password")),
          // Nightly scans run at 04:00 in the owner's zone; changeable later.
          timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        },
      });
      await queryClient.invalidateQueries();
      await goto("/sign-in?setup=done");
    } catch (e) {
      if (e instanceof ApiError && e.code === "invalid-setup-token") error = "setup.invalidToken";
      else if (e instanceof ApiError && e.code === "already-set-up") alreadyDone = true;
      else error = e instanceof ApiError ? "errors.generic" : "errors.network";
    } finally {
      busy = false;
    }
  }

  async function restore(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const file = form.get("file");
    if (!(file instanceof File) || file.size === 0) {
      error = "setup.restore.errorNoFile";
      return;
    }
    busy = true;
    error = null;
    try {
      const { id } = await api<{ id: string }>("/setup/restore", {
        method: "POST",
        body: { token: String(form.get("token")).trim(), passphrase: String(form.get("passphrase")) },
      });
      const res = await fetch(`/api/v1/setup/restore/${encodeURIComponent(id)}`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { accept: "application/json", "content-type": "application/octet-stream" },
        body: file,
      });
      const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
      if (!res.ok) throw new ApiError(res.status, body as never);
      restored = body as typeof restored;
      await queryClient.invalidateQueries();
    } catch (e) {
      if (e instanceof ApiError && e.code === "already-set-up") alreadyDone = true;
      else if (e instanceof ApiError) error = RESTORE_ERRORS[e.code ?? ""] ?? "setup.restore.errorFailed";
      else error = "errors.network";
    } finally {
      busy = false;
    }
  }
</script>

{#if alreadyDone}
  <AuthLayout title={t("setup.title")}>
    <div class="grid gap-4">
      <Alert tone="info">{t("setup.alreadyDone")}</Alert>
      <a href="/sign-in" class="font-medium text-primary-text underline-offset-4 hover:underline">{t("signIn.title")}</a>
    </div>
  </AuthLayout>
{:else if restored}
  <AuthLayout title={t("setup.restore.doneTitle")}>
    <div class="grid gap-4" data-testid="restore-done">
      <Alert tone="info">{t("setup.restore.done", { rows: restored.rows })}</Alert>
      {#if restored.secretsNotOpened > 0}
        <Alert tone="error">{t("setup.restore.secretsNotOpened", { count: restored.secretsNotOpened })}</Alert>
      {/if}
      <p class="text-sm text-muted-foreground">{t("setup.restore.signInHint")}</p>
      <a href="/sign-in" class="font-medium text-primary-text underline-offset-4 hover:underline">{t("signIn.title")}</a>
    </div>
  </AuthLayout>
{:else if mode === "choose"}
  <AuthLayout title={t("setup.title")} description={t("setup.chooseDescription")}>
    <div class="grid gap-3" data-testid="setup-choose">
      <button
        type="button"
        class="grid gap-1 rounded-md border px-4 py-3 text-left hover:bg-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        onclick={() => (mode = "new")}
        data-testid="setup-choose-new"
      >
        <span class="font-medium">{t("setup.chooseNew")}</span>
        <span class="text-sm text-muted-foreground">{t("setup.chooseNewText")}</span>
      </button>
      <button
        type="button"
        class="grid gap-1 rounded-md border px-4 py-3 text-left hover:bg-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        onclick={() => (mode = "restore")}
        data-testid="setup-choose-restore"
      >
        <span class="font-medium">{t("setup.chooseRestore")}</span>
        <span class="text-sm text-muted-foreground">{t("setup.chooseRestoreText")}</span>
      </button>
    </div>
  </AuthLayout>
{:else if mode === "restore"}
  <AuthLayout title={t("setup.restore.title")} description={t("setup.restore.description")}>
    <form class="grid gap-4" onsubmit={restore} data-testid="restore-form">
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      <Field
        label={t("setup.token")}
        hint={t("setup.tokenHint")}
        name="token"
        required
        autocomplete="off"
        spellcheck={false}
        class="font-mono"
      />
      <div class="grid gap-1.5">
        <label for="restore-file" class="text-sm font-medium">{t("setup.restore.file")}</label>
        <input
          id="restore-file"
          name="file"
          type="file"
          accept=".age,application/octet-stream"
          required
          aria-describedby="restore-file-hint"
          class="text-sm file:mr-3 file:rounded-md file:border file:bg-background file:px-3 file:py-1.5 file:text-sm"
        />
        <p id="restore-file-hint" class="text-sm text-muted-foreground">{t("setup.restore.fileHint")}</p>
      </div>
      <Field
        label={t("setup.restore.passphrase")}
        name="passphrase"
        type="password"
        required
        maxlength={1024}
        autocomplete="off"
      />
      <Alert tone="info">{t("setup.restore.replaces")}</Alert>
      <div class="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy}>{busy ? t("setup.restore.busy") : t("setup.restore.submit")}</Button>
        <Button type="button" variant="outline" disabled={busy} onclick={() => ((mode = "choose"), (error = null))}>
          {t("common.back")}
        </Button>
      </div>
    </form>
  </AuthLayout>
{:else}
  <AuthLayout title={t("setup.title")} description={t("setup.description")}>
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert tone="error">{t(error)}</Alert>{/if}
      <Field
        label={t("setup.token")}
        hint={t("setup.tokenHint")}
        name="token"
        required
        autocomplete="off"
        spellcheck={false}
        class="font-mono"
      />
      <Field label={t("setup.organization")} name="organizationName" required minlength={2} maxlength={100} />
      <Field label={t("common.name")} name="name" required autocomplete="name" maxlength={100} />
      <Field label={t("common.email")} name="email" type="email" required autocomplete="email" />
      <Field
        label={t("common.password")}
        hint={t("errors.passwordTooShort")}
        name="password"
        type="password"
        required
        minlength={12}
        maxlength={256}
        autocomplete="new-password"
      />
      <div class="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy}>{busy ? t("common.loading") : t("setup.submit")}</Button>
        <Button type="button" variant="outline" disabled={busy} onclick={() => ((mode = "choose"), (error = null))}>
          {t("common.back")}
        </Button>
      </div>
    </form>
  </AuthLayout>
{/if}
