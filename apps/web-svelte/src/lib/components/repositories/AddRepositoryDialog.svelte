<script lang="ts" module>
  import type { MessageKey } from "../../i18n.svelte.ts";
  import type { RepositoryRow } from "../../types.ts";

  const ACCESS_LABELS = {
    none: "repositories.accessPublic",
    "https-token": "repositories.accessToken",
    "ssh-deploy-key": "repositories.accessDeployKey",
  } as const satisfies Record<RepositoryRow["authKind"], MessageKey>;

  type BulkResult = {
    created: { id: string; name: string; url: string; scanId: string }[];
    skipped: { url: string; reason: "duplicate" }[];
  };
</script>

<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { BULK_LIMIT, parseUrlList } from "../../repo-urls.ts";
  import Alert from "../ui/Alert.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";
  import Radio from "../ui/Radio.svelte";
  import TextAreaField from "../ui/TextAreaField.svelte";
  import DeployKeyInstructions from "./DeployKeyInstructions.svelte";

  let { open, onClose }: { open: boolean; onClose: () => void } = $props();

  const queryClient = useQueryClient();
  /** Several https:// repositories at once, all with the same access. */
  let many = $state(false);
  let urlList = $state("");
  let access = $state<RepositoryRow["authKind"]>("none");
  /** Set after an SSH repository was added: the key the user now adds to the forge. */
  let created = $state<{ id: string; deployPublicKey: string } | null>(null);
  /** Set after several repositories were added and some were already connected. */
  let bulkResult = $state<BulkResult | null>(null);
  let error = $state<string | null>(null);
  let fieldErrors = $state<Record<string, string>>({});
  const urls = $derived(parseUrlList(urlList));

  function fail(e: unknown, sent: string[] = []) {
    if (!(e instanceof ApiError)) {
      error = t("errors.network");
      return;
    }
    if (e.code === "duplicate") {
      error = t("repositories.errorDuplicate");
      return;
    }
    if (e.code === "auth-mismatch") {
      const ssh = (e.problem as { urls?: string[] } | null)?.urls;
      error = ssh?.length
        ? t("repositories.errorSshMany", { urls: ssh.join(", ") })
        : t("repositories.errorAuthMismatch");
      return;
    }
    if (e.status === 422) {
      const errors: Record<string, string> = {};
      for (const x of e.problem?.errors ?? []) {
        const [field, index] = x.path.split(".");
        if (!field || errors[field]) continue;
        const url = field === "urls" && index !== undefined ? sent[Number(index)] : undefined;
        errors[field] = url ? t("repositories.errorUrlInvalid", { url }) : x.message;
      }
      fieldErrors = errors;
      error = t("repositories.errorInvalid");
      return;
    }
    error = t("errors.generic");
  }

  const create = createMutation(() => ({
    mutationFn: (body: unknown) =>
      api<{ id: string; scanId: string | null; deployPublicKey: string | null }>("/repositories", {
        method: "POST",
        body,
      }),
    onSuccess: async (result: { id: string; scanId: string | null; deployPublicKey: string | null }) => {
      await queryClient.invalidateQueries();
      if (result.deployPublicKey) created = { id: result.id, deployPublicKey: result.deployPublicKey };
      else onClose();
    },
    onError: (e: Error) => fail(e),
  }));

  const createMany = createMutation(() => ({
    mutationFn: (body: { urls: string[] } & Record<string, unknown>) =>
      api<BulkResult>("/repositories/bulk", { method: "POST", body }),
    onSuccess: async (result: BulkResult) => {
      await queryClient.invalidateQueries();
      if (result.skipped.length > 0) bulkResult = result;
      else onClose();
    },
    onError: (e: Error, body: { urls: string[] } & Record<string, unknown>) => fail(e, body.urls),
  }));

  $effect(() => {
    if (!open) {
      error = null;
      fieldErrors = {};
      access = "none";
      many = false;
      urlList = "";
      created = null;
      bulkResult = null;
    }
  });

  const firstScan = createMutation(() => ({
    mutationFn: (id: string) => api(`/repositories/${id}/scans`, { method: "POST" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repositories"] });
      onClose();
    },
    onError: () => {
      error = t("errors.generic");
    },
  }));

  function switchMode(next: boolean) {
    many = next;
    error = null;
    fieldErrors = {};
    // Deploy keys are created per repository, so the list offers public access and tokens only.
    if (next && access === "ssh-deploy-key") access = "none";
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const optional = (key: string) => String(form.get(key) ?? "").trim() || undefined;
    const auth =
      access === "https-token" ? { kind: "https-token", token: String(form.get("token")) } : { kind: access };
    error = null;
    fieldErrors = {};
    if (!many) {
      create.mutate({
        url: String(form.get("url")).trim(),
        name: optional("name"),
        branch: optional("branch"),
        auth,
      });
      return;
    }
    if (urls.length === 0) {
      fieldErrors = { urls: t("repositories.errorUrlsEmpty") };
      return;
    }
    if (urls.length > BULK_LIMIT) {
      fieldErrors = { urls: t("repositories.errorUrlsTooMany", { max: BULK_LIMIT }) };
      return;
    }
    createMany.mutate({ urls, branch: optional("branch"), auth });
  }

  const pending = $derived(create.isPending || createMany.isPending);
  const kinds = $derived(
    many ? (["none", "https-token"] as const) : (["none", "https-token", "ssh-deploy-key"] as const),
  );
  // One dialog whose content follows the step: the form, the new deploy key, or the result of a list.
  const title = $derived(
    created
      ? t("repositories.deployKeyAddedTitle")
      : bulkResult
        ? t("repositories.bulkResultTitle")
        : t("repositories.addTitle"),
  );
  const description = $derived(
    created
      ? t("repositories.deployKeyAddedDescription")
      : bulkResult
        ? undefined
        : t("repositories.addDescription"),
  );
</script>

<Dialog {open} {onClose} {title} {description}>
  {#if created}
    {@const added = created}
    <div class="grid gap-4">
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      <DeployKeyInstructions publicKey={added.deployPublicKey} />
      <DialogFooter>
        <Button variant="outline" onclick={onClose}>{t("repositories.later")}</Button>
        <Button disabled={firstScan.isPending} onclick={() => firstScan.mutate(added.id)}>
          {firstScan.isPending ? t("common.loading") : t("repositories.startFirstScan")}
        </Button>
      </DialogFooter>
    </div>
  {:else if bulkResult}
    <div class="grid gap-4">
      <p>{t("repositories.bulkAdded", { count: bulkResult.created.length })}</p>
      <div class="grid gap-1.5">
        <p class="text-sm font-medium">{t("repositories.bulkSkipped")}</p>
        <ul class="grid gap-1 font-mono text-sm break-all text-muted-foreground">
          {#each bulkResult.skipped as s (s.url)}
            <li>{s.url}</li>
          {/each}
        </ul>
      </div>
      <DialogFooter>
        <Button onclick={onClose}>{t("common.close")}</Button>
      </DialogFooter>
    </div>
  {:else}
    <form class="grid gap-4" onsubmit={submit} novalidate={many}>
      {#if error}<Alert tone="error">{error}</Alert>{/if}
      {#if many}
        <TextAreaField
          label={t("repositories.urls")}
          hint={t("repositories.urlsHint", { max: BULK_LIMIT })}
          error={fieldErrors.urls}
          name="urls"
          rows={6}
          bind:value={urlList}
          autocomplete="off"
          spellcheck={false}
          class="font-mono text-sm"
        />
      {:else}
        <Field
          label={t("repositories.url")}
          hint={t("repositories.urlHint")}
          error={fieldErrors.url}
          name="url"
          required
          autocomplete="off"
          spellcheck={false}
          class="font-mono"
        />
      {/if}
      <div>
        <button
          type="button"
          class="text-sm font-medium text-primary underline-offset-4 hover:underline"
          onclick={() => switchMode(!many)}
        >
          {many ? t("repositories.addOne") : t("repositories.addSeveral")}
        </button>
      </div>
      {#if !many}
        <Field
          label={t("repositories.name")}
          hint={t("repositories.nameHint")}
          error={fieldErrors.name}
          name="name"
          maxlength={120}
        />
      {/if}
      <Field
        label={t("repositories.branch")}
        hint={t("repositories.branchHint")}
        error={fieldErrors.branch}
        name="branch"
        maxlength={200}
        spellcheck={false}
        class="font-mono"
      />
      <fieldset class="grid gap-2">
        <legend class="mb-1.5 text-sm font-medium">{t("repositories.access")}</legend>
        {#each kinds as kind (kind)}
          <label class="flex items-center gap-2.5">
            <Radio name="access" value={kind} checked={access === kind} onchange={() => (access = kind)} />
            {t(ACCESS_LABELS[kind])}
          </label>
        {/each}
      </fieldset>
      {#if access === "https-token"}
        <Field
          label={t("repositories.token")}
          hint={many ? t("repositories.tokenHintMany") : t("repositories.tokenHint")}
          error={fieldErrors.auth}
          name="token"
          type="password"
          required
          minlength={8}
          maxlength={500}
          autocomplete="off"
        />
      {/if}
      <DialogFooter>
        <Button variant="outline" onclick={onClose}>{t("repositories.cancel")}</Button>
        <Button type="submit" disabled={pending}>
          {pending
            ? t("common.loading")
            : many
              ? t("repositories.submitMany", { count: urls.length })
              : access === "ssh-deploy-key"
                ? t("repositories.submitKey")
                : t("repositories.submit")}
        </Button>
      </DialogFooter>
    </form>
  {/if}
</Dialog>
