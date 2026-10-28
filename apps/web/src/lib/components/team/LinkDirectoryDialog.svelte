<script lang="ts" module>
  import type { DirectoryRole } from "@garnetops/core/directory";

  interface Lookup {
    outcome: string;
    problem: string | null;
    person: {
      dn: string;
      email: string | null;
      name: string | null;
      groups: string[];
      role: DirectoryRole | null;
    } | null;
    emailMatches: boolean;
    alreadyLinked: boolean;
    account: { email: string; name: string; role: string };
  }
</script>

<script lang="ts">
  import { createMutation, useQueryClient } from "@tanstack/svelte-query";
  import { ApiError, api } from "../../api.ts";
  import { t } from "../../i18n.svelte.ts";
  import { StepUp } from "../../step-up.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import StepUpPrompt from "../StepUpPrompt.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import Dialog from "../ui/Dialog.svelte";
  import DialogFooter from "../ui/DialogFooter.svelte";
  import Field from "../ui/Field.svelte";

  /**
   * Links an existing local account to its directory entry (ADR 0020). Nothing is linked by mail
   * address on its own: an owner looks the person up, sees what the directory says, and confirms.
   * The account then signs in with the directory, takes its role from its groups and loses its
   * local password; its authenticator app stays.
   */
  let {
    member,
    currentUserEmail,
    onClose,
  }: {
    member: { userId: string; name: string; email: string } | null;
    currentUserEmail: string;
    onClose: () => void;
  } = $props();
  const queryClient = useQueryClient();
  const stepUp = new StepUp();
  let username = $state("");
  let error = $state<string | null>(null);

  const lookup = createMutation(() => ({
    mutationFn: (name: string) =>
      api<Lookup>("/directory/lookup", { method: "POST", body: { userId: member?.userId, username: name } }),
    onMutate: () => {
      error = null;
    },
    onError: (e: Error) => {
      error =
        e instanceof ApiError && e.status === 422
          ? t("directory.fieldError.username_invalid")
          : e instanceof ApiError && e.status === 429
            ? t("errors.tooManyAttempts")
            : e instanceof ApiError && e.status === 503
              ? t("errors.directoryUnavailable")
              : t("errors.actionFailed");
    },
  }));
  const link = createMutation(() => ({
    mutationFn: (name: string) =>
      api<{ role: DirectoryRole }>("/directory/link", {
        method: "POST",
        body: { userId: member?.userId, username: name },
      }),
    onMutate: () => {
      error = null;
    },
    onSuccess: async () => {
      toast.success(t("directory.linked", { name: member?.name ?? "" }));
      await queryClient.invalidateQueries({ queryKey: ["team-members"] });
      close();
    },
    onError: (e: Error, name: string): void => {
      if (stepUp.handled(e, () => link.mutate(name))) return;
      const code = e instanceof ApiError ? e.code : null;
      error =
        code === "email-mismatch"
          ? t("directory.linkEmailMismatch")
          : code === "not-allowed"
            ? t("directory.linkNotAllowed")
            : code === "already-linked"
              ? t("directory.linkAlreadyLinked")
              : t("errors.actionFailed");
    },
  }));

  function close() {
    lookup.reset();
    link.reset();
    username = "";
    error = null;
    onClose();
  }
  function submit(event: SubmitEvent) {
    event.preventDefault();
    link.reset();
    lookup.mutate(username.trim());
  }

  const found = $derived(lookup.data);
  const person = $derived(found?.person ?? null);
  const ready = $derived(Boolean(found && person?.role && found.emailMatches && !found.alreadyLinked));
</script>

<Dialog
  open={member !== null}
  onClose={close}
  title={t("directory.linkTitle", { name: member?.name ?? "" })}
  description={t("directory.linkDescription", { email: member?.email ?? "" })}
>
  <div class="grid gap-4">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    <form class="flex flex-wrap items-end gap-3" onsubmit={submit} novalidate>
      <div class="min-w-0 flex-[1_1_14rem]">
        <Field
          label={t("directory.linkUsername")}
          bind:value={username}
          oninput={() => lookup.reset()}
          required
          maxlength={128}
          autocapitalize="off"
          autocomplete="off"
          spellcheck={false}
        />
      </div>
      <Button type="submit" variant="outline" disabled={lookup.isPending || username.trim() === ""}>
        {lookup.isPending ? t("common.loading") : t("directory.linkLookup")}
      </Button>
    </form>
    {#if found}
      <div class="grid gap-3" data-testid="link-result">
        {#if person}
          <dl
            class="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 gap-y-1 rounded-md border px-3 py-3 text-sm"
          >
            <dt class="text-muted-foreground">{t("directory.testDn")}</dt>
            <dd class="font-mono break-all">{person.dn}</dd>
            <dt class="text-muted-foreground">{t("directory.testEmail")}</dt>
            <dd class="break-all">
              {person.email ?? t("directory.testNoEmail")}
              <Badge tone={found.emailMatches ? "neutral" : "critical"}>
                {found.emailMatches ? t("directory.linkEmailSame") : t("directory.linkEmailOther")}
              </Badge>
            </dd>
            <dt class="text-muted-foreground">{t("directory.testGroups")}</dt>
            <dd class="font-mono break-all">
              {person.groups.length > 0 ? person.groups.join("; ") : t("directory.testNoGroups")}
            </dd>
            <dt class="text-muted-foreground">{t("directory.testRole")}</dt>
            <dd>
              {#if person.role}
                <Badge tone="neutral">{t(`team.roles.${person.role}`)}</Badge>
              {:else}
                <span class="text-destructive-text">{t("directory.testNoRole")}</span>
              {/if}
            </dd>
          </dl>
        {:else}
          <Alert tone="error">{t("directory.linkNotFound")}</Alert>
        {/if}
        {#if found.alreadyLinked}<Alert tone="error">{t("directory.linkAlreadyLinked")}</Alert>{/if}
        {#if person && !found.emailMatches}<Alert tone="error">{t("directory.linkEmailMismatch")}</Alert>{/if}
        {#if person && !person.role}<Alert tone="error">{t("directory.linkNotAllowed")}</Alert>{/if}
        {#if ready}<Alert tone="info">{t("directory.linkConsequences")}</Alert>{/if}
      </div>
    {/if}
    <DialogFooter>
      <Button variant="outline" onclick={close}>
        {t("common.cancel")}
      </Button>
      <Button disabled={!ready || link.isPending} onclick={() => link.mutate(username.trim())}>
        {link.isPending ? t("common.loading") : t("directory.linkConfirm")}
      </Button>
    </DialogFooter>
  </div>
</Dialog>
<StepUpPrompt {stepUp} email={currentUserEmail} />
