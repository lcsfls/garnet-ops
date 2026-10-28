<script lang="ts">
  import { LogOut } from "@lucide/svelte";
  import { createMutation, createQuery, useQueryClient } from "@tanstack/svelte-query";
  import { type SessionRow, sessionsQuery } from "../../account.ts";
  import { api } from "../../api.ts";
  import { formatDateTime, formatRelative } from "../../format.ts";
  import { t } from "../../i18n.svelte.ts";
  import { toast } from "../../toast.svelte.ts";
  import Card from "../Card.svelte";
  import CardHeader from "../CardHeader.svelte";
  import QueryStatus from "../QueryStatus.svelte";
  import Alert from "../ui/Alert.svelte";
  import Badge from "../ui/Badge.svelte";
  import Button from "../ui/Button.svelte";
  import ConfirmDialog from "../ui/ConfirmDialog.svelte";

  /** Account → Sessions: where the account is signed in; end one session or all the others. */
  const queryClient = useQueryClient();
  const query = createQuery(() => sessionsQuery);
  let ending = $state<SessionRow | null>(null);
  let endingOthers = $state(false);
  let error = $state<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["account", "sessions"] });

  const end = createMutation(() => ({
    mutationFn: (id: string) => api(`/account/sessions/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      ending = null;
      await refresh();
    },
    onError: () => {
      error = t("errors.generic");
    },
  }));
  const endOthers = createMutation(() => ({
    mutationFn: () => api<{ revoked: number }>("/account/sessions/revoke-others", { method: "POST" }),
    onSuccess: async (result: { revoked: number }) => {
      endingOthers = false;
      toast.success(t("account.sessions.revoked", { count: result.revoked }));
      await refresh();
    },
    onError: () => {
      error = t("errors.generic");
    },
  }));

  const label = (s: SessionRow) =>
    s.device.browser && s.device.os
      ? t("account.sessions.deviceLabel", { browser: s.device.browser, os: s.device.os })
      : s.device.browser || s.device.os || t("account.sessions.unknownDevice");
  const others = $derived(query.data?.filter((s) => !s.current).length ?? 0);
</script>

<Card>
  <CardHeader title={t("account.sessions.title")} description={t("account.sessions.description")}>
    {#snippet actions()}
      <Button
        variant="outline"
        disabled={others === 0}
        onclick={() => {
          error = null;
          endingOthers = true;
        }}
      >
        <LogOut aria-hidden="true" class="size-4" />
        {t("account.sessions.revokeOthers")}
      </Button>
    {/snippet}
  </CardHeader>
  <div class="grid gap-4 px-5 pb-5">
    {#if error}<Alert tone="error">{error}</Alert>{/if}
    {#if query.data}
      <ul class="grid gap-2">
        {#each query.data as s (s.id)}
          <li
            data-testid="session"
            data-current={s.current ? "true" : undefined}
            class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border px-3 py-2.5"
          >
            <div class="min-w-0 flex-[1_1_16rem]">
              <div class="flex flex-wrap items-center gap-2">
                <span class="truncate font-medium">{label(s)}</span>
                {#if s.current}<Badge tone="info">{t("account.sessions.current")}</Badge>{/if}
              </div>
              <div class="text-sm text-muted-foreground">
                {#if s.ip}<span class="font-mono">{s.ip}</span>{" · "}{/if}{t("account.sessions.signedIn")}{" "}<time
                  datetime={s.createdAt}>{formatDateTime(s.createdAt)}</time
                >{" · "}{t("account.sessions.lastActive")}{" "}<time
                  datetime={s.lastActiveAt}
                  title={formatDateTime(s.lastActiveAt)}>{formatRelative(s.lastActiveAt)}</time
                >
              </div>
            </div>
            {#if !s.current}
              <Button
                variant="outline"
                class="h-9 px-3 text-sm"
                onclick={() => {
                  error = null;
                  ending = s;
                }}
              >
                {t("account.sessions.signOut")}
              </Button>
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <QueryStatus {query} class="px-0" />
    {/if}
    {#if query.data && others === 0}
      <p class="text-muted-foreground">{t("account.sessions.none")}</p>
    {/if}
    <p class="text-sm text-muted-foreground">{t("account.sessions.lastActiveNote")}</p>
  </div>
  <ConfirmDialog
    open={ending !== null}
    title={t("account.sessions.signOutTitle")}
    description={t("account.sessions.signOutText")}
    confirmLabel={t("account.sessions.signOut")}
    pending={end.isPending}
    onConfirm={() => ending && end.mutate(ending.id)}
    onClose={() => (ending = null)}
  />
  <ConfirmDialog
    open={endingOthers}
    title={t("account.sessions.revokeOthersTitle")}
    description={t("account.sessions.revokeOthersText")}
    confirmLabel={t("account.sessions.revokeOthersConfirm")}
    pending={endOthers.isPending}
    onConfirm={() => endOthers.mutate()}
    onClose={() => (endingOthers = false)}
  />
</Card>
