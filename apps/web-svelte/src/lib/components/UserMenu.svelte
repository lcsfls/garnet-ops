<script lang="ts">
  import { LogOut, UserRound } from "@lucide/svelte";
  import { api } from "../api.ts";
  import { authClient } from "../auth-client.ts";
  import { t } from "../i18n.svelte.ts";
  import { initialsOf } from "../initials.ts";
  import type { Me } from "../session.ts";
  import { signOutAndLeave } from "../session-end.ts";
  import { getTheme, setTheme, THEMES } from "../theme.svelte.ts";
  import LanguagePicker from "./LanguagePicker.svelte";
  import Segmented from "./Segmented.svelte";
  import Button from "./ui/Button.svelte";

  /**
   * The avatar in the top bar opens a panel with who is signed in, language, theme and sign-out. It is a disclosure, not
   * a menu: it holds form controls. Escape and a click outside close it.
   */
  let { me }: { me: Me } = $props();
  let open = $state(false);
  const panelId = $props.id();
  let root: HTMLDivElement | undefined = $state();
  let button: HTMLButtonElement | undefined = $state();

  $effect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root?.contains(event.target as Node)) open = false;
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      open = false;
      button?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  });

  const signOut = () => signOutAndLeave(() => authClient.signOut());
</script>

<div bind:this={root} class="relative">
  <button
    bind:this={button}
    type="button"
    aria-expanded={open}
    aria-controls={panelId}
    aria-label={t("shell.accountMenu", { name: me.user.name })}
    onclick={() => (open = !open)}
    class="grid size-9 place-items-center rounded-full bg-muted text-sm font-semibold hover:bg-accent"
  >
    <span aria-hidden="true">{initialsOf(me.user.name)}</span>
  </button>
  {#if open}
    <div
      id={panelId}
      class="absolute top-full right-0 z-30 mt-2 grid w-80 gap-4 rounded-lg border bg-card p-4 text-card-foreground shadow-xs"
    >
      <div class="min-w-0">
        <div class="truncate font-medium">{t("shell.signedInAs", { name: me.user.name })}</div>
        <div class="truncate text-sm text-muted-foreground">{me.user.email}</div>
        <div class="mt-1 text-sm text-muted-foreground">{me.organization.name} · {t(`shell.role.${me.role}`)}</div>
      </div>
      <a
        href="/account"
        onclick={() => (open = false)}
        class="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-input bg-card px-4 text-base font-medium shadow-xs hover:bg-accent"
      >
        <UserRound aria-hidden="true" class="size-4" />
        {t("shell.accountLink")}
      </a>
      <div class="grid gap-1.5">
        <span class="text-sm font-medium">{t("common.language")}</span>
        <!-- The choice is kept on the account too, so it follows the user to other browsers (ADR 0017). -->
        <LanguagePicker
          onChanged={(locale) => {
            void api("/account/preferences", {
              method: "PUT",
              body: { locale, timeZone: me.user.timeZone },
            }).catch(() => {});
          }}
        />
      </div>
      <div class="grid gap-1.5">
        <span class="text-sm font-medium">{t("shell.theme")}</span>
        <Segmented
          label={t("shell.theme")}
          value={getTheme()}
          options={THEMES.map((value) => ({ value, label: t(`shell.themes.${value}`) }))}
          onChange={setTheme}
        />
      </div>
      <Button variant="outline" onclick={signOut}>
        <LogOut aria-hidden="true" class="size-4" />
        {t("common.signOut")}
      </Button>
    </div>
  {/if}
</div>
