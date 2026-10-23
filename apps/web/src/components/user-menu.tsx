import { Link } from "@tanstack/react-router";
import { LogOut, UserRound } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api.ts";
import { authClient } from "../lib/auth-client.ts";
import type { Me } from "../lib/session.ts";
import { signOutAndLeave } from "../lib/session-end.ts";
import { setTheme, THEMES, useTheme } from "../lib/theme.ts";
import { Segmented } from "./filters.tsx";
import { LanguagePicker } from "./language-picker.tsx";
import { Button } from "./ui/button.tsx";

/** Up to two initials of the user's name, for the avatar. */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? [parts[0], parts[parts.length - 1]] : parts;
  return letters.map((p) => [...(p ?? "")][0]?.toUpperCase() ?? "").join("") || "?";
}

/**
 * The avatar in the top bar opens a panel with who is signed in, language,
 * theme and sign-out. It is a disclosure, not a menu: it holds form controls.
 * Escape and a click outside close it.
 */
export function UserMenu({ me }: { me: Me }) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const signOut = () => signOutAndLeave(() => authClient.signOut());

  return (
    <div ref={root} className="relative">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={t("shell.accountMenu", { name: me.user.name })}
        onClick={() => setOpen((v) => !v)}
        className="grid size-9 place-items-center rounded-full bg-muted text-sm font-semibold hover:bg-accent"
      >
        <span aria-hidden="true">{initialsOf(me.user.name)}</span>
      </button>
      {open ? (
        <div
          id={panelId}
          className="absolute top-full right-0 z-30 mt-2 grid w-80 gap-4 rounded-lg border bg-card p-4 text-card-foreground shadow-xs"
        >
          <div className="min-w-0">
            <div className="truncate font-medium">{t("shell.signedInAs", { name: me.user.name })}</div>
            <div className="truncate text-sm text-muted-foreground">{me.user.email}</div>
            <div className="mt-1 text-sm text-muted-foreground">
              {me.organization.name} · {t(`shell.role.${me.role}`)}
            </div>
          </div>
          <Link
            to="/account"
            onClick={() => setOpen(false)}
            className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-input bg-card px-4 text-base font-medium shadow-xs hover:bg-accent"
          >
            <UserRound aria-hidden="true" className="size-4" />
            {t("shell.accountLink")}
          </Link>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t("common.language")}</span>
            {/* The choice is kept on the account too, so it follows the user to other browsers (ADR 0017). */}
            <LanguagePicker
              onChanged={(locale) => {
                void api("/account/preferences", {
                  method: "PUT",
                  body: { locale, timeZone: me.user.timeZone },
                }).catch(() => {});
              }}
            />
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">{t("shell.theme")}</span>
            <Segmented
              label={t("shell.theme")}
              value={theme}
              options={THEMES.map((value) => ({ value, label: t(`shell.themes.${value}`) }))}
              onChange={setTheme}
            />
          </div>
          <Button variant="outline" onClick={signOut}>
            <LogOut aria-hidden="true" className="size-4" />
            {t("common.signOut")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
