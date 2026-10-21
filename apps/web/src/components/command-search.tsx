import { useNavigate } from "@tanstack/react-router";
import { Bug, GitBranch, type LucideIcon, Package, Search } from "lucide-react";
import { type KeyboardEvent, useEffect, useId, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import type { Me } from "../lib/session.ts";
import { navFor } from "./nav.ts";
import { Dialog } from "./ui/dialog.tsx";

interface Option {
  id: string;
  label: string;
  icon: LucideIcon;
  go: () => void;
}

/**
 * Search box in the top bar (Ctrl K or ⌘ K). It does not search by itself:
 * it opens the findings, packages or repositories list with the text as
 * filter, or jumps to a page whose name matches. Results stay in the URL,
 * so they can be shared like any other filter.
 */
export function CommandSearch({ me }: { me: Me }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const listId = useId();
  const optionId = (index: number) => `${listId}-${index}`;

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const close = () => {
    setOpen(false);
    setText("");
    setActive(0);
  };

  const options = useMemo<Option[]>(() => {
    const q = text.trim();
    const pages: Option[] = navFor(me)
      .flatMap((group) => group.items)
      .filter((item) => !q || t(item.label).toLowerCase().includes(q.toLowerCase()))
      .map((item) => ({
        id: `page:${item.to}`,
        label: t("shell.searchGoTo", { page: t(item.label) }),
        icon: item.icon,
        go: () => navigate({ to: item.to }),
      }));
    if (!q) return pages;
    return [
      {
        id: "findings",
        label: t("shell.searchFindings", { text: q }),
        icon: Bug,
        go: () => navigate({ to: "/findings", search: { q, state: "all" } }),
      },
      {
        id: "packages",
        label: t("shell.searchPackages", { text: q }),
        icon: Package,
        go: () => navigate({ to: "/packages", search: { q } }),
      },
      {
        id: "repositories",
        label: t("shell.searchRepositories", { text: q }),
        icon: GitBranch,
        go: () => navigate({ to: "/repositories", search: { q } }),
      },
      ...pages,
    ];
  }, [text, me, t, navigate]);

  const choose = (option: Option | undefined) => {
    if (!option) return;
    close();
    option.go();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((i) => Math.min(i + 1, options.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      choose(options[active]);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-keyshortcuts="Control+K Meta+K"
        className="flex h-9 w-[clamp(12rem,16vw,20rem)] items-center gap-2 overflow-hidden rounded-md border border-input bg-card px-2.5 text-sm whitespace-nowrap text-muted-foreground shadow-xs hover:bg-accent"
      >
        <Search aria-hidden="true" className="size-4 flex-none" />
        <span className="min-w-0 truncate">{t("shell.searchPlaceholder")}</span>
        <kbd className="ml-auto flex-none rounded border bg-muted px-1.5 font-mono text-xs">Ctrl K</kbd>
      </button>
      <Dialog open={open} onClose={close} title={t("shell.searchTitle")}>
        <div className="grid gap-3">
          <input
            type="search"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={options[active] ? optionId(active) : undefined}
            aria-label={t("shell.searchTitle")}
            placeholder={t("shell.searchPlaceholder")}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            className="h-10 w-full rounded-md border border-input bg-card px-3 text-base shadow-xs placeholder:text-muted-foreground"
          />
          <div id={listId} role="listbox" aria-label={t("shell.searchTitle")} className="grid gap-0.5">
            {options.map((option, index) => (
              // Keyboard selection happens in the combobox input (aria-activedescendant).
              <div
                key={option.id}
                id={optionId(index)}
                role="option"
                aria-selected={index === active}
                tabIndex={-1}
                onMouseMove={() => setActive(index)}
                onClick={() => choose(option)}
                onKeyDown={(e) => e.key === "Enter" && choose(option)}
                className={cn(
                  "flex h-10 cursor-pointer items-center gap-2.5 rounded-md px-2.5",
                  index === active && "bg-accent",
                )}
              >
                <option.icon aria-hidden="true" className="size-4 flex-none text-muted-foreground" />
                <span className="truncate">{option.label}</span>
              </div>
            ))}
          </div>
        </div>
      </Dialog>
    </>
  );
}
