import { Ellipsis, type LucideIcon } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { cn } from "../../lib/cn.ts";

export interface MenuAction {
  label: string;
  icon: LucideIcon;
  onSelect: () => void;
  disabled?: boolean;
  destructive?: boolean;
}

/**
 * The "…" button of a table row (mockup) with the row's less frequent actions.
 * A WAI-ARIA menu button: arrow keys move between items, Escape and a click
 * outside close it and return focus to the button.
 */
export function ActionMenu({ label, actions }: { label: string; actions: MenuAction[] }) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const items = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => {
    if (!open) return;
    items.current.find((item) => item && !item.disabled)?.focus();
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [open]);

  function close() {
    setOpen(false);
    button.current?.focus();
  }

  function onKeyDown(event: React.KeyboardEvent) {
    const enabled = items.current.filter((item): item is HTMLButtonElement =>
      Boolean(item && !item.disabled),
    );
    const index = enabled.indexOf(document.activeElement as HTMLButtonElement);
    if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      close();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      enabled[(index + step + enabled.length) % enabled.length]?.focus();
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      (event.key === "Home" ? enabled[0] : enabled[enabled.length - 1])?.focus();
    }
  }

  if (actions.length === 0) return null;
  return (
    <div ref={root} className="relative inline-block">
      <button
        ref={button}
        type="button"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
        className="grid size-9 place-items-center rounded-md hover:bg-accent"
      >
        <Ellipsis aria-hidden="true" className="size-4" />
      </button>
      {open ? (
        <div
          id={menuId}
          role="menu"
          aria-label={label}
          onKeyDown={onKeyDown}
          className="absolute top-full right-0 z-30 mt-1 grid min-w-48 rounded-lg border bg-card p-1 text-card-foreground shadow-xs"
        >
          {actions.map((action, i) => (
            <button
              key={action.label}
              ref={(el) => {
                items.current[i] = el;
              }}
              type="button"
              role="menuitem"
              tabIndex={-1}
              disabled={action.disabled}
              onClick={() => {
                setOpen(false);
                action.onSelect();
              }}
              className={cn(
                "flex h-9 items-center gap-2.5 rounded-md px-2.5 text-left whitespace-nowrap hover:bg-accent focus-visible:bg-accent disabled:opacity-50",
                action.destructive && "text-destructive-text",
              )}
            >
              <action.icon aria-hidden="true" className="size-4" />
              {action.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
