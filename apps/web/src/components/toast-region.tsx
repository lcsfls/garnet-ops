import { safeAppLink } from "@garnetops/core/user-notifications";
import { useRouter } from "@tanstack/react-router";
import { CircleAlert, CircleCheck, Info, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import { toast as store, useToasts } from "../lib/toast.ts";
import type { Toast, ToastKind } from "../lib/toast-queue.ts";

const ICON = { success: CircleCheck, error: CircleAlert, info: Info } as const;

/**
 * Kind is carried by an icon and a word for screen readers, never by colour alone. Success is
 * neutral: green means proof only (AGENTS.md rule 6), and a saved setting proves nothing.
 */
const TONE: Record<ToastKind, string> = {
  success: "border-border",
  error: "border-destructive/50",
  info: "border-info/50",
};
const ICON_TONE: Record<ToastKind, string> = {
  success: "text-foreground",
  error: "text-destructive-text",
  info: "text-info-text",
};

/**
 * One message. It closes by itself after its time (errors never do); hovering it or moving focus
 * into it pauses the timer, and leaving continues with the time that was left.
 */
function ToastItem({ toast }: { toast: Toast }) {
  const { t } = useTranslation();
  const router = useRouter();
  const [paused, setPaused] = useState(false);
  const left = useRef<number | null>(toast.durationMs);
  const started = useRef(0);
  const Icon = ICON[toast.kind];
  const item = useRef<HTMLDivElement>(null);

  // Hovering or focusing the message pauses its timer. Listeners instead of JSX props: the item
  // is a live region, not an interactive element, and focus events bubble as focusin/focusout.
  useEffect(() => {
    const node = item.current;
    if (!node) return;
    const pause = () => setPaused(true);
    const resume = () => setPaused(false);
    const leaveFocus = (event: FocusEvent) => {
      if (!node.contains(event.relatedTarget as Node | null)) setPaused(false);
    };
    node.addEventListener("mouseenter", pause);
    node.addEventListener("mouseleave", resume);
    node.addEventListener("focusin", pause);
    node.addEventListener("focusout", leaveFocus);
    return () => {
      node.removeEventListener("mouseenter", pause);
      node.removeEventListener("mouseleave", resume);
      node.removeEventListener("focusin", pause);
      node.removeEventListener("focusout", leaveFocus);
    };
  }, []);

  const revision = useRef(toast.revision);

  useEffect(() => {
    // A repeat of the message (a new revision) gives it its full time again.
    if (revision.current !== toast.revision) {
      revision.current = toast.revision;
      left.current = toast.durationMs;
    }
    if (paused || left.current === null) return;
    started.current = Date.now();
    const timer = setTimeout(() => store.dismiss(toast.id), left.current);
    return () => {
      clearTimeout(timer);
      // Pausing keeps what is left of the time.
      if (left.current !== null) left.current = Math.max(0, left.current - (Date.now() - started.current));
    };
  }, [paused, toast.id, toast.revision, toast.durationMs]);

  const href = toast.action ? safeAppLink(toast.action.href) : null;
  return (
    <div
      ref={item}
      data-toast={toast.kind}
      role={toast.kind === "error" ? "alert" : "status"}
      aria-live={toast.kind === "error" ? "assertive" : "polite"}
      className={cn(
        "toast-in pointer-events-auto flex items-start gap-2.5 rounded-lg border bg-card p-3 text-sm text-card-foreground shadow-xs",
        TONE[toast.kind],
      )}
    >
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4 flex-none", ICON_TONE[toast.kind])} />
      <div className="min-w-0 flex-1">
        <span className="sr-only">{t(`toast.${toast.kind}`)}: </span>
        <span className="break-words">{toast.message}</span>
        {toast.action && href ? (
          <a
            href={href}
            onClick={(event) => {
              if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
              event.preventDefault();
              router.history.push(href);
              store.dismiss(toast.id);
            }}
            className="mt-1 block w-fit font-medium text-primary-text underline underline-offset-4"
          >
            {toast.action.label}
          </a>
        ) : null}
      </div>
      <button
        type="button"
        data-toast-close
        aria-label={t("toast.close")}
        onClick={() => store.dismiss(toast.id)}
        className="-m-1 grid size-7 flex-none place-items-center rounded-md hover:bg-accent"
      >
        <X aria-hidden="true" className="size-4" />
      </button>
    </div>
  );
}

/**
 * The messages for what people just did (ADR 0019), bottom right. Each message is its own live
 * region: errors are announced at once (role alert), everything else politely (role status).
 * Nothing here takes focus; the close buttons and links are reached with Tab, or with
 * Alt+Shift+T, which moves to the first message.
 */
export function ToastRegion() {
  const { t } = useTranslation();
  const { visible } = useToasts();
  const root = useRef<HTMLElement>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey && event.shiftKey && event.code === "KeyT") {
        event.preventDefault();
        root.current?.querySelector<HTMLElement>("[data-toast-close]")?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return (
    <section
      ref={root}
      aria-label={t("toast.region")}
      className="pointer-events-none fixed right-4 bottom-4 z-50 grid w-[min(24rem,calc(100vw-2rem))] gap-2"
    >
      {visible.map((x) => (
        <ToastItem key={x.id} toast={x} />
      ))}
    </section>
  );
}
