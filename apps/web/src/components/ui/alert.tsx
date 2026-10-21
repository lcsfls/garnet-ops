import { CircleAlert, Info, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/cn.ts";

/** An inline message. Errors are announced to screen readers; information is polite. */
export function Alert({ tone, children }: { tone: "error" | "info"; children: ReactNode }) {
  const Icon = tone === "error" ? CircleAlert : Info;
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "flex gap-2.5 rounded-md border px-3 py-2.5 text-sm",
        tone === "error" ? "border-destructive/40 text-destructive-text" : "border-info/40 text-info-text",
      )}
    >
      <Icon aria-hidden="true" className="mt-0.5 size-4 flex-none" />
      <div>{children}</div>
    </div>
  );
}

/** A page-level notice that needs attention (mockup .alert): title, one sentence, one action. */
export function Banner({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      role="status"
      className="mb-5 flex flex-wrap items-center gap-3.5 rounded-xl border border-warning/45 bg-[color-mix(in_srgb,var(--warning)_9%,var(--card))] px-[18px] py-3.5"
    >
      <TriangleAlert aria-hidden="true" className="size-[18px] flex-none text-warning-text" />
      <div className="min-w-0 flex-[1_1_20rem]">
        <b className="block font-semibold">{title}</b>
        {children ? <span className="text-muted-foreground">{children}</span> : null}
      </div>
      {action ? <div className="ml-auto">{action}</div> : null}
    </div>
  );
}
