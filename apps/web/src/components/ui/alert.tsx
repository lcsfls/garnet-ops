import { CircleAlert, Info } from "lucide-react";
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
