import { Check } from "lucide-react";
import type { InputHTMLAttributes } from "react";
import { cn } from "../../lib/cn.ts";

type BoxProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;

const box =
  "peer col-start-1 row-start-1 size-4 appearance-none border border-input bg-card shadow-xs " +
  "checked:border-primary checked:bg-primary disabled:opacity-50";

/**
 * A native checkbox with the look of the inputs: same corner radius checked or
 * not, and our own check mark. Keyboard, labels and screen readers behave as
 * with any checkbox, because it is one.
 */
export function Checkbox({ className, ...props }: BoxProps) {
  return (
    <span className={cn("inline-grid size-4 flex-none place-items-center", className)}>
      <input type="checkbox" className={cn(box, "rounded-[4px]")} {...props} />
      <Check
        aria-hidden="true"
        strokeWidth={3}
        className="pointer-events-none col-start-1 row-start-1 size-3 text-primary-foreground opacity-0 peer-checked:opacity-100"
      />
    </span>
  );
}

/** A native radio button styled to match {@link Checkbox}. */
export function Radio({ className, ...props }: BoxProps) {
  return (
    <span className={cn("inline-grid size-4 flex-none place-items-center", className)}>
      <input type="radio" className={cn(box, "rounded-full")} {...props} />
      <span
        aria-hidden="true"
        className="pointer-events-none col-start-1 row-start-1 size-1.5 rounded-full bg-primary-foreground opacity-0 peer-checked:opacity-100"
      />
    </span>
  );
}
