import type { ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/cn.ts";

const variants = {
  primary: "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90",
  outline: "border border-input bg-card shadow-xs hover:bg-accent",
  ghost: "hover:bg-accent",
  /** Irreversible actions; vermilion text on the card surface keeps the contrast in both themes. */
  destructive: "border border-destructive/50 bg-card text-destructive-text shadow-xs hover:bg-destructive/10",
  link: "h-auto px-0 text-primary-text underline-offset-4 hover:underline",
} as const;

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants;
}

export function Button({ variant = "primary", className, type = "button", ...props }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-base font-medium whitespace-nowrap transition-colors",
        "disabled:pointer-events-none disabled:opacity-50",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}
