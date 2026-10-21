import type { ReactNode } from "react";
import { Wordmark } from "./brand.tsx";
import { LanguagePicker } from "./language-picker.tsx";

/** Single-column layout for setup and sign-in: reading width, one card, one primary action. */
export function AuthLayout({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-md flex-col justify-center gap-6 px-4 py-12">
      <div className="flex items-center justify-between gap-4">
        <Wordmark />
        <LanguagePicker />
      </div>
      <section className="rounded-lg border bg-card p-6 text-card-foreground shadow-xs">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 text-muted-foreground">{description}</p> : null}
        <div className="mt-6">{children}</div>
      </section>
      {footer ? <div className="text-sm text-muted-foreground">{footer}</div> : null}
    </main>
  );
}
