import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function PageHeader({
  icon: Icon,
  title,
  description,
  actions,
  meta,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  actions?: ReactNode;
  /** Facts about the page's subject under the description, e.g. its grade. */
  meta?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start gap-3.5">
      <div className="grid size-10 flex-none place-items-center rounded-lg border bg-card shadow-xs">
        <Icon aria-hidden="true" className="size-[18px]" />
      </div>
      <div className="min-w-0 flex-[1_1_24rem]">
        <h1 className="text-2xl leading-tight font-semibold tracking-tight">{title}</h1>
        <p className="text-muted-foreground">{description}</p>
        {meta}
      </div>
      {actions ? <div className="ml-auto flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A bordered surface for tables and panels. */
export function Card({
  className = "",
  id,
  children,
}: {
  className?: string;
  id?: string;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      className={`min-w-0 rounded-xl border bg-card text-card-foreground shadow-xs ${className}`}
    >
      {children}
    </section>
  );
}

export function CardHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 px-5 pt-[18px] pb-3">
      <div className="min-w-0 flex-1">
        <h2 className="font-semibold tracking-[-0.01em]">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions}
    </div>
  );
}
