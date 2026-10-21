/** Mark draft from the mockup: a cut garnet, hexagonal outline with an inner facet in the brand colour. */
export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" aria-hidden="true" className={className}>
      <path
        d="M24 5 L40 14.5 V33.5 L24 43 L8 33.5 V14.5 Z"
        fill="none"
        strokeWidth="4.5"
        strokeLinejoin="round"
        className="stroke-[var(--mark-hold)]"
      />
      <path d="M24 15 L32 24 L24 33 L16 24 Z" className="fill-[var(--mark-beam)]" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <Mark className="size-6" />
      <span>
        {/* Normal tracking on purpose: tighter spacing merges "rn" into "m" at this size. */}
        <span className="text-lg font-bold">garnet</span>
        <span className="ml-1 font-mono text-xs text-muted-foreground">ops</span>
      </span>
      <span className="sr-only">GarnetOps</span>
    </span>
  );
}
